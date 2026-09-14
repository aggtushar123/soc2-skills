# Node.js (Express / Fastify, TypeScript) — SOC 2 patterns

Express has no opinions, which is exactly the problem: nothing is denied, validated, redacted, or rate limited unless a middleware does it. The registry maps cleanly onto a fixed middleware chain (`requestId → helmet → cors → bodyLimit → rateLimit → auth → validate → handler → errorHandler`) plus a handful of small libraries. Patterns below assume Express 4.19+ (Express 5 differences noted), TypeScript 5, `helmet` 7, `cors` 2.8, `express-rate-limit` 7 (+ `rate-limit-redis` for multi-instance), `zod` 3.23+, `pino` 9 with `pino-http`, `argon2` 0.40+, `jose` 5 for JWT, and Prisma 5 or `pg` 8 for data access. Fastify equivalents are noted inline (`@fastify/helmet`, `@fastify/cors`, `@fastify/rate-limit`, `fastify-type-provider-zod`); NestJS equivalents are `Guards`, `Pipes` (`ZodValidationPipe`), `Interceptors`, and `@nestjs/throttler`.

## Detection

- `package.json` `dependencies` contains `express`, `fastify`, or `@nestjs/core`. TypeScript if `typescript` in `devDependencies` and a `tsconfig.json` exists.
- ORM: `@prisma/client` + `prisma/schema.prisma`; or `pg`, `knex`, `drizzle-orm`, `typeorm`, `mongoose`.
- Typical layout: `src/routes/` or `src/controllers/` (Express), `src/plugins/` + `src/routes/` (Fastify), `src/**/*.module.ts` + `*.controller.ts` (Nest). Middleware in `src/middleware/`. Config in `src/config.ts` or `src/config/`. Models in `prisma/schema.prisma` or `src/models/` / `src/entities/`.
- Entry point: `src/index.ts`, `src/server.ts`, `src/app.ts`, or `src/main.ts` (Nest). `app.listen` / `fastify.listen` marks it.
- Lockfile: `package-lock.json`, `pnpm-lock.yaml`, or `yarn.lock` (SEC-03). Its absence is a finding.

## Project scaffold for compliance

```
src/
  config.ts                 # SEC-01, SEC-02, SEC-06 — zod-validated env, no secret defaults
  app.ts                    # API-06, API-04 — middleware order lives here
  middleware/
    request-id.ts           # API-05, LOG-02 — correlation ID per request
    auth.ts                 # AUTH-01, AUTH-05 — deny-by-default JWT verification
    authorize.ts            # AUTH-02, AUTH-09, DATA-08 — role + ownership guards
    validate.ts             # API-01 — zod schemas, strict()
    rate-limit.ts           # API-04, AUTH-06 — global + login limiters
    error-handler.ts        # API-05, SEC-06 — generic errors, no stack in prod
    route-meta.ts           # API-07, EVD-01 — auth/classification/owner metadata
  lib/
    logger.ts               # LOG-03, LOG-04 — pino with redact paths
    audit.ts                # LOG-01, LOG-02 — append-only audit writer
    redact.ts               # LOG-03 — deep redaction for arbitrary objects
    crypto.ts               # SEC-07, DATA-02 — AES-256-GCM + KMS key wrap
    password.ts             # AUTH-04 — argon2id + breached check
    db.ts                   # API-03, DATA-08 — Prisma client with tenant extension
  jobs/
    retention.ts            # DATA-04, DATA-05 — scheduled purge
  routes/
    health.ts               # LOG-06
scripts/
  routes-manifest.ts        # API-07, EVD-01 — emits .soc2/routes.json
.soc2/
  CONTROL_MAP.md            # EVD-01
```

## Patterns

### 1. Authentication middleware, deny by default (AUTH-01, AUTH-05)

Mount `requireAuth` on the whole app, before any router. Public routes are an explicit list of `method + path` pairs, not a regex on `/public`.

```ts
// src/middleware/auth.ts
import type { Request, Response, NextFunction } from "express";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { config } from "../config";
import { isRevoked } from "../lib/session-store";

const JWKS = createRemoteJWKSet(new URL(config.AUTH_JWKS_URL));

// SOC2:AUTH-01 — the only routes reachable without a verified token
const PUBLIC_ROUTES = new Set<string>([
  "GET /healthz",
  "GET /readyz",
  "POST /v1/auth/login",
  "POST /v1/auth/refresh",
]);

export async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const key = `${req.method} ${req.route?.path ?? req.path}`;
  if (PUBLIC_ROUTES.has(key)) return next();

  const header = req.headers.authorization ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "unauthenticated", correlationId: req.id });

  try {
    // SOC2:AUTH-05 — issuer/audience pinned, max age bounded to 1h regardless of exp claim
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: config.AUTH_ISSUER,
      audience: config.AUTH_AUDIENCE,
      maxTokenAge: "1h",
      clockTolerance: 30,
    });
    if (typeof payload.jti !== "string" || (await isRevoked(payload.jti))) {
      return res.status(401).json({ error: "unauthenticated", correlationId: req.id });
    }
    req.user = {
      id: payload.sub!,
      tenantId: payload["tenant_id"] as string,
      roles: (payload["roles"] as string[]) ?? [],
      sessionId: payload.jti,
    };
    return next();
  } catch {
    return res.status(401).json({ error: "unauthenticated", correlationId: req.id });
  }
}
```

- `app.use(requireAuth)` must come before `app.use("/v1", router)`. If a router is mounted earlier, it silently bypasses auth; the scanner should check mount order in `app.ts`.
- `req.route` is undefined in app-level middleware in Express 4; the key falls back to `req.path`, so declare public routes with their full mounted path. In Express 5 and Fastify use the route config instead (Fastify: `onRequest` hook checking `request.routeOptions.config.public === true`).
- Revocation (`isRevoked`) needs a store (Redis set of `jti` with TTL = token lifetime). Without it AUTH-07 "deactivation is immediate" fails, because stateless JWTs live until expiry.
- If sessions are cookie-based, set `cookie: { httpOnly: true, secure: true, sameSite: "lax", maxAge: 3600_000 }` and add CSRF (pattern 7).

### 2. Authorization guard: role + object ownership (AUTH-02, AUTH-09, DATA-08)

```ts
// src/middleware/authorize.ts
import type { Request, Response, NextFunction, RequestHandler } from "express";
import { db } from "../lib/db";

export type Role = "member" | "tenant_admin" | "platform_admin";

// SOC2:AUTH-09 — admin is a distinct role; there is no `isAdmin` boolean on users
export function requireRole(...allowed: Role[]): RequestHandler {
  return (req, res, next) => {
    const roles = req.user?.roles ?? [];
    if (!allowed.some((r) => roles.includes(r))) {
      return res.status(403).json({ error: "forbidden", correlationId: req.id });
    }
    next();
  };
}

// SOC2:AUTH-02 — object-level check: load the record scoped by tenant, never trust body.tenantId
export function requireOwnership(
  loader: (id: string, tenantId: string) => Promise<{ ownerId: string } | null>,
  param = "id",
): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction) => {
    const { id: userId, tenantId, roles } = req.user!;
    // SOC2:DATA-08 — tenant comes from the verified token, not the request
    const record = await loader(req.params[param], tenantId);
    if (!record) return res.status(404).json({ error: "not_found", correlationId: req.id });
    const isOwner = record.ownerId === userId;
    const isTenantAdmin = roles.includes("tenant_admin");
    if (!isOwner && !isTenantAdmin) {
      return res.status(403).json({ error: "forbidden", correlationId: req.id });
    }
    res.locals.record = record;
    next();
  };
}

// usage
router.delete(
  "/invoices/:id",
  requireRole("member", "tenant_admin"),
  requireOwnership((id, tenantId) => db.invoice.findFirst({ where: { id, tenantId } })),
  deleteInvoice,
);
```

- Return 404, not 403, when the object exists in another tenant. 403 confirms existence (IDOR enumeration).
- With Prisma, install a client extension that injects `where: { tenantId }` on every query for tenant-scoped models (`$extends({ query: { $allModels: { findMany, findFirst, update, delete } } })`) so a forgotten filter fails closed. Postgres row-level security with `SET LOCAL app.tenant_id` is stronger and survives raw SQL.
- Never merge `req.body.role`, `req.body.tenantId`, or `req.body.userId` into a write. Strip them in the zod schema (pattern 3) and set them from `req.user`.
- NestJS: `@UseGuards(AuthGuard, RolesGuard)` with a `@Roles()` decorator; ownership still needs an explicit service-layer check.

### 3. Input validation with zod, rejecting unknown fields (API-01)

```ts
// src/middleware/validate.ts
import type { RequestHandler } from "express";
import { z, type ZodTypeAny } from "zod";

type Schemas = { body?: ZodTypeAny; query?: ZodTypeAny; params?: ZodTypeAny; headers?: ZodTypeAny };

// SOC2:API-01 — every segment validated; .strict() rejects unknown keys
export function validate(schemas: Schemas): RequestHandler {
  return (req, res, next) => {
    for (const part of ["params", "query", "body", "headers"] as const) {
      const schema = schemas[part];
      if (!schema) continue;
      const result = schema.safeParse(req[part]);
      if (!result.success) {
        return res.status(400).json({
          error: "validation_failed",
          correlationId: req.id,
          issues: result.error.issues.map((i) => ({ path: i.path.join("."), code: i.code })),
        });
      }
      if (part !== "headers") (req as any)[part] = result.data; // use parsed, coerced data
    }
    next();
  };
}

// src/routes/invoices.schema.ts
export const createInvoice = {
  params: z.object({}).strict(),
  body: z
    .object({
      customerId: z.string().uuid(),
      amountCents: z.number().int().positive().max(10_000_000),
      currency: z.enum(["USD", "EUR", "GBP"]),
      memo: z.string().max(500).optional(),
      // tenantId / ownerId deliberately absent: set from req.user
    })
    .strict(),
  query: z.object({}).strict(),
};

router.post("/invoices", validate(createInvoice), createInvoiceHandler);
```

- `z.object()` strips unknown keys by default; that hides mass-assignment attempts instead of rejecting them. Use `.strict()` on every request schema and treat `.passthrough()` as a finding.
- Express `req.query` values are strings; use `z.coerce.number()` and bound them (`.max()`), otherwise `?limit=1e9` reaches your database.
- Validate `params` too. A UUID schema on `:id` blocks path traversal and NoSQL operator injection (`{"$gt": ""}`) before the ORM sees it.
- Fastify: use `fastify-type-provider-zod` with `additionalProperties: false`; its JSON-schema validation is applied before the handler automatically. Nest: `ZodValidationPipe` or `ValidationPipe({ whitelist: true, forbidNonWhitelisted: true })`.

### 4. Parameterized data access and the anti-pattern (API-03)

```ts
// src/lib/db.ts
import { PrismaClient, Prisma } from "@prisma/client";
import { Pool } from "pg";

export const db = new PrismaClient({ log: ["warn", "error"] }); // never "query" in prod: LOG-03
export const pool = new Pool({ connectionString: config.DATABASE_URL, ssl: { rejectUnauthorized: true } }); // DATA-03

// SOC2:API-03 — Prisma query builder: values are always bound parameters
export function findInvoicesByStatus(tenantId: string, status: string) {
  return db.invoice.findMany({ where: { tenantId, status }, orderBy: { createdAt: "desc" }, take: 100 });
}

// SOC2:API-03 — raw SQL only through tagged template (Prisma.sql) or $1 placeholders
export function searchInvoices(tenantId: string, term: string) {
  return db.$queryRaw<Invoice[]>`
    SELECT id, number, amount_cents FROM invoices
    WHERE tenant_id = ${tenantId} AND number ILIKE ${"%" + term + "%"}
    LIMIT 100`;
}

export async function countByCustomer(tenantId: string, customerId: string) {
  const { rows } = await pool.query(
    "SELECT count(*)::int AS n FROM invoices WHERE tenant_id = $1 AND customer_id = $2",
    [tenantId, customerId],
  );
  return rows[0].n;
}

// ANTI-PATTERN — string-built SQL. Flag on sight.
// db.$queryRawUnsafe(`SELECT * FROM invoices WHERE number = '${term}'`)
// pool.query("SELECT * FROM users WHERE email = '" + email + "'")
// Same rule for shell: never child_process.exec(`convert ${filename}`); use execFile("convert", [filename]).
```

- `$queryRawUnsafe`, `$executeRawUnsafe`, `knex.raw(string + var)`, `sequelize.query(string + var)`, `child_process.exec`, and `eval`/`new Function` are the grep targets. Any hit with interpolation is an API-03 finding.
- Column and table names cannot be parameters. If sort column is user-controlled, map it through an allow-list object, never interpolate.
- Mongoose/MongoDB: `Model.find(req.query)` is injection (`{ $where }` / `$gt`). Validate to primitives first (pattern 3) and enable `mongoose.set("sanitizeFilter", true)`.
- Enforce TLS on the database connection (`ssl: { rejectUnauthorized: true }` or `?sslmode=verify-full`) for DATA-03. `rejectUnauthorized: false` is a finding.

### 5. Rate limiting and body size limits (API-04, AUTH-06)

```ts
// src/middleware/rate-limit.ts
import rateLimit from "express-rate-limit";
import { RedisStore } from "rate-limit-redis";
import { redis } from "../lib/redis";

const store = () => new RedisStore({ sendCommand: (...args: string[]) => redis.sendCommand(args) });

// SOC2:API-04 — global limit on every public endpoint, keyed by client IP
export const globalLimiter = rateLimit({
  windowMs: 60_000,
  limit: 300,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  store: store(),
});

// SOC2:AUTH-06 — tight limit on credential endpoints, keyed by IP + identifier
export const loginLimiter = rateLimit({
  windowMs: 15 * 60_000,
  limit: 10,
  skipSuccessfulRequests: false,
  keyGenerator: (req) => `${req.ip}:${String(req.body?.email ?? "").toLowerCase()}`,
  handler: (req, res) => res.status(429).json({ error: "too_many_attempts", correlationId: req.id }),
  store: store(),
});

// src/app.ts
app.set("trust proxy", 1); // exactly the number of proxies in front of you
// SOC2:API-04 — body limits before any parser runs
app.use(express.json({ limit: "100kb", strict: true }));
app.use(express.urlencoded({ extended: false, limit: "50kb" }));
app.use(globalLimiter);
app.post("/v1/auth/login", loginLimiter, validate(loginSchema), login);
app.post("/v1/auth/reset", loginLimiter, validate(resetSchema), requestReset);
app.post("/v1/auth/mfa/verify", loginLimiter, validate(mfaSchema), verifyMfa);
```

- `trust proxy` set to `true` lets clients spoof `X-Forwarded-For` and defeat every IP-keyed limit. Set it to the hop count or a CIDR list.
- The default `MemoryStore` is per process. With more than one replica the effective limit multiplies; use the Redis store.
- Body limit must be set on the parser, not only at the load balancer; a direct-to-pod request bypasses the LB. For multipart uploads set `limits: { fileSize }` in `multer`/`busboy` (API-10).
- Lockout after N failures (AUTH-06 "lockout or backoff") is separate: track failures per account in the user table and require a reset or exponential delay past 10 failures. Fastify: `@fastify/rate-limit` with `keyGenerator` and `bodyLimit` on `fastify({ bodyLimit: 102400 })`.

### 6. Error handler: generic response + correlation ID (API-05, SEC-06)

```ts
// src/middleware/request-id.ts
import { randomUUID } from "node:crypto";
export function requestId(req, res, next) {
  // SOC2:LOG-02 — accept upstream ID only if it looks like one; otherwise mint
  const incoming = req.headers["x-request-id"];
  req.id = typeof incoming === "string" && /^[A-Za-z0-9-_]{8,64}$/.test(incoming) ? incoming : randomUUID();
  res.setHeader("X-Request-Id", req.id);
  next();
}

// src/middleware/error-handler.ts
import type { ErrorRequestHandler } from "express";
import { logger } from "../lib/logger";
import { config } from "../config";

export class HttpError extends Error {
  constructor(public status: number, public code: string) { super(code); }
}

// SOC2:API-05 — four-arg signature is required for Express to treat this as an error handler
export const errorHandler: ErrorRequestHandler = (err, req, res, _next) => {
  const status = err instanceof HttpError ? err.status : 500;
  const code = err instanceof HttpError ? err.code : "internal_error";

  // full detail goes to the log (redacted by pino), keyed by correlation ID
  logger.error({ err, correlationId: req.id, path: req.path, status }, "request failed");

  // SOC2:SEC-06 — never leak stack, SQL, or paths to the client; not even in staging
  const body: Record<string, unknown> = { error: code, correlationId: req.id };
  if (config.NODE_ENV === "development") body.detail = err.message;
  res.status(status).json(body);
};

// src/app.ts — must be the LAST app.use()
app.use(errorHandler);
```

- Express 4 does not catch rejected promises from async handlers. Wrap handlers (`express-async-errors` or a `wrap(fn)` helper) or the request hangs and the error goes to `unhandledRejection`. Express 5 forwards them automatically.
- Also set `process.on("unhandledRejection")` / `uncaughtException` to log and exit; a swallowed exception leaves the process in an undefined state.
- Prisma `P2002`/`P2025` errors contain column names and table names in `err.message`. Map them to `HttpError(409, "conflict")` / `HttpError(404, "not_found")` rather than passing `err.message` through.
- Fastify: `fastify.setErrorHandler` plus `genReqId` in the constructor. Disable the default validation error message reflection with `schemaErrorFormatter`.

### 7. Security headers, CORS allow-list, CSRF (API-06, DATA-03)

```ts
// src/app.ts
import helmet from "helmet";
import cors from "cors";
import { doubleCsrf } from "csrf-csrf";

// SOC2:API-06 — helmet sets HSTS, X-Content-Type-Options, frame options, and a CSP
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    // SOC2:DATA-03 — HSTS one year, subdomains, preload
    strictTransportSecurity: { maxAge: 31_536_000, includeSubDomains: true, preload: true },
    referrerPolicy: { policy: "no-referrer" },
  }),
);

// SOC2:API-06 — explicit origin allow-list from config; no "*" and no reflecting Origin
const allowedOrigins = new Set(config.CORS_ORIGINS); // e.g. ["https://app.example.com"]
app.use(
  cors({
    origin: (origin, cb) => cb(null, !origin || allowedOrigins.has(origin)),
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
    allowedHeaders: ["Authorization", "Content-Type", "X-Request-Id", "X-CSRF-Token"],
    maxAge: 600,
  }),
);

// SOC2:API-06 — CSRF only matters when auth rides on cookies; skip for pure Bearer APIs
if (config.SESSION_MODE === "cookie") {
  const { doubleCsrfProtection } = doubleCsrf({
    getSecret: () => config.CSRF_SECRET,
    cookieName: "__Host-csrf",
    cookieOptions: { httpOnly: true, sameSite: "strict", secure: true, path: "/" },
    getTokenFromRequest: (req) => req.headers["x-csrf-token"] as string,
  });
  app.use(doubleCsrfProtection);
}
```

- `cors({ origin: true })` reflects any origin with credentials, which is the worst possible setting. `origin: "*"` with `credentials: true` is rejected by browsers but still signals a finding.
- The `!origin` allowance is for non-browser clients (curl, server-to-server). If the API is browser-only, remove it.
- HSTS is only honored over HTTPS; if TLS terminates at a load balancer, confirm it forwards `X-Forwarded-Proto` and that `trust proxy` is set, or `secure` cookies will never be set.
- `csurf` is deprecated and vulnerable; use `csrf-csrf` (double-submit) or rely on `SameSite=strict` cookies plus a custom-header check. Fastify: `@fastify/helmet`, `@fastify/cors`, `@fastify/csrf-protection`.

### 8. Audit logger: append-only structured events (LOG-01, LOG-02)

```ts
// src/lib/audit.ts
import pino from "pino";
import { db } from "./db";

export type AuditAction =
  | "auth.login.success" | "auth.login.failure" | "auth.mfa.verify" | "auth.logout"
  | "user.password.change" | "user.role.grant" | "user.role.revoke" | "user.deactivate"
  | "data.restricted.read" | "data.export" | "data.delete" | "admin.config.change";

export interface AuditEvent {
  actor: { id: string; type: "user" | "service" | "system" };
  action: AuditAction;
  target: { type: string; id: string };
  outcome: "success" | "failure" | "denied";
  ip: string | undefined;
  correlation_id: string;
  tenant_id: string | null;
  timestamp?: string;            // ISO-8601 UTC, set here
  metadata?: Record<string, string | number | boolean>; // never free-form objects: LOG-03
}

// SOC2:LOG-02 — separate stream from app logs; pino to stdout with a distinguishing `stream` field
const auditStream = pino({ base: { stream: "audit", service: config.SERVICE_NAME }, timestamp: pino.stdTimeFunctions.isoTime });

// SOC2:LOG-01 — single entry point; callers cannot skip fields because of the type
export async function audit(event: AuditEvent): Promise<void> {
  const entry = { ...event, timestamp: new Date().toISOString() };
  auditStream.info(entry);
  // SOC2:LOG-02 — append-only table: app role has INSERT only, no UPDATE/DELETE grants
  await db.auditLog.create({ data: { ...entry, actor: entry.actor.id, actorType: entry.actor.type,
    targetType: entry.target.type, targetId: entry.target.id, metadata: entry.metadata ?? {} } });
}

// usage in login handler
await audit({
  actor: { id: user?.id ?? email, type: "user" }, action: ok ? "auth.login.success" : "auth.login.failure",
  target: { type: "user", id: user?.id ?? "unknown" }, outcome: ok ? "success" : "failure",
  ip: req.ip, correlation_id: req.id, tenant_id: user?.tenantId ?? null,
});
```

- Append-only means enforced by the database, not by convention: `REVOKE UPDATE, DELETE ON audit_log FROM app_role`, and a trigger that raises on UPDATE/DELETE is cheap insurance. Prisma migrations can carry the `REVOKE`.
- Audit on failure too. A denied authorization (`outcome: "denied"`) in `requireOwnership` is one of the most useful security signals and is often forgotten.
- Do not `await audit()` inside the DB transaction of the business write, or a rolled-back action leaves a "success" entry. Emit after commit; for failures, emit in the catch.
- `metadata` is typed to primitives on purpose. Passing `req.body` in is how card numbers end up in the audit table.

### 9. Log redaction of secrets and PII (LOG-03, LOG-04)

```ts
// src/lib/logger.ts
import pino from "pino";
import pinoHttp from "pino-http";

// SOC2:LOG-03 — path-based redaction runs inside pino before serialization
export const logger = pino({
  level: config.LOG_LEVEL,
  timestamp: pino.stdTimeFunctions.isoTime,           // SOC2:LOG-07 — UTC ISO timestamps
  base: { service: config.SERVICE_NAME, env: config.NODE_ENV },
  redact: {
    paths: [
      "req.headers.authorization", "req.headers.cookie", "req.headers['x-api-key']",
      "res.headers['set-cookie']",
      "*.password", "*.newPassword", "*.currentPassword", "*.token", "*.refreshToken",
      "*.accessToken", "*.secret", "*.clientSecret", "*.ssn", "*.cardNumber", "*.cvv",
      "*.email", "*.phone", "*.dateOfBirth",
    ],
    censor: "[REDACTED]",
  },
  formatters: { level: (label) => ({ level: label }) }, // SOC2:LOG-04 — JSON with string levels
});

// SOC2:LOG-03 — request logging: no bodies, no query strings (DATA-06), correlation ID always
export const httpLogger = pinoHttp({
  logger,
  genReqId: (req) => (req as any).id,
  customProps: (req) => ({ correlationId: (req as any).id, userId: (req as any).user?.id, tenantId: (req as any).user?.tenantId }),
  serializers: {
    req: (req) => ({ id: req.id, method: req.method, path: req.url.split("?")[0], ip: req.remoteAddress }),
    res: (res) => ({ statusCode: res.statusCode }),
  },
});

// src/lib/redact.ts — for values you log ad hoc, e.g. third-party responses
const SENSITIVE = /(pass(word)?|secret|token|authorization|cookie|ssn|card|cvv|api[-_]?key)/i;
export function redact<T>(value: T, depth = 0): T {
  if (depth > 6 || value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1)) as T;
  return Object.fromEntries(
    Object.entries(value as object).map(([k, v]) => [k, SENSITIVE.test(k) ? "[REDACTED]" : redact(v, depth + 1)]),
  ) as T;
}
```

- pino `redact` is key-path based, not content based. A JWT logged as a bare string in `msg` is not caught; the rule is "log objects with known keys, never `logger.info(JSON.stringify(x))`".
- Never enable `pino-pretty` or `LOG_LEVEL=debug` in production images; pretty output breaks JSON shipping (LOG-04) and debug often logs full requests.
- Prisma `log: ["query"]` prints bound parameter values. Keep it off outside local development.
- `console.log` bypasses redaction. Lint rule `no-console: error` and a scanner grep for `console.` in `src/` are the enforcement.

### 10. Secrets loading with startup validation (SEC-01, SEC-02, SEC-06)

```ts
// src/config.ts
import { z } from "zod";

// SOC2:SEC-01 — schema has no .default() on any secret; missing secret => process exits at boot
const Env = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  LOG_LEVEL: z.enum(["error", "warn", "info", "debug"]).default("info"),
  SERVICE_NAME: z.string().min(1),
  DATABASE_URL: z.string().url().refine((u) => u.includes("sslmode=verify-full") || u.startsWith("postgresql://localhost"), "DATABASE_URL must require TLS"),
  REDIS_URL: z.string().url(),
  AUTH_JWKS_URL: z.string().url(),
  AUTH_ISSUER: z.string().url(),
  AUTH_AUDIENCE: z.string().min(1),
  CSRF_SECRET: z.string().min(32),
  FIELD_ENCRYPTION_KEY_ID: z.string().min(1),          // KMS key id, not key material
  CORS_ORIGINS: z.string().transform((s) => s.split(",").map((o) => o.trim()).filter(Boolean)),
  SESSION_MODE: z.enum(["bearer", "cookie"]).default("bearer"),
  DEBUG: z.coerce.boolean().default(false),
}).superRefine((env, ctx) => {
  // SOC2:SEC-06 — production cannot run with debug on or with dev-only settings
  if (env.NODE_ENV === "production" && env.DEBUG) ctx.addIssue({ code: "custom", message: "DEBUG must be false in production" });
  if (env.NODE_ENV === "production" && env.LOG_LEVEL === "debug") ctx.addIssue({ code: "custom", message: "LOG_LEVEL=debug not allowed in production" });
});

const parsed = Env.safeParse(process.env);
if (!parsed.success) {
  // print variable names only, never values
  console.error("Invalid configuration:", parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; "));
  process.exit(1);
}
export const config = Object.freeze(parsed.data);

// SOC2:SEC-02 — secrets that rotate are read through a getter with a TTL, not cached forever
let cachedDbPassword: { value: string; expires: number } | undefined;
export async function getDbPassword(): Promise<string> {
  if (cachedDbPassword && cachedDbPassword.expires > Date.now()) return cachedDbPassword.value;
  const value = await secretManager.getSecretValue({ SecretId: "prod/app/db-password" });
  cachedDbPassword = { value, expires: Date.now() + 5 * 60_000 };
  return value;
}
```

- `dotenv` is fine for local development. `require("dotenv").config()` in production code paths is not a finding by itself, but a committed `.env` is. `.gitignore` must contain `.env` and `.env.*` with `!.env.example` allowed.
- `process.env.JWT_SECRET || "dev-secret"` is the single most common SEC-01/SEC-06 finding in Node code. Grep for `process.env\.\w+\s*(\|\||\?\?)\s*["']`.
- Do not read `process.env` anywhere except `config.ts`. Scattered reads defeat startup validation and hide which secrets exist.
- Deploy secrets via the platform (Kubernetes Secret mounted as env, ECS `secrets`, Fly/Render secret store); `Dockerfile` `ENV` and `ARG` for secrets leak into image layers.

### 11. Password hashing and approved crypto helpers (AUTH-04, SEC-07)

```ts
// src/lib/password.ts
import argon2 from "argon2";
import { createHash, timingSafeEqual } from "node:crypto";

// SOC2:AUTH-04 — argon2id, OWASP-recommended parameters (19 MiB, t=2, p=1)
const ARGON2_OPTS = { type: argon2.argon2id, memoryCost: 19_456, timeCost: 2, parallelism: 1 } as const;

export async function hashPassword(plain: string): Promise<string> {
  if (plain.length < 12 || plain.length > 256) throw new HttpError(400, "password_policy");
  if (await isBreached(plain)) throw new HttpError(400, "password_breached");
  return argon2.hash(plain, ARGON2_OPTS);
}

export async function verifyPassword(hash: string, plain: string): Promise<boolean> {
  try { return await argon2.verify(hash, plain); } catch { return false; }
}

export function needsRehash(hash: string): boolean {
  return argon2.needsRehash(hash, ARGON2_OPTS); // upgrade legacy bcrypt/params on next login
}

// SOC2:AUTH-04 — HIBP k-anonymity range check; only the 5-char SHA-1 prefix leaves the process
async function isBreached(plain: string): Promise<boolean> {
  const sha1 = createHash("sha1").update(plain).digest("hex").toUpperCase(); // SHA-1 here is the HIBP protocol, not storage
  const res = await fetch(`https://api.pwnedpasswords.com/range/${sha1.slice(0, 5)}`, { headers: { "Add-Padding": "true" } });
  if (!res.ok) return false; // fail open on HIBP outage, but log it
  return (await res.text()).split("\n").some((line) => line.startsWith(sha1.slice(5)));
}

// src/lib/crypto.ts — approved primitives only
// SOC2:SEC-07 — SHA-256 for integrity, constant-time compare for secrets
export const sha256 = (data: string | Buffer) => createHash("sha256").update(data).digest("hex");
export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a), bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}
```

- `bcrypt` is acceptable at cost 12+; `bcryptjs` with default cost 10 is a finding. bcrypt also truncates input at 72 bytes, so pre-hashing long passwords or using argon2 is preferred.
- Never log the password on validation failure, and never send it by email or include it in the audit `metadata`.
- Comparison of API keys, reset tokens, and webhook signatures must use `timingSafeEqual`, not `===`.
- Grep targets for SEC-07: `createHash("md5")`, `createHash("sha1")` outside the HIBP call, `createCipheriv("aes-256-cbc"` without an HMAC, `"des"`, `"rc4"`, `Math.random()` for tokens (use `randomBytes`/`randomUUID`).

### 12. Field-level encryption for a restricted column (DATA-02)

```ts
// src/lib/crypto.ts (continued)
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { KMSClient, GenerateDataKeyCommand, DecryptCommand } from "@aws-sdk/client-kms";

const kms = new KMSClient({});
const KEY_ID = config.FIELD_ENCRYPTION_KEY_ID;

// Envelope encryption: KMS wraps a per-record data key; AES-256-GCM encrypts the value.
// Stored format: v1.<b64 wrappedKey>.<b64 iv>.<b64 tag>.<b64 ciphertext>
// SOC2:DATA-02 SOC2:SEC-07 — AES-256-GCM with a KMS-managed key, AAD binds ciphertext to the record
export async function encryptField(plain: string, aad: { table: string; column: string; recordId: string }): Promise<string> {
  const { Plaintext, CiphertextBlob } = await kms.send(new GenerateDataKeyCommand({ KeyId: KEY_ID, KeySpec: "AES_256" }));
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", Buffer.from(Plaintext!), iv);
  cipher.setAAD(Buffer.from(`${aad.table}.${aad.column}.${aad.recordId}`));
  const ct = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  Buffer.from(Plaintext!).fill(0);
  return ["v1", Buffer.from(CiphertextBlob!).toString("base64"), iv.toString("base64"), cipher.getAuthTag().toString("base64"), ct.toString("base64")].join(".");
}

export async function decryptField(stored: string, aad: { table: string; column: string; recordId: string }): Promise<string> {
  const [v, wrapped, iv, tag, ct] = stored.split(".");
  if (v !== "v1") throw new Error("unknown ciphertext version");
  const { Plaintext } = await kms.send(new DecryptCommand({ CiphertextBlob: Buffer.from(wrapped, "base64"), KeyId: KEY_ID }));
  const decipher = createDecipheriv("aes-256-gcm", Buffer.from(Plaintext!), Buffer.from(iv, "base64"));
  decipher.setAAD(Buffer.from(`${aad.table}.${aad.column}.${aad.recordId}`));
  decipher.setAuthTag(Buffer.from(tag, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(ct, "base64")), decipher.final()]).toString("utf8");
}

// Prisma: keep the column opaque (`taxId String @db.Text /// @classification restricted pii`)
// and wrap access in a repository so handlers never see the raw column.
export async function setTaxId(userId: string, taxId: string) {
  const ciphertext = await encryptField(taxId, { table: "users", column: "tax_id", recordId: userId });
  await db.user.update({ where: { id: userId }, data: { taxId: ciphertext } });
  // SOC2:LOG-01 — access to restricted data is audited by the caller with data.restricted.read/write
}
```

- Add a blind index (`hmac-sha256(key, normalize(value))` in a separate column) if you need to search by the encrypted value; equality on ciphertext is impossible because the IV is random.
- A single symmetric key in an env var is acceptable only with documented rotation; KMS envelope encryption (as above) makes SEC-02 rotation a key-alias update plus background re-wrap.
- Client-side `Prisma` middleware/extension can auto-encrypt on write and decrypt on read for tagged fields, but be explicit: implicit decryption on every `findMany` defeats the "access to restricted data is audited" goal.
- Mark the field in `schema.prisma` with a `///` doc comment carrying its classification so DATA-01 is greppable next to the column.

### 13. Retention/purge job skeleton (DATA-04, DATA-05)

```ts
// src/jobs/retention.ts
import { db } from "../lib/db";
import { audit } from "../lib/audit";
import { logger } from "../lib/logger";
import { search } from "../lib/search";
import { redis } from "../lib/redis";

// SOC2:DATA-04 — retention periods defined in one place, read from config (days)
const RETENTION_DAYS = {
  auditLog: config.RETENTION_AUDIT_DAYS,        // >= 365, LOG-04
  appLog: config.RETENTION_APP_LOG_DAYS,
  sessions: 30,
  passwordResetTokens: 1,
  deletedUsersGrace: 30,
  invoicesArchived: 7 * 365,
} as const;

const cutoff = (days: number) => new Date(Date.now() - days * 86_400_000);

export async function runRetention(correlationId: string): Promise<void> {
  const started = Date.now();

  // cheap tables first; each statement is bounded so a huge backlog cannot lock the table
  const sessions = await db.session.deleteMany({ where: { lastSeenAt: { lt: cutoff(RETENTION_DAYS.sessions) } } });
  const resets = await db.passwordResetToken.deleteMany({ where: { createdAt: { lt: cutoff(RETENTION_DAYS.passwordResetTokens) } } });

  // SOC2:DATA-05 — subject erasure past grace period: cascade to derived data, cache, search index
  const users = await db.user.findMany({ where: { deletedAt: { lt: cutoff(RETENTION_DAYS.deletedUsersGrace) } }, select: { id: true, tenantId: true }, take: 500 });
  for (const u of users) {
    await db.$transaction([
      db.userPreference.deleteMany({ where: { userId: u.id } }),
      db.apiKey.deleteMany({ where: { userId: u.id } }),
      db.user.delete({ where: { id: u.id } }),           // FK ON DELETE CASCADE handles the rest
    ]);
    await redis.del(`user:${u.id}`);
    await search.deleteDocument("users", u.id);
    await audit({ actor: { id: "retention-job", type: "system" }, action: "data.delete", target: { type: "user", id: u.id },
      outcome: "success", ip: undefined, correlation_id: correlationId, tenant_id: u.tenantId });
  }

  logger.info({ correlationId, sessions: sessions.count, resets: resets.count, users: users.length, ms: Date.now() - started }, "retention run complete");
}

// scheduled by the platform (K8s CronJob / ECS scheduled task), not by setInterval in the web process
if (require.main === module) runRetention(randomUUID()).then(() => process.exit(0)).catch((e) => { logger.error({ err: e }, "retention failed"); process.exit(1); });
```

- Run it as a separate process with its own DB role. If it runs inside the API process with the API's credentials, DELETE grants leak into the request path.
- Backups are outside this job's reach. DATA-05 requires the backup retention window to be documented so the auditor can see when erased data ages out of snapshots.
- Every erasure must produce an audit entry; a purge that silently removes records is indistinguishable from an attacker's deletion.
- Log counts, never the deleted records' contents.

### 14. Health/readiness endpoints (LOG-06)

```ts
// src/routes/health.ts
import { Router } from "express";
import { db } from "../lib/db";
import { redis } from "../lib/redis";

export const health = Router();

// SOC2:LOG-06 — liveness: process is up, no dependencies checked, no auth (listed in PUBLIC_ROUTES)
health.get("/healthz", (_req, res) => res.status(200).json({ status: "ok" }));

// SOC2:LOG-06 — readiness: dependencies reachable; unready => LB stops routing traffic
health.get("/readyz", async (_req, res) => {
  const checks = await Promise.allSettled([
    withTimeout(db.$queryRaw`SELECT 1`, 1500),
    withTimeout(redis.ping(), 1000),
  ]);
  const names = ["database", "redis"];
  const result = Object.fromEntries(checks.map((c, i) => [names[i], c.status === "fulfilled" ? "ok" : "fail"]));
  const ready = checks.every((c) => c.status === "fulfilled");
  res.status(ready ? 200 : 503).json({ status: ready ? "ready" : "degraded", checks: result });
});

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return Promise.race([p, new Promise<T>((_, rej) => setTimeout(() => rej(new Error("timeout")), ms))]);
}
```

- Do not include versions, hostnames, dependency URLs, or config in the response body. `{"database":"fail"}` is enough for an operator; `{"database":"postgres://prod-db-1:5432 ECONNREFUSED"}` is a finding.
- Readiness must time out. A hung DB pool that makes `/readyz` hang forever means the LB never marks the pod unhealthy.
- Exclude both endpoints from the global rate limiter and from request logging noise (or sample them), but not from the correlation-ID middleware.
- Wire uptime and p95 latency to the SLO monitor; the endpoint alone does not satisfy the "monitored against documented SLOs" half of LOG-06.

### 15. Route metadata and routes manifest (API-07, EVD-01)

```ts
// src/middleware/route-meta.ts
import type { RequestHandler } from "express";

export type Classification = "public" | "internal" | "confidential" | "restricted";
export interface RouteMeta {
  auth: "public" | "user" | "tenant_admin" | "platform_admin" | "service";
  classification: Classification;
  owner: string;                     // team handle, e.g. "@payments-team"
  pii?: boolean;
  description?: string;
}

export const routeRegistry: Array<RouteMeta & { method: string; path: string }> = [];

// SOC2:API-07 — a route without meta() cannot be registered through this helper
export function meta(m: RouteMeta): RequestHandler {
  const handler: RequestHandler = (req, res, next) => { res.locals.routeMeta = m; next(); };
  (handler as any).__routeMeta = m;
  return handler;
}

export function route(router: Router, method: "get" | "post" | "put" | "patch" | "delete", path: string, m: RouteMeta, ...handlers: RequestHandler[]) {
  routeRegistry.push({ method: method.toUpperCase(), path, ...m });
  const chain = m.auth === "public" ? handlers : [requireRole(...rolesFor(m.auth)), ...handlers];
  router[method](path, meta(m), ...chain);
}

// usage
route(router, "delete", "/invoices/:id",
  { auth: "user", classification: "confidential", owner: "@payments-team", pii: true },
  validate(deleteInvoice), requireOwnership(loadInvoice), deleteInvoiceHandler);

// scripts/routes-manifest.ts — run in CI, diff against committed .soc2/routes.json
// SOC2:EVD-01 — manifest is evidence that every route declares auth, classification, owner
import { writeFileSync } from "node:fs";
import { app } from "../src/app";
import { routeRegistry } from "../src/middleware/route-meta";
const registered = new Set(routeRegistry.map((r) => `${r.method} ${r.path}`));
const mounted = listExpressRoutes(app);                // walks app._router.stack
const undeclared = mounted.filter((r) => !registered.has(r));
if (undeclared.length) { console.error("Routes without metadata:", undeclared); process.exit(1); }
writeFileSync(".soc2/routes.json", JSON.stringify({ generatedAt: new Date().toISOString(), routes: routeRegistry }, null, 2));
```

- The manifest is only evidence if CI regenerates it and fails on drift (`git diff --exit-code .soc2/routes.json`). A hand-maintained file rots within a sprint.
- Walking `app._router.stack` is an Express 4 internal; Express 5 renames it to `app.router`. Fastify has `fastify.printRoutes()` and route `config`, which is cleaner: put `{ config: { auth, classification, owner } }` on each route and read it in an `onRoute` hook.
- NestJS: a custom `@RouteMeta()` decorator with `SetMetadata`, read via `Reflector` in a guard, and `DiscoveryService` to enumerate controllers for the manifest.
- `.soc2/CONTROL_MAP.md` should point at `.soc2/routes.json` as the evidence for API-07 and at this script as the generator.

## CI additions for this stack

| Job | Tool | Requirement |
|-----|------|-------------|
| `test` | `npm ci && npm test` (vitest/jest), coverage upload | CHG-02 |
| `typecheck-lint` | `tsc --noEmit`, `eslint` with `eslint-plugin-security`, `no-console` | CHG-02, LOG-03 |
| `sast` | Semgrep (`p/nodejs`, `p/typescript`, `p/owasp-top-ten`, `p/jwt`) or CodeQL `javascript-typescript` | SEC-04 |
| `sca` | `npm audit --audit-level=high` + OSV-Scanner or Snyk on the lockfile | SEC-03 |
| `secrets` | gitleaks (full history on default branch, diff on PRs) | SEC-01 |
| `routes-manifest` | `tsx scripts/routes-manifest.ts && git diff --exit-code .soc2/` | API-07, EVD-01 |
| `container` | Trivy on the built image; fails on HIGH/CRITICAL | SEC-05 |

```yaml
# .github/workflows/ci.yml (excerpt)
name: ci
on: { pull_request: {}, push: { branches: [main] } }
permissions: { contents: read, security-events: write }
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20, cache: npm }
      - run: npm ci --ignore-scripts          # lockfile enforced; no postinstall surprises
      - run: npm run typecheck && npm run lint
      - run: npm test -- --coverage
  sca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20, cache: npm }
      - run: npm ci --ignore-scripts
      - run: npm audit --audit-level=high --omit=dev   # SOC2:SEC-03
  sast:
    runs-on: ubuntu-latest
    container: returntocorp/semgrep
    steps:
      - uses: actions/checkout@v4
      - run: semgrep ci --config p/nodejs --config p/typescript --config p/owasp-top-ten --config p/jwt   # SOC2:SEC-04
  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: gitleaks/gitleaks-action@v2        # SOC2:SEC-01
        env: { GITHUB_TOKEN: "${{ secrets.GITHUB_TOKEN }}" }
```

Branch protection must list `test`, `sca`, `sast`, and `secrets` as required status checks (CHG-01, CHG-02); a job that runs but is not required is advisory and does not count.

## Known pitfalls in this stack

- **Middleware order.** A router mounted with `app.use("/v1/admin", adminRouter)` above `app.use(requireAuth)` is unauthenticated. Reviewers rarely read `app.ts` top to bottom; the scanner should.
- **`trust proxy: true`.** Turns every IP-keyed control (rate limit, lockout, audit `ip`) into client-controlled data via `X-Forwarded-For`.
- **`process.env.X || "default"` for secrets.** Ships a working default credential into production and makes SEC-01 and SEC-06 findings simultaneously. Same for `JWT_SECRET = "changeme"` in a docker-compose file that is reused in prod.
- **Async errors in Express 4.** An unhandled rejection in a handler never reaches the error handler; the client hangs, no correlation ID is logged, and the failure is invisible to LOG-05 error-rate alerts.
- **`z.object()` without `.strict()`.** Unknown fields are stripped silently; `role: "admin"` in a signup body is discarded instead of rejected, so nobody notices the probe. Also `.passthrough()` on any request schema is mass assignment by design.
- **Prisma `log: ["query"]` and `pino-pretty` in production.** Both leak parameter values or break JSON shipping. Confirm via the production `LOG_LEVEL` and the image's `CMD`.
- **`cors({ origin: true })` or reflecting `req.headers.origin`.** Any site can make credentialed requests. Combined with cookie sessions and no CSRF token, this is a full account-takeover primitive.
- **Stateless JWT with no revocation list and 7-day expiry.** Deactivating a user (AUTH-07) does nothing until the token expires. Either cap `maxTokenAge` at 1h with rotating refresh tokens or check `jti` against a revocation store on every request.
