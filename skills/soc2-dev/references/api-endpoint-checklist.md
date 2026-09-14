# API Endpoint Checklist

This file details API-01 through API-10 from `requirements.md`. It covers everything that happens between a request arriving and a response leaving: input validation, output encoding, safe use of downstream systems (database, shell, templates), abuse limits, error handling, browser security headers, route metadata, idempotency, versioning, and file uploads. These requirements serve Security criteria CC6.1 (logical access), CC6.6 (external threats), CC6.8 (unauthorized software), CC7.1 and CC7.2 (detection and monitoring), CC5.3 and CC2.3/CC8.1 (control ownership, communication, and change), plus Processing Integrity PI1.1/PI1.2 and Availability A1.1 where in scope. Every item here is something a reviewer can check on the PR diff without running the system.

## When Claude must load this file

- Adding or modifying a route, controller, handler, resolver, gRPC method, or webhook receiver
- Adding or changing request parsing, DTOs, schemas, serializers, or validators
- Writing any database query, ORM call, raw SQL, shell exec, LDAP lookup, or template render
- Changing error handlers, exception middleware, or response formatting
- Modifying CORS, CSP, cookie, or other header configuration; adding a new frontend origin
- Adding a public or unauthenticated endpoint, or changing rate-limit or body-size settings
- Adding an endpoint that creates, charges, sends, or otherwise has side effects and may be retried
- Introducing a breaking API change, removing a field, or bumping an API version
- Adding file upload, download, or import/export functionality

## Requirements

### API-01 — Schema-validate all inputs; reject unknown fields

**Rule:** Every input (body, query string, path params, headers you read, multipart fields, files) is validated against an explicit schema before any business logic runs. Unknown fields are rejected, not silently dropped.

**TSC:** CC6.1, PI1.1

**How to implement:**
- One schema per endpoint, declared next to the route. Node: `zod` (`z.object({...}).strict()`), `joi` (`.unknown(false)`), or `ajv` with `additionalProperties: false`. Python: `pydantic` models with `model_config = ConfigDict(extra="forbid")` (FastAPI uses them automatically); Django REST Framework serializers with explicit fields plus a check for unexpected keys. Go: `go-playground/validator` struct tags plus `json.Decoder.DisallowUnknownFields()`. Java/Spring: Bean Validation (`@Valid`, `@NotNull`, `@Size`, `@Pattern`) with `spring.jackson.deserialization.fail-on-unknown-properties=true`.
- Validate types, ranges, lengths, enums, and formats (UUID, email, ISO-8601). Bound every string (`max`) and every array (`max items`); unbounded inputs are a DoS and a storage-cost vector.
- Validate path params and query strings too: `?page=-1`, `?limit=100000`, `?sort=owner_id;DROP` must all fail.
- Never spread the raw body into an ORM call (`Model.create(req.body)`, `User(**request.json)`) — that is mass assignment. Build the model from the parsed schema output only.
- Reject before authorization-expensive work; return 400 with field-level errors, no echo of the offending value for sensitive fields.
- For GraphQL: depth and complexity limits (`graphql-depth-limit`, `graphql-query-complexity`) and disabled introspection in production.

**Code example:**

```javascript
// routes/invoices.js
const { z } = require('zod');

const CreateInvoice = z.object({
  customerId: z.string().uuid(),
  currency: z.enum(['USD', 'EUR', 'GBP']),
  lines: z.array(z.object({
    sku: z.string().min(1).max(64),
    quantity: z.number().int().min(1).max(10_000),
    unitCents: z.number().int().min(0).max(100_000_000),
  })).min(1).max(500),
  memo: z.string().max(1000).optional(),
}).strict(); // SOC2:API-01 — unknown fields rejected; no mass assignment

router.post('/invoices', async (req, res) => {
  const parsed = CreateInvoice.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'validation_failed', issues: parsed.error.issues });
  }
  const invoice = await invoices.create({ ...parsed.data, tenantId: req.user.tenantId });
  res.status(201).json(invoice);
});
```

**Common violations:**
- `Model.create(req.body)` or `serializer = Serializer(data=request.data)` with a `fields = '__all__'` serializer.
- Schema declared but `.strict()` / `extra="forbid"` / `DisallowUnknownFields` omitted, allowing `{"role":"admin"}` through.
- Query params cast with `parseInt` and no bound, so `?limit=1e9` reaches the database.
- Headers such as `X-Forwarded-For` or `X-Tenant-Id` used without validation or allow-listing the proxy that sets them.

**Evidence to produce:**
- Schema files co-located with routes (`routes/*/schema.*`, `app/schemas/*.py`, `*Request.java` DTOs)
- A CI test that posts an unknown field and asserts 400; framework config enabling fail-on-unknown

### API-02 — Context-aware output encoding and explicit content types

**Rule:** All output is encoded for the context it lands in (HTML, attribute, JS, URL, header, JSON). Every response sets an explicit `Content-Type`. Untrusted data is never reflected raw into HTML, response headers, or redirect targets.

**TSC:** CC6.1

**How to implement:**
- Use auto-escaping templates and never disable them for user data: Jinja2 with `autoescape=True` (Django templates escape by default), Go `html/template` (never `text/template` for HTML), React/JSX default escaping (no `dangerouslySetInnerHTML` with user content), Thymeleaf `th:text` not `th:utext`.
- JSON APIs: always `res.json()` / `JSONResponse` / `encoding/json` — never build JSON strings. Set `Content-Type: application/json; charset=utf-8` and `X-Content-Type-Options: nosniff` (API-06).
- Headers: reject `\r` and `\n` in any value derived from input (most frameworks throw; do not catch and retry). Never set `Location` from a raw parameter.
- Redirects: allow-list of relative paths or known hosts; parse with `new URL(target, base)` and compare `origin`. Open redirects fail audits and phishing tests.
- If you must render user-supplied HTML (rich text), sanitize with `DOMPurify` (browser), `sanitize-html` (Node), `bleach`/`nh3` (Python), `bluemonday` (Go), OWASP Java HTML Sanitizer — with an explicit tag allow-list.
- Serve user-uploaded files from a separate origin or with `Content-Disposition: attachment` (see API-10).

**Code example:**

```go
// internal/http/redirect.go
package httpx

import (
	"net/http"
	"net/url"
)

var allowedReturnHosts = map[string]bool{"app.example.com": true, "admin.example.com": true}

// SOC2:API-02 — redirect target validated against an allow-list; never reflected raw
func SafeRedirect(w http.ResponseWriter, r *http.Request, target string) {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "" && u.Scheme != "https" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if u.Host != "" && !allowedReturnHosts[u.Host] {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	// relative path or allow-listed host; strip userinfo and fragments
	u.User, u.Fragment = nil, ""
	http.Redirect(w, r, u.String(), http.StatusFound)
}
```

**Common violations:**
- `res.send('<p>Hello ' + req.query.name + '</p>')` or `{% autoescape off %}` around user data.
- `res.redirect(req.query.next)` with no validation.
- Error pages that echo the requested path or query unescaped.
- API responses with no `Content-Type` or `text/html` on JSON, enabling MIME-sniffing XSS.

**Evidence to produce:**
- Template engine configuration showing autoescape, and the sanitizer allow-list for any rich-text path
- The redirect helper and a test proving `//evil.com` and `https://evil.com` are rejected

### API-03 — Parameterized queries and safe APIs only

**Rule:** All calls to databases, shells, LDAP, and template engines use parameterization or a safe API. No query, command, filter, or template is built by string concatenation or interpolation of input.

**TSC:** CC6.1, CC7.1

**How to implement:**
- SQL: bound parameters everywhere — `pg` `$1`, `mysql2` `?`, `psycopg` `%s` with a params tuple, `database/sql` `?`/`$1`, JDBC `PreparedStatement`/JPA named params. ORMs (Prisma, SQLAlchemy, GORM, Hibernate) are safe until you use `$queryRawUnsafe`, `text()` with f-strings, `db.Raw(fmt.Sprintf(...))`, or `createNativeQuery(string + input)`.
- Identifiers (table/column names, `ORDER BY`) cannot be parameterized: map input to a hard-coded allow-list of column names.
- Shell: do not shell out if a library exists. If you must, use argument arrays with no shell: `execFile` (Node, never `exec`), `subprocess.run([...], shell=False)`, `exec.Command(name, args...)`, `ProcessBuilder`. Never interpolate into a command string.
- LDAP: escape with `ldap3.utils.conv.escape_filter_chars`, `ldapjs` filter objects, Spring `LdapEncoder.filterEncode`.
- Templates: never pass user input as the template source (SSTI). `render(template_string_from_user)` is a remote code execution finding. Use precompiled templates with data as context.
- NoSQL: MongoDB operators from input (`{ $gt: "" }`) are injection — validate types (API-01) and use `mongo-sanitize` or equivalent.
- Enable a SAST rule (Semgrep `sql-injection`, `subprocess-shell-true`, CodeQL) so this is caught in CI (SEC-04).

**Code example:**

```python
# app/repos/users.py
import psycopg

ALLOWED_SORT = {"created_at": "created_at", "email": "email", "last_login": "last_login_at"}

def search_users(conn: psycopg.Connection, tenant_id: str, q: str, sort: str, limit: int):
    # SOC2:API-03 — values bound as parameters; identifiers mapped through an allow-list
    order_col = ALLOWED_SORT.get(sort)
    if order_col is None:
        raise ValueError("invalid sort")
    sql = f"""
        SELECT id, email, status, created_at
        FROM users
        WHERE tenant_id = %s AND email ILIKE %s
        ORDER BY {order_col} DESC
        LIMIT %s
    """  # only order_col is interpolated, and it comes from ALLOWED_SORT, never from input
    with conn.cursor() as cur:
        cur.execute(sql, (tenant_id, f"%{q}%", min(limit, 100)))
        return cur.fetchall()
```

**Common violations:**
- `db.query(\`SELECT * FROM users WHERE email = '${email}'\`)`; `cursor.execute(f"... {user_id}")`.
- `ORDER BY ${req.query.sort}` because "parameters don't work for ORDER BY."
- `child_process.exec('convert ' + filename)`; `os.system(f"tar xzf {path}")`.
- ORM raw-query escape hatches used for "performance" with interpolated filters.

**Evidence to produce:**
- Semgrep/CodeQL rule set in CI blocking injection patterns (`.semgrep.yml`, `.github/workflows/sast.yml`)
- Repository layer files showing bound parameters; the identifier allow-list

### API-04 — Rate limits and body size limits on public endpoints

**Rule:** Every public (internet-reachable) endpoint has a rate limit and a maximum request body size. Limits are enforced at the edge and in the application.

**TSC:** CC6.6, A1.1

**How to implement:**
- Body size: set a global cap and lower per-route caps. Express `express.json({ limit: '100kb' })`; FastAPI/Starlette via a middleware checking `Content-Length` and streaming cap, or at uvicorn/nginx (`client_max_body_size`); Go `http.MaxBytesReader(w, r.Body, 1<<20)`; Spring `spring.servlet.multipart.max-request-size` and `server.max-http-request-header-size`. Upload routes get their own, larger limit (API-10).
- Rate limits: token bucket per API key / user / IP with a shared Redis store (`rate-limiter-flexible`, `slowapi`, `ulule/limiter`, `bucket4j`). Return 429 with `Retry-After` and `RateLimit-*` headers.
- Edge: AWS WAF rate-based rules, CloudFront, API Gateway usage plans and throttling; GCP Cloud Armor rate-based bans, Apigee quotas; Cloudflare Rate Limiting. Edge limits protect against volumetric abuse; app limits protect expensive routes (search, export, email send).
- Set per-route budgets where cost differs: e.g. 600/min for reads, 60/min for writes, 5/min for `/export`, `/invite`, `/send-verification`.
- Timeouts: `server.ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout` (Go); `--timeout-keep-alive` (uvicorn); `server.headersTimeout`/`requestTimeout` (Node ≥ 18). Slowloris is an availability finding.
- Limit pagination (`limit ≤ 100`) and query complexity for search endpoints.

**Code example:**

```go
// cmd/api/main.go
package main

import (
	"net/http"
	"time"
)

const maxBodyBytes = 1 << 20 // 1 MiB default; upload routes override

// SOC2:API-04 — body cap and server timeouts on every public route
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

func newServer(h http.Handler, rl *RateLimiter) *http.Server {
	return &http.Server{
		Addr:              ":8080",
		Handler:           limitBody(rl.Middleware(h)), // rl: per-key token bucket in Redis
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}
```

**Common violations:**
- Body parser with the framework default (Express `100kb` is fine; Node raw `http` and Go `net/http` have no cap at all).
- Rate limiting on `/login` only; `/search`, `/export`, and `/webhooks` unlimited.
- In-process limiter that resets on every deploy or differs per replica.
- No `Retry-After`, so well-behaved clients retry in a tight loop.

**Evidence to produce:**
- Server configuration (`cmd/api/main.go`, `app.ts` body parser, `application.yml`) and limiter middleware
- WAF / API Gateway throttling rule export; a load test or integration test hitting 413 and 429

### API-05 — Generic errors with a correlation ID

**Rule:** Error responses contain a stable error code and a generic message — never stack traces, SQL, file paths, dependency versions, or internal hostnames — and carry a correlation ID that appears in server logs.

**TSC:** CC6.1, CC7.2

**How to implement:**
- One global error handler: map known error types to `{ error: "<code>", message: "<safe text>", correlation_id }` and everything else to 500 `"internal_error"`. Log the full exception with the same `correlation_id` server-side (LOG-02).
- Correlation ID: accept an incoming `X-Request-Id` from your own edge only (regenerate if absent or malformed), attach it to the logger context (`AsyncLocalStorage` in Node, `contextvars` in Python, `context.Context` in Go, MDC in Java), and return it in the `X-Request-Id` header and error body.
- Framework flags: Express — no `NODE_ENV=development`; do not use `errorhandler` in prod. Django `DEBUG = False`; FastAPI custom `exception_handler(Exception)`; Spring `server.error.include-stacktrace=never`, `include-message=never`, `include-exception=false`; Go — never write `err.Error()` to the response for unexpected errors.
- Validation errors (API-01) may list field names and constraint types; they must not echo secrets or full submitted values.
- 404 for not-found or not-authorized objects where existence is sensitive (AUTH-02). Same shape and timing for auth failures (AUTH-06).
- Test: an integration test that forces an unhandled exception and asserts the body has no `at ` / `Traceback` / `.go:` strings.

**Code example:**

```javascript
// middleware/errorHandler.js
const { randomUUID } = require('crypto');
const logger = require('../logger');

class AppError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}

// SOC2:API-05 — generic client-facing error, full detail only in logs, linked by correlation_id
function errorHandler(err, req, res, _next) {
  const correlationId = req.id ?? randomUUID();
  res.setHeader('X-Request-Id', correlationId);

  if (err instanceof AppError) {
    logger.warn({ correlationId, code: err.code, path: req.path }, err.message);
    return res.status(err.status).json({ error: err.code, message: err.message, correlation_id: correlationId });
  }
  logger.error({ correlationId, path: req.path, err }, 'unhandled error'); // stack goes here only
  return res.status(500).json({ error: 'internal_error', message: 'Something went wrong.', correlation_id: correlationId });
}
module.exports = { errorHandler, AppError };
```

**Common violations:**
- `res.status(500).send(err.stack)` or Django `DEBUG=True` in a staging environment reachable from the internet.
- ORM errors passed through: `duplicate key value violates unique constraint "users_email_key"`.
- Correlation ID present in logs but not returned to the client, so support cannot find the request.
- Different messages for "user not found" vs "wrong password" (see AUTH-06).

**Evidence to produce:**
- The global error handler (`middleware/errorHandler.*`, `app/exceptions.py`, `@ControllerAdvice` class) and framework config disabling debug output
- A log query joining a client-reported `correlation_id` to the server-side stack trace

### API-06 — Security headers, CORS allow-list, CSRF protection

**Rule:** Responses set HSTS, CSP, `X-Content-Type-Options: nosniff`, and frame protection. CORS allows an explicit origin list, never `*` when credentials are involved. Cookie-authenticated state-changing requests are protected by SameSite plus a CSRF token or origin check.

**TSC:** CC6.6

**How to implement:**
- Headers: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` (start with a lower max-age, then raise), `Content-Security-Policy` with `default-src 'self'`, nonce-based `script-src`, `object-src 'none'`, `frame-ancestors 'none'` (or an allow-list), `base-uri 'self'`; `X-Content-Type-Options: nosniff`; `X-Frame-Options: DENY` for older clients; `Referrer-Policy: strict-origin-when-cross-origin`; `Permissions-Policy` to disable unused features. Libraries: `helmet` (Node), `django-csp` + `SECURE_*` settings, `secure` (FastAPI), `unrolled/secure` (Go), Spring Security `headers()`.
- CORS: explicit origin list from config; reflect only if the request `Origin` is in the list; `Access-Control-Allow-Credentials: true` only with a specific origin; limit `Allow-Methods` and `Allow-Headers`; set `Vary: Origin`. `cors` (Node), `CORSMiddleware` (FastAPI), `django-cors-headers` with `CORS_ALLOWED_ORIGINS`, `rs/cors` (Go), `@CrossOrigin`/`CorsConfigurationSource` (Spring).
- CSRF (cookie sessions only; bearer-token APIs are exempt): `SameSite=Lax` on the session cookie plus one of: synchronizer token (`csrf-csrf`/`csurf` successor in Node, Django `CsrfViewMiddleware`, Spring `CsrfFilter`), double-submit cookie with a signed value, or strict `Origin`/`Sec-Fetch-Site` header check rejecting cross-site on non-GET. Do not accept state changes via GET.
- Set headers at the framework level and at the edge (ALB/CloudFront response headers policy, Cloud Load Balancer, nginx `add_header`) so static assets get them too.
- CSP `report-to` endpoint so violations surface before you tighten policy.

**Code example:**

```python
# app/main.py — FastAPI with cookie sessions
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from app.settings import settings  # ALLOWED_ORIGINS loaded from config, not '*'

app = FastAPI()

app.add_middleware(  # SOC2:API-06 — explicit origin allow-list with credentials
    CORSMiddleware, allow_origins=settings.ALLOWED_ORIGINS, allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"], allow_headers=["Content-Type", "X-CSRF-Token"],
)

@app.middleware("http")
async def security_headers_and_csrf(request: Request, call_next):
    if request.method not in ("GET", "HEAD", "OPTIONS") and "session" in request.cookies:
        # SOC2:API-06 — CSRF: origin check + double-submit token for cookie-authenticated writes
        origin = request.headers.get("origin") or request.headers.get("referer", "")
        if not any(origin.startswith(o) for o in settings.ALLOWED_ORIGINS):
            raise HTTPException(403, "csrf_origin")
        if request.headers.get("x-csrf-token") != request.cookies.get("csrf"):
            raise HTTPException(403, "csrf_token")
    resp = await call_next(request)
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return resp
```

**Common violations:**
- `cors({ origin: true, credentials: true })` or `allow_origins=["*"]` with `allow_credentials=True` (browsers reject it, so someone "fixes" it by reflecting any origin).
- CSP present but `script-src 'unsafe-inline' 'unsafe-eval'` everywhere, or CSP only in report-only mode for two years.
- HSTS `max-age=300` left from initial rollout; no `includeSubDomains`.
- CSRF middleware present but a new router mounted without it, or `@csrf_exempt` on a "temporary" webhook that also accepts session cookies.

**Evidence to produce:**
- Header/CORS/CSRF configuration file and the origin list in config; a securityheaders.com or `curl -I` capture of production
- A test asserting a cross-origin POST with a valid session cookie but no CSRF token returns 403

### API-07 — Route metadata: auth, classification, owner

**Rule:** Each route declares its authentication requirement, the highest data classification it handles, and the owning team, in a machine-readable form (decorator, annotation, route metadata, or a routes manifest) that can be listed and diffed.

**TSC:** CC5.3

**How to implement:**
- Pick one mechanism and enforce it in CI: a decorator/annotation on the handler (`@route_meta(auth="user", classification="confidential", owner="payments")`), NestJS `SetMetadata`, Spring custom annotation `@Soc2Route(...)`, Go a `RouteSpec` struct registered with the handler, or a `routes.yml` manifest keyed by `METHOD /path`.
- Classification values match DATA-01 (`public`, `internal`, `confidential`, `restricted`). Auth values match your AUTH-01 tiers (`public`, `user`, `admin`, `service`).
- Write a startup or CI check that walks the router and fails when a route has no metadata. This is the same enumeration used for AUTH-01 tests — share the code.
- Emit the manifest as a build artifact (`build/routes.json`) and diff it in PRs; new `restricted` or `public` routes should trigger CODEOWNERS review (CHG-04).
- Owner should be a team handle that maps to an on-call rotation (LOG-05) and to `CONTROL_MAP.md` (EVD-01).
- Use the metadata: the rate limiter, the audit logger (LOG-01 for `restricted`), and the CSRF/CORS layer can all read it instead of being configured separately.

**Code example:**

```go
// internal/http/routes.go
package httpx

type RouteSpec struct {
	Method, Path    string
	Auth            string // public | user | admin | service
	Classification  string // public | internal | confidential | restricted
	Owner           string // team handle, e.g. "payments"
	Handler         http.HandlerFunc
}

// SOC2:API-07 — every route registered with auth tier, data classification, and owner
var Routes = []RouteSpec{
	{"GET", "/health", "public", "public", "platform", healthHandler},
	{"GET", "/invoices/{id}", "user", "confidential", "payments", getInvoice},
	{"POST", "/admin/users/{id}/deactivate", "admin", "restricted", "identity", deactivateUser},
}

func Register(mux *http.ServeMux) {
	for _, rt := range Routes {
		if rt.Auth == "" || rt.Classification == "" || rt.Owner == "" {
			panic("route missing SOC2 metadata: " + rt.Method + " " + rt.Path) // fails at startup and in CI
		}
		mux.Handle(rt.Method+" "+rt.Path, withAuth(rt.Auth, withAudit(rt.Classification, rt.Handler)))
	}
}
```

**Common violations:**
- Metadata lives in a wiki page that drifted from the code within a month.
- Decorator exists but is optional; half the routes have it.
- Owner is a person's name who left the company.
- Classification defaulted to `internal` everywhere so nobody has to think about it.

**Evidence to produce:**
- The route registry / decorator definition and the CI check that fails on missing metadata
- Generated `routes.json` (or equivalent) attached to the release, showing auth tier and owner per route

### API-08 — Idempotent mutations and transactional writes

**Rule:** Mutating endpoints that clients or queues may retry accept an idempotency key and return the original result on replay. Multi-step writes execute inside a single transaction or a compensating saga; partial writes are never left behind.

**TSC:** PI1.1, PI1.2

**How to implement:**
- Accept `Idempotency-Key` (UUID, ≤ 255 chars) on `POST` endpoints that create, charge, send, or enqueue. Store `(tenant_id, key) -> request_hash, status, response_body, created_at` with a unique constraint; on a hit, compare the request hash (mismatch → 422) and return the stored response. Expire keys after 24 h to 7 days.
- Do the check-and-insert atomically (unique index plus `INSERT ... ON CONFLICT DO NOTHING RETURNING`, or `SELECT ... FOR UPDATE`) so concurrent duplicates don't both proceed.
- Wrap multi-table writes in a transaction: Prisma `$transaction`, Knex `trx`, SQLAlchemy `with session.begin()`, Django `@transaction.atomic`, `database/sql` `BeginTx`, Spring `@Transactional`. Do external side effects (email, payment) after commit, or use the outbox pattern.
- Queue consumers: make handlers idempotent by message ID; use visibility timeouts and dead-letter queues (SQS, Pub/Sub, RabbitMQ) rather than at-most-once delivery.
- Downstream providers with their own idempotency (Stripe, SES, Twilio) get your key passed through.
- Use `PUT`/`PATCH` with optimistic concurrency (`If-Match`/`version` column) for updates so lost-update races are detected.

**Code example:**

```python
# app/api/payments.py
from fastapi import APIRouter, Header, HTTPException, Depends
from sqlalchemy import text
from app.db import Session
from app.auth import current_principal

router = APIRouter()

@router.post("/payments")
def create_payment(body: CreatePayment, idempotency_key: str = Header(..., alias="Idempotency-Key"),
                   p=Depends(current_principal), db: Session = Depends(get_db)):
    req_hash = body.stable_hash()
    with db.begin():  # SOC2:API-08 — atomic key claim + all writes in one transaction
        row = db.execute(text("""
            INSERT INTO idempotency_keys (tenant_id, key, request_hash, status)
            VALUES (:t, :k, :h, 'in_progress')
            ON CONFLICT (tenant_id, key) DO NOTHING
            RETURNING id"""), {"t": p.tenant_id, "k": idempotency_key, "h": req_hash}).first()
        if row is None:  # replay
            prev = db.execute(text("SELECT request_hash, status, response FROM idempotency_keys "
                                   "WHERE tenant_id=:t AND key=:k"), {"t": p.tenant_id, "k": idempotency_key}).one()
            if prev.request_hash != req_hash: raise HTTPException(422, "idempotency_key_reused")
            if prev.status != "done": raise HTTPException(409, "in_progress")
            return prev.response
        payment = payments.create(db, p.tenant_id, body)          # write 1
        ledger.post(db, payment)                                   # write 2, same transaction
        db.execute(text("UPDATE idempotency_keys SET status='done', response=:r WHERE id=:id"),
                   {"r": payment.to_json(), "id": row.id})
    return payment.to_json()
```

**Common violations:**
- Payment or email sent inside the transaction; on rollback the side effect has already happened.
- Idempotency check implemented as `SELECT` then `INSERT` without a unique constraint (race).
- Keys scoped globally instead of per tenant, so one tenant can replay another's response.
- Multi-step writes across two services with no compensation; a failure leaves an orphaned record.

**Evidence to produce:**
- `idempotency_keys` migration with its unique index; the transaction wrapper in the handler
- A test that sends the same request twice concurrently and asserts one write and identical responses

### API-09 — Versioning and deprecation communication

**Rule:** Public and partner APIs are versioned. Breaking changes ship as a new version; deprecated versions carry a published sunset date, are announced to consumers, and are monitored until removed.

**TSC:** CC2.3, CC8.1

**How to implement:**
- Choose one scheme and stick to it: URL prefix (`/v1/`), header (`Accept: application/vnd.example.v2+json`), or date-based (`Example-Version: 2026-09-01`, Stripe-style). URL prefix is the easiest to route and review.
- Define "breaking" in a written policy: removing or renaming a field, changing a type, tightening validation, changing auth, changing error codes. Adding optional fields is not breaking (clients must ignore unknown fields — note this is the reverse of API-01, which is for inbound).
- Publish an OpenAPI spec per version (`openapi/v1.yaml`) and run a diff in CI (`oasdiff`, `openapi-diff`) that fails on breaking changes to a published version.
- Deprecation headers: `Deprecation: true` (or a date), `Sunset: <HTTP-date>`, `Link: <changelog-url>; rel="deprecation"`. Log version usage per API key so you can contact remaining consumers.
- Communication: changelog entry, email to registered API contacts, and a minimum notice period (90 days for partner APIs is typical). Record the notice in the ticket linked from the PR (CHG-03).
- Internal APIs between your own services still need compatibility: deploy consumer-tolerant changes first (expand/contract), never a synchronized big-bang.

**Code example:**

```javascript
// app.js
const v1 = require('./routes/v1');
const v2 = require('./routes/v2');

const SUNSET_V1 = 'Tue, 31 Mar 2027 00:00:00 GMT';

// SOC2:API-09 — versioned prefixes; deprecated version advertises Deprecation/Sunset and is metered
app.use('/v1', (req, res, next) => {
  res.setHeader('Deprecation', 'true');
  res.setHeader('Sunset', SUNSET_V1);
  res.setHeader('Link', '<https://docs.example.com/changelog#v1-sunset>; rel="deprecation"');
  metrics.increment('api.version.request', { version: 'v1', api_key: req.apiKeyId });
  next();
}, v1);

app.use('/v2', v2);

// unversioned paths are not served; fail loudly instead of silently mapping to latest
app.use('/', (req, res) => res.status(404).json({ error: 'unversioned_path', hint: 'use /v2' }));
```

**Common violations:**
- `/api/` with no version, fields removed in place, and consumers discover it in production.
- A version prefix exists but breaking changes are made "within" `v1`.
- Sunset announced only in a Slack channel; no record for the auditor.
- Old version removed without checking usage metrics; a partner integration breaks.

**Evidence to produce:**
- OpenAPI specs per version and the CI diff job blocking breaking changes
- Changelog entries and consumer notification records for each deprecation, plus version-usage dashboard

### API-10 — Safe file uploads

**Rule:** Uploads are validated for type (by content, not extension) and size, stored outside the web root or in object storage with private ACLs under a server-generated name, and scanned for malware or quarantined before use.

**TSC:** CC6.1, CC6.8

**How to implement:**
- Enforce size at the edge and in the handler (`multer` `limits.fileSize`, Starlette `UploadFile` with a streaming size check, Go `MaxBytesReader` + `ParseMultipartForm`, Spring `spring.servlet.multipart.max-file-size`). Stream to storage; never buffer whole files in memory.
- Validate type by magic bytes (`file-type` in Node, `python-magic`, Go `http.DetectContentType`, Apache Tika) against a per-endpoint allow-list. Reject SVG/HTML unless sanitized; they execute scripts when rendered inline.
- Rename to a server-generated key (`<tenant>/<uuid>.<ext-from-detected-type>`); never use the client filename in a path. Store the original name as metadata only.
- Storage: S3/GCS bucket with public access blocked, bucket-level encryption (INFRA-04), object keys scoped by tenant, and access through short-lived presigned/signed URLs (≤ 15 min). Serve downloads with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`, ideally from a separate origin.
- Scan: ClamAV (`clamd` sidecar, `clamav-node`, `pyclamd`), AWS GuardDuty Malware Protection for S3, GCP Cloud Storage + Cloud Functions with ClamAV, or a commercial API. Write to a `quarantine/` prefix, tag `scan=pending`, and only move to `clean/` after a pass; downstream code reads `clean/` only.
- Images: re-encode with `sharp`/Pillow/`imaging` to strip metadata and neutralize polyglots. Documents: consider converting to PDF in an isolated worker. Archives: reject or extract with path and size limits (zip-slip, zip bombs).
- Direct-to-storage uploads: use presigned POST with conditions (`content-length-range`, `Content-Type` starts-with) so the browser cannot bypass limits.

**Code example:**

```javascript
// routes/uploads.js
const multer = require('multer');
const { fileTypeFromBuffer } = require('file-type');
const { randomUUID } = require('crypto');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');

const ALLOWED = new Map([['image/png', 'png'], ['image/jpeg', 'jpg'], ['application/pdf', 'pdf']]);
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024, files: 1 } });
const s3 = new S3Client({});

router.post('/uploads', upload.single('file'), async (req, res) => {
  // SOC2:API-10 — type by magic bytes, server-generated key, private bucket, quarantine until scanned
  const detected = await fileTypeFromBuffer(req.file.buffer.subarray(0, 4100));
  if (!detected || !ALLOWED.has(detected.mime)) return res.status(415).json({ error: 'unsupported_type' });

  const key = `quarantine/${req.user.tenantId}/${randomUUID()}.${ALLOWED.get(detected.mime)}`;
  await s3.send(new PutObjectCommand({
    Bucket: process.env.UPLOAD_BUCKET, Key: key, Body: req.file.buffer,
    ContentType: detected.mime, ACL: 'private', ServerSideEncryption: 'aws:kms',
    Metadata: { original_name: encodeURIComponent(req.file.originalname), scan: 'pending' },
  }));
  await scanQueue.send({ key });            // worker moves to clean/ after ClamAV passes
  res.status(202).json({ upload_id: key.split('/').pop(), status: 'scanning' });
});
```

**Common violations:**
- Type checked via `req.file.mimetype` (client-supplied) or file extension only.
- Files written to `public/uploads/<originalname>` inside the web root; path traversal via `../`.
- Bucket with public-read ACL "so the frontend can load images"; no signed URLs.
- No scanning, or scanning that runs but nothing consumes the result.

**Evidence to produce:**
- Upload handler with type allow-list and size limits; bucket policy showing public access blocked and encryption on
- Scanner deployment (ClamAV sidecar manifest, GuardDuty configuration) and a log query showing scan outcomes

### API-11 — Webhook and callback signature verification

**Rule:** Every inbound webhook or third-party callback verifies a signature before any processing, using a constant-time comparison, rejects events older than a short replay window, and is idempotent on the provider's event ID. Unsigned or unverifiable requests are rejected with 401 and audit-logged.

**TSC:** CC6.6, CC6.1

**How to implement:**
- Use the provider's SDK verifier where one exists (`stripe.webhooks.constructEvent`, `@octokit/webhooks` `verify`, Twilio `validateRequest`, Slack signing secret). For custom integrations, compute HMAC-SHA256 over the raw request body plus timestamp with a per-integration secret from the secret manager.
- Read the **raw** body for verification. Body parsers that re-serialize JSON break signatures; register the raw-body parser on the webhook route only.
- Compare with `crypto.timingSafeEqual`, `hmac.compare_digest`, `hmac.Equal`, or `MessageDigest.isEqual`. Never `===` or `==`.
- Reject requests whose timestamp header is older than 5 minutes; store processed event IDs (with TTL) and skip duplicates (API-08).
- Keep the webhook secret rotatable (SEC-02): support two active secrets during rotation.
- Do not list webhook routes in `public_routes`; they are authenticated by signature, and the scanner checks for a verifier in the handler file.

**Code example:**

```typescript
// src/routes/webhooks/stripe.ts
import express from "express";
import Stripe from "stripe";
const stripe = new Stripe(config.stripeSecretKey);
export const router = express.Router();

router.post("/stripe", express.raw({ type: "application/json" }), async (req, res) => {
  let event: Stripe.Event;
  try {
    // SOC2:API-11 signature + timestamp verified by the SDK (constant-time, 5-min tolerance)
    event = stripe.webhooks.constructEvent(req.body, req.header("stripe-signature") ?? "", config.stripeWebhookSecret);
  } catch (err) {
    audit.log({ event_type: "webhook.rejected", outcome: "failure", target_type: "stripe", ip: req.ip });
    return res.status(401).json({ error: "invalid signature" });
  }
  if (await processedEvents.claim(event.id, { ttlSeconds: 86400 }) === false) return res.status(200).end(); // duplicate
  await handleStripeEvent(event);
  res.status(200).end();
});
```

**Common violations:**
- Webhook route accepts any POST and trusts the payload's `customer_id`.
- Signature compared with `===`, or computed over the parsed and re-stringified body.
- No replay window, so a captured valid request can be resent indefinitely.
- Webhook secret hardcoded in the handler (SEC-01).

**Evidence to produce:**
- Handler file with the verifier and the `SOC2:API-11` annotation; test proving a tampered body returns 401.
- Audit log query for `webhook.rejected` events.

## Review checklist

- [ ] API-01: Is every input (body, query, path, headers, files) validated against a strict schema that rejects unknown fields, with bounded strings and arrays, before any business logic or ORM call?
- [ ] API-02: Is all output auto-escaped or encoded for its context, is `Content-Type` explicit, and are redirects and headers never built from raw input?
- [ ] API-03: Do all database, shell, LDAP, and template calls use bound parameters or argument arrays, with identifiers mapped through an allow-list?
- [ ] API-04: Does every public route have a rate limit (shared store, 429 + `Retry-After`) and a body size cap, with server timeouts configured?
- [ ] API-05: Do error responses expose only a code, generic message, and correlation ID, with the correlation ID also in server logs and debug output disabled in all deployed environments?
- [ ] API-06: Are HSTS, CSP, nosniff, and frame protections set; is CORS an explicit origin list (never `*` with credentials); and are cookie-authenticated writes protected by SameSite plus a CSRF token or origin check?
- [ ] API-07: Does the route declare its auth tier, data classification, and owning team in the registered metadata, and does CI fail if any route lacks it?
- [ ] API-08: Does a retryable mutating endpoint accept an `Idempotency-Key` with an atomic claim, and are multi-step writes in one transaction with side effects after commit?
- [ ] API-09: Is the endpoint versioned, is any breaking change in a new version, and are deprecations announced with `Sunset` headers, a changelog entry, and a consumer notice?
- [ ] API-10: Are uploads type-checked by content, size-capped, stored under a server-generated key in a private encrypted bucket, and quarantined until scanned?
- [ ] API-11: Does every inbound webhook verify a signature over the raw body with a constant-time compare, reject stale timestamps, and deduplicate on event ID before processing?
