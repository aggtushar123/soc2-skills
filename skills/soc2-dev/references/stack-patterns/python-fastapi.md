# Python (FastAPI) — SOC 2 patterns

FastAPI's dependency injection system is the natural enforcement point for most of the registry: a `Depends(current_user)` on the router (not the individual route) gives deny-by-default auth, Pydantic v2 models with `extra="forbid"` give API-01 for free on every declared body, and `APIRouter` metadata carries route classification. What FastAPI does not give you is anything about logging, rate limiting, headers, or error shaping; those are middleware you add. Patterns assume FastAPI 0.110+, Pydantic 2.x, `pydantic-settings` 2.x, `slowapi` 0.1.9, `structlog` 24, `argon2-cffi` 23, `PyJWT` 2.8 with `cryptography`, SQLAlchemy 2.0 (async, `asyncpg`), `secure` or hand-rolled header middleware, and `cryptography` 42 for AES-GCM. Django/DRF equivalents are noted inline (`DEFAULT_PERMISSION_CLASSES`, `django-ratelimit`, `SecurityMiddleware`, `django-axes`).

## Detection

- `pyproject.toml` (`[project.dependencies]` or `[tool.poetry.dependencies]`) or `requirements*.txt` contains `fastapi`; `django` + `djangorestframework` for DRF; `starlette` alone is a bare ASGI app.
- Lockfile: `poetry.lock`, `uv.lock`, `pdm.lock`, `requirements.txt` with `==` pins from `pip-compile`. `requirements.txt` with unpinned names is a SEC-03 finding.
- Layout: `app/main.py` or `src/<pkg>/main.py` with `app = FastAPI(...)`; routers in `app/routers/` or `app/api/v1/`; models in `app/models/` (SQLAlchemy) and `app/schemas/` (Pydantic); dependencies in `app/deps.py` or `app/dependencies/`; settings in `app/core/config.py` or `app/settings.py`; migrations in `alembic/`.
- Django: `manage.py`, `settings.py`, per-app `views.py`/`serializers.py`/`models.py`, `urls.py`.
- Entry: `uvicorn app.main:app`, `gunicorn -k uvicorn.workers.UvicornWorker` in a `Procfile`, `Dockerfile`, or `Makefile`.

## Project scaffold for compliance

```
app/
  core/
    config.py               # SEC-01, SEC-02, SEC-06 — pydantic-settings, no secret defaults
    logging.py              # LOG-03, LOG-04, LOG-07 — structlog JSON + redaction processor
    security.py             # AUTH-04, SEC-07 — argon2id, constant-time compare, approved hashes
    crypto.py               # DATA-02, SEC-07 — AES-256-GCM envelope encryption via KMS
  middleware/
    request_id.py           # API-05, LOG-02 — correlation ID
    headers.py              # API-06, DATA-03 — HSTS, CSP, nosniff, frame options
    body_limit.py           # API-04 — Content-Length / streaming cap
  deps/
    auth.py                 # AUTH-01, AUTH-05 — JWT verification, revocation check
    authz.py                # AUTH-02, AUTH-09, DATA-08 — role + ownership dependencies
    rate_limit.py           # API-04, AUTH-06 — slowapi limiter instances
  audit/
    log.py                  # LOG-01, LOG-02 — audit event model + append-only writer
  errors.py                 # API-05, SEC-06 — exception handlers
  routers/
    health.py               # LOG-06
    route_meta.py           # API-07, EVD-01 — typed route metadata
  jobs/
    retention.py            # DATA-04, DATA-05
scripts/
  routes_manifest.py        # API-07, EVD-01 — emits .soc2/routes.json
.soc2/
  CONTROL_MAP.md            # EVD-01
```

## Patterns

### 1. Authentication dependency, deny by default (AUTH-01, AUTH-05)

Put the dependency on the `APIRouter` via `dependencies=[Depends(current_user)]` and mount every router through a single function that requires it. Public routers are a separate, explicitly named list.

```python
# app/deps/auth.py
from dataclasses import dataclass
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from jwt import PyJWKClient
from app.core.config import settings
from app.core.revocation import is_revoked

bearer = HTTPBearer(auto_error=False)
_jwks = PyJWKClient(settings.AUTH_JWKS_URL, cache_keys=True, lifespan=600)

@dataclass(frozen=True)
class Principal:
    id: str
    tenant_id: str
    roles: frozenset[str]
    session_id: str

# SOC2:AUTH-01 — every router except PUBLIC_ROUTERS is mounted with this dependency
async def current_user(request: Request, creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> Principal:
    if creds is None or creds.scheme.lower() != "bearer":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="unauthenticated")
    try:
        key = _jwks.get_signing_key_from_jwt(creds.credentials).key
        # SOC2:AUTH-05 — algorithm pinned, iss/aud/exp/iat all required, 1h max age enforced server-side
        claims = jwt.decode(
            creds.credentials, key, algorithms=["RS256", "ES256"],
            issuer=settings.AUTH_ISSUER, audience=settings.AUTH_AUDIENCE,
            options={"require": ["exp", "iat", "sub", "jti"]}, leeway=30,
        )
        if claims["exp"] - claims["iat"] > 3600:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="unauthenticated")
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="unauthenticated")
    if await is_revoked(claims["jti"]):                       # Redis set, TTL = token lifetime
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="unauthenticated")
    principal = Principal(claims["sub"], claims["tenant_id"], frozenset(claims.get("roles", [])), claims["jti"])
    request.state.user = principal
    return principal

# app/main.py
PUBLIC_ROUTERS = [health.router, auth_router]                   # SOC2:AUTH-01 — the allow-list
PROTECTED_ROUTERS = [invoices.router, users.router, admin.router]
for r in PUBLIC_ROUTERS:
    app.include_router(r)
for r in PROTECTED_ROUTERS:
    app.include_router(r, dependencies=[Depends(current_user)])
```

- `HTTPBearer(auto_error=True)` returns 403 for a missing header. Use `auto_error=False` and raise 401 yourself so the status code is correct and the response shape is uniform.
- `jwt.decode(token, key, algorithms=[...])` with `"none"` or `"HS256"` alongside RS256 lets a public key be used as an HMAC secret. Pin one asymmetric family.
- A router that is `include_router`-ed anywhere other than the two loops above is the bypass. The scanner should assert that every `include_router` call in `main.py` is inside one of the loops.
- Django/DRF: `REST_FRAMEWORK = {"DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"]}` and override with `permission_classes = [AllowAny]` only on the explicit public views.

### 2. Authorization: role + object ownership (AUTH-02, AUTH-09, DATA-08)

```python
# app/deps/authz.py
from collections.abc import Awaitable, Callable
from fastapi import Depends, HTTPException, Path, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.deps.auth import Principal, current_user
from app.deps.db import get_session
from app.models import Invoice

# SOC2:AUTH-09 — roles are distinct strings on the principal; no `is_admin` boolean on User
def require_role(*allowed: str):
    async def _dep(user: Principal = Depends(current_user)) -> Principal:
        if not user.roles.intersection(allowed):
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="forbidden")
        return user
    return _dep

# SOC2:AUTH-02 — object-level check: record is loaded scoped by the token's tenant
# SOC2:DATA-08 — tenant_id comes from Principal, never from path/body/query
def owned_invoice():
    async def _dep(
        invoice_id: str = Path(..., pattern=r"^[0-9a-f-]{36}$"),
        user: Principal = Depends(current_user),
        db: AsyncSession = Depends(get_session),
    ) -> Invoice:
        row = await db.scalar(select(Invoice).where(Invoice.id == invoice_id, Invoice.tenant_id == user.tenant_id))
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="not_found")   # 404, not 403: no enumeration
        if row.owner_id != user.id and "tenant_admin" not in user.roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="forbidden")
        return row
    return _dep

# app/routers/invoices.py
@router.delete("/invoices/{invoice_id}", status_code=204, dependencies=[Depends(require_role("member", "tenant_admin"))])
async def delete_invoice(invoice: Invoice = Depends(owned_invoice()), db: AsyncSession = Depends(get_session)):
    await db.delete(invoice)
    await db.commit()

# app/deps/db.py — Postgres RLS as the backstop for DATA-08
async def get_session(user: Principal = Depends(current_user)):
    async with SessionLocal() as session:
        # SOC2:DATA-08 — RLS policies on tenant tables read current_setting('app.tenant_id')
        await session.execute(text("SET LOCAL app.tenant_id = :t"), {"t": user.tenant_id})
        yield session
```

- Path parameter regexes are cheap IDOR insurance; an `invoice_id` of `../` or a Mongo operator never reaches the query.
- Pydantic body models for updates must not have `tenant_id`, `owner_id`, or `role` fields. If the ORM model has them, use a separate `InvoiceUpdate` schema; never `Invoice(**body.model_dump())`.
- `SET LOCAL` only works inside a transaction; with SQLAlchemy 2.0 `async_sessionmaker` the session begins one implicitly on first execute, so issue the `SET LOCAL` as the first statement.
- DRF: `has_object_permission` on a `BasePermission` plus `get_queryset()` filtered by `request.user.tenant_id`. `queryset = Invoice.objects.all()` as a class attribute is the DATA-08 finding.

### 3. Input validation with Pydantic v2, rejecting unknown fields (API-01)

```python
# app/schemas/base.py
from pydantic import BaseModel, ConfigDict

class StrictModel(BaseModel):
    # SOC2:API-01 — unknown keys are a 422, not silently dropped; no implicit str->int coercion
    model_config = ConfigDict(extra="forbid", strict=True, str_max_length=10_000)

# app/schemas/invoice.py
from decimal import Decimal
from typing import Annotated, Literal
from pydantic import Field, StringConstraints
from app.schemas.base import StrictModel

Uuid = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")]

class InvoiceCreate(StrictModel):
    customer_id: Uuid
    amount_cents: Annotated[int, Field(gt=0, le=10_000_000)]
    currency: Literal["USD", "EUR", "GBP"]
    memo: Annotated[str, StringConstraints(max_length=500)] | None = None
    # tenant_id / owner_id intentionally absent: set from the Principal in the handler

class InvoiceListQuery(StrictModel):
    status: Literal["draft", "sent", "paid"] | None = None
    limit: Annotated[int, Field(ge=1, le=100)] = 25
    cursor: Annotated[str, StringConstraints(max_length=200)] | None = None

# app/routers/invoices.py
from fastapi import Query
from typing import Annotated

@router.post("/invoices", status_code=201, response_model=InvoiceOut)
async def create_invoice(body: InvoiceCreate, user: Principal = Depends(current_user), db: AsyncSession = Depends(get_session)):
    inv = Invoice(**body.model_dump(), tenant_id=user.tenant_id, owner_id=user.id)
    ...

@router.get("/invoices", response_model=list[InvoiceOut])
async def list_invoices(q: Annotated[InvoiceListQuery, Query()], user: Principal = Depends(current_user)):
    ...
```

- Pydantic's default `extra="ignore"` hides mass-assignment probes. Every request model should inherit `StrictModel`; the scanner greps for `BaseModel)` in `app/schemas/` and flags classes without `extra="forbid"`.
- `response_model=` is output validation and output minimization together: it strips fields not on the response schema (e.g. `password_hash`), which is DATA-06 and API-02 in one line. Returning ORM objects without a `response_model` is a finding.
- Query-model support (`Annotated[Model, Query()]`) needs FastAPI 0.115+. On older versions, declare each query param with `Query(..., le=100)` bounds individually.
- Headers count too: `x_idempotency_key: Annotated[str, Header(max_length=64, pattern=...)]`. DRF: `serializer.is_valid(raise_exception=True)` and reject unknown fields by overriding `to_internal_value` or using `drf-extra-fields` strict mixins; DRF ignores unknown keys by default.

### 4. Parameterized data access and the anti-pattern (API-03)

```python
# app/repositories/invoices.py
from sqlalchemy import select, text, func
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import Invoice

# SOC2:API-03 — SQLAlchemy Core/ORM expressions bind every value
async def by_status(db: AsyncSession, tenant_id: str, status: str, limit: int) -> list[Invoice]:
    stmt = select(Invoice).where(Invoice.tenant_id == tenant_id, Invoice.status == status).order_by(Invoice.created_at.desc()).limit(limit)
    return list((await db.scalars(stmt)).all())

# SOC2:API-03 — raw SQL only via text() with named binds
async def search(db: AsyncSession, tenant_id: str, term: str) -> list[dict]:
    stmt = text("SELECT id, number, amount_cents FROM invoices WHERE tenant_id = :tenant AND number ILIKE :term LIMIT 100")
    rows = await db.execute(stmt, {"tenant": tenant_id, "term": f"%{term}%"})
    return [dict(r._mapping) for r in rows]

# sort column from user input: allow-list map, never interpolate
SORTABLE = {"created": Invoice.created_at, "amount": Invoice.amount_cents}
def sorted_query(sort_key: str):
    return select(Invoice).order_by(SORTABLE[sort_key].desc())   # KeyError is fine; validated upstream

# ANTI-PATTERN — flag on sight
# await db.execute(text(f"SELECT * FROM invoices WHERE number = '{term}'"))
# cursor.execute("SELECT * FROM users WHERE email = '%s'" % email)
# cursor.execute("SELECT * FROM users WHERE email = '" + email + "'")
# subprocess.run(f"convert {filename} out.png", shell=True)      -> subprocess.run(["convert", filename, "out.png"])
# os.system("ping " + host)
# Template(user_string).render()  (Jinja SSTI) -> render a file template with the string as a variable
```

- Grep targets: `text(f"`, `text("..." %`, `text("..." +`, `.execute(f"`, `shell=True`, `os.system(`, `os.popen(`, `eval(`, `exec(`, `pickle.loads(` on untrusted data, `yaml.load(` without `SafeLoader`.
- `asyncpg` uses `$1` positional binds; `psycopg` uses `%s`. Both are fine; `.format()` on either is not.
- `Invoice.__table__.c[user_column]` is still injection-adjacent if `user_column` is unvalidated; go through an allow-list dict as shown.
- Enforce TLS on the connection string (`?ssl=require` for asyncpg, `sslmode=verify-full` for psycopg) for DATA-03. Django: `OPTIONS: {"sslmode": "verify-full"}` in `DATABASES`.

### 5. Rate limiting and body size limits (API-04, AUTH-06)

```python
# app/deps/rate_limit.py
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.requests import Request
from app.core.config import settings

def client_key(request: Request) -> str:
    # trust exactly one proxy hop; never take the leftmost X-Forwarded-For blindly
    xff = request.headers.get("x-forwarded-for", "")
    return xff.split(",")[-1].strip() if xff and settings.BEHIND_PROXY else get_remote_address(request)

# SOC2:API-04 — global default on every route, shared store so the limit holds across workers
limiter = Limiter(key_func=client_key, default_limits=["300/minute"], storage_uri=settings.REDIS_URL, headers_enabled=True)

# SOC2:AUTH-06 — credential endpoints keyed by IP + identifier, much tighter
def login_key(request: Request) -> str:
    ident = getattr(request.state, "login_identifier", "")        # set by the handler after parsing body
    return f"{client_key(request)}:{ident.lower()}"

# app/routers/auth.py
@router.post("/auth/login")
@limiter.limit("10/15minutes", key_func=login_key)
async def login(request: Request, body: LoginRequest, db: AsyncSession = Depends(get_session)):
    request.state.login_identifier = body.email
    ...

# app/middleware/body_limit.py
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

class BodyLimitMiddleware(BaseHTTPMiddleware):
    # SOC2:API-04 — reject oversized bodies before they are read; streaming cap for chunked uploads
    def __init__(self, app, max_bytes: int = 100 * 1024):
        super().__init__(app); self.max_bytes = max_bytes
    async def dispatch(self, request, call_next):
        length = request.headers.get("content-length")
        if length and int(length) > self.max_bytes:
            return JSONResponse({"error": "payload_too_large", "correlation_id": request.state.correlation_id}, status_code=413)
        return await call_next(request)

# app/main.py
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(BodyLimitMiddleware, max_bytes=settings.MAX_BODY_BYTES)
```

- `slowapi` without `storage_uri` uses in-process memory; with 4 uvicorn workers the real limit is 4x. Redis storage is mandatory in production.
- The `request: Request` parameter must be present in the signature of any route decorated with `@limiter.limit`, or slowapi raises at import time in some versions and silently no-ops in others.
- `Content-Length` can be omitted with chunked encoding. For upload endpoints, also cap the stream (`async for chunk in request.stream()` with a running total) or rely on the reverse proxy's `client_max_body_size`, and document which layer enforces it.
- Account lockout is separate from rate limiting: increment `failed_login_count` on the user row, require reset after 10, and audit the lockout. Django: `django-axes` handles both; DRF: `throttle_classes` with `ScopedRateThrottle` on the login view.

### 6. Error handlers: generic response + correlation ID (API-05, SEC-06)

```python
# app/middleware/request_id.py
import re, uuid
from starlette.middleware.base import BaseHTTPMiddleware
import structlog

_ID = re.compile(r"^[A-Za-z0-9_-]{8,64}$")

class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        # SOC2:LOG-02 — accept a well-formed upstream ID, else mint one; bind it to the log context
        incoming = request.headers.get("x-request-id", "")
        cid = incoming if _ID.match(incoming) else str(uuid.uuid4())
        request.state.correlation_id = cid
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(correlation_id=cid, path=request.url.path, method=request.method)
        response = await call_next(request)
        response.headers["X-Request-Id"] = cid
        return response

# app/errors.py
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
import structlog

log = structlog.get_logger()

def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(HTTPException)
    async def http_exc(request: Request, exc: HTTPException):
        return JSONResponse({"error": exc.detail, "correlation_id": request.state.correlation_id}, status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def validation_exc(request: Request, exc: RequestValidationError):
        # SOC2:API-05 — location and type only; never echo the offending input value
        issues = [{"loc": ".".join(str(p) for p in e["loc"]), "type": e["type"]} for e in exc.errors()]
        return JSONResponse({"error": "validation_failed", "issues": issues, "correlation_id": request.state.correlation_id}, status_code=422)

    @app.exception_handler(IntegrityError)
    async def integrity_exc(request: Request, exc: IntegrityError):
        log.warning("integrity_error", exc_info=exc)          # constraint name goes to logs, not client
        return JSONResponse({"error": "conflict", "correlation_id": request.state.correlation_id}, status_code=409)

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        log.error("unhandled_exception", exc_info=exc)
        # SOC2:SEC-06 — no traceback, no repr(exc), no internal path in the body, regardless of environment
        return JSONResponse({"error": "internal_error", "correlation_id": request.state.correlation_id}, status_code=500)
```

- `FastAPI(debug=True)` returns Starlette's HTML traceback page for 500s. It must be `debug=False` (the default) in production; the scanner should fail on `debug=True` or `debug=settings.DEBUG` unless `DEBUG` is validated false in prod (pattern 10).
- The default `RequestValidationError` body includes `"input": <the value>`, which reflects the submitted secret or PII back to the client and into any proxy log. Always override it as above.
- The generic `Exception` handler is invoked by `ServerErrorMiddleware` after the response has started in some edge cases; keep it side-effect free apart from logging.
- Django: `DEBUG = False`, custom `handler500`, and DRF's `EXCEPTION_HANDLER` setting to inject the correlation ID from `django-request-id` or `django-structlog`.

### 7. Security headers, CORS allow-list, CSRF (API-06, DATA-03)

```python
# app/middleware/headers.py
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        resp = await call_next(request)
        # SOC2:API-06 — set on every response, including errors and 404s
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"  # API-only; loosen for served HTML
        # SOC2:DATA-03 — HSTS one year with subdomains and preload
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp

# app/main.py
from fastapi.middleware.cors import CORSMiddleware

# SOC2:API-06 — explicit allow-list from settings; never ["*"] with credentials, never allow_origin_regex=".*"
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,                 # ["https://app.example.com"]
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Request-Id", "X-CSRF-Token"],
    max_age=600,
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIdMiddleware)     # added last => runs first

# SOC2:API-06 — CSRF only when sessions ride on cookies (starlette-csrf, double submit)
if settings.SESSION_MODE == "cookie":
    from starlette_csrf import CSRFMiddleware
    app.add_middleware(CSRFMiddleware, secret=settings.CSRF_SECRET, cookie_name="__Host-csrftoken",
                       cookie_secure=True, cookie_samesite="strict", header_name="X-CSRF-Token", safe_methods={"GET", "HEAD", "OPTIONS"})
```

- Starlette middleware runs in reverse order of `add_middleware`. Add `RequestIdMiddleware` last so it wraps everything and the correlation ID exists when an earlier-added middleware fails.
- `allow_origins=["*"]` with `allow_credentials=True` is silently downgraded by Starlette to no credentials, which breaks the app and prompts developers to "fix" it with `allow_origin_regex=".*"`. Both are findings.
- If TLS terminates at a proxy, run uvicorn with `--proxy-headers --forwarded-allow-ips=<proxy CIDR>` so `request.url.scheme` is `https` and secure cookies are set. `--forwarded-allow-ips='*'` is a finding.
- Django: `SecurityMiddleware` with `SECURE_HSTS_SECONDS=31536000`, `SECURE_CONTENT_TYPE_NOSNIFF=True`, `X_FRAME_OPTIONS="DENY"`, `django-cors-headers` with `CORS_ALLOWED_ORIGINS`, and `CsrfViewMiddleware` (on by default; `@csrf_exempt` is the grep target).

### 8. Audit logger: append-only structured events (LOG-01, LOG-02)

```python
# app/audit/log.py
from datetime import datetime, timezone
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field
import structlog
from sqlalchemy import insert
from app.models import AuditLog
from app.core.db import audit_engine       # separate engine, role with INSERT only

AuditAction = Literal[
    "auth.login.success", "auth.login.failure", "auth.mfa.verify", "auth.logout",
    "user.password.change", "user.role.grant", "user.role.revoke", "user.deactivate",
    "data.restricted.read", "data.export", "data.delete", "admin.config.change",
]

class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    actor_id: str
    actor_type: Literal["user", "service", "system"]
    action: AuditAction
    target_type: str
    target_id: str
    outcome: Literal["success", "failure", "denied"]
    ip: str | None
    correlation_id: str
    tenant_id: str | None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))   # SOC2:LOG-07 — tz-aware UTC
    metadata: dict[str, str | int | bool] = Field(default_factory=dict)             # primitives only: LOG-03

_audit_log = structlog.get_logger("audit").bind(stream="audit")

# SOC2:LOG-01 — one entry point for every security-relevant event
async def audit(event: AuditEvent) -> None:
    record = event.model_dump(mode="json")
    # SOC2:LOG-02 — separate stream from app logs (stream=audit) and append-only table
    _audit_log.info("audit", **record)
    async with audit_engine.begin() as conn:
        await conn.execute(insert(AuditLog).values(**record))

# usage: app/routers/auth.py
await audit(AuditEvent(
    actor_id=user.id if user else body.email, actor_type="user",
    action="auth.login.success" if ok else "auth.login.failure",
    target_type="user", target_id=user.id if user else "unknown", outcome="success" if ok else "failure",
    ip=client_key(request), correlation_id=request.state.correlation_id, tenant_id=user.tenant_id if user else None,
))
```

- Append-only is a database grant, not a Python convention: the alembic migration that creates `audit_log` should also `REVOKE UPDATE, DELETE ON audit_log FROM app_rw` and add a trigger raising on UPDATE/DELETE.
- Use a second engine bound to a distinct DB role for the audit table so a compromised app connection cannot rewrite history. It also keeps audit inserts outside the business transaction (a rolled-back request would otherwise erase its own "success" record).
- Emit `outcome="denied"` from `require_role` and `owned_invoice` on 403. Denied authorization attempts are the highest-signal events in the table and are usually missing.
- `metadata` is typed to primitives on purpose. `metadata=body.model_dump()` is how card numbers end up in the audit table.

### 9. Log redaction of secrets and PII (LOG-03, LOG-04)

```python
# app/core/logging.py
import logging, re, sys
import structlog

SENSITIVE_KEYS = re.compile(r"(pass(word)?|secret|token|authorization|cookie|ssn|card|cvv|api[-_]?key|private[-_]?key)", re.I)
PII_KEYS = re.compile(r"^(email|phone|date_of_birth|dob|address|tax_id|national_id)$", re.I)
BEARER = re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{20,}")
CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")

def _redact_value(v):
    if isinstance(v, dict):
        return {k: ("[REDACTED]" if SENSITIVE_KEYS.search(str(k)) else _mask(k, _redact_value(v2))) for k, v2 in v.items()}
    if isinstance(v, (list, tuple)):
        return [_redact_value(x) for x in v]
    if isinstance(v, str):
        return CARD.sub("[CARD]", BEARER.sub("Bearer [REDACTED]", v))
    return v

def _mask(key, value):
    if PII_KEYS.match(str(key)) and isinstance(value, str) and value:
        return value[:2] + "***"                                   # partial mask keeps logs debuggable
    return value

# SOC2:LOG-03 — processor runs on every event before the JSON renderer
def redact_processor(logger, method, event_dict):
    return _redact_value(event_dict)

def configure_logging(level: str, json_output: bool = True) -> None:
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,            # correlation_id, tenant_id from RequestIdMiddleware
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),   # SOC2:LOG-07
            redact_processor,
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer() if json_output else structlog.dev.ConsoleRenderer(),   # SOC2:LOG-04
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level)),
        logger_factory=structlog.PrintLoggerFactory(sys.stdout),
        cache_logger_on_first_use=True,
    )
    # SOC2:LOG-03 — stdlib loggers (uvicorn, sqlalchemy) go through the same pipeline; never echo SQL in prod
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").disabled = True         # replaced by our own access log with no query strings
```

- Key-based redaction is only as good as the keys. `log.info("login", data=str(body))` bypasses it because the value is a string; the rule is "log objects with named keys, never `str()`/`repr()` of a model".
- `create_async_engine(..., echo=True)` prints every statement with bound parameters. It must be `echo=False` outside local dev; the scanner greps `echo=True`.
- uvicorn's access log includes the full query string, which is a DATA-06 leak if anything sensitive is in a URL. Replace it with an access-log middleware that logs `request.url.path` only.
- `print()` bypasses everything. `ruff` rule `T201` (`flake8-print`) as an error is the enforcement.

### 10. Secrets loading with startup validation (SEC-01, SEC-02, SEC-06)

```python
# app/core/config.py
import time, boto3
from typing import Literal
from pydantic import AnyUrl, Field, PostgresDsn, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="forbid", frozen=True)

    ENV: Literal["development", "test", "production"]
    DEBUG: bool = False
    LOG_LEVEL: Literal["ERROR", "WARNING", "INFO", "DEBUG"] = "INFO"
    SERVICE_NAME: str
    BEHIND_PROXY: bool = False
    MAX_BODY_BYTES: int = 100 * 1024
    # SOC2:SEC-01 — no default on any secret; SecretStr so repr()/logging never shows the value
    DATABASE_URL: PostgresDsn
    REDIS_URL: AnyUrl
    AUTH_JWKS_URL: AnyUrl
    AUTH_ISSUER: str
    AUTH_AUDIENCE: str
    CSRF_SECRET: SecretStr = Field(min_length=32)
    FIELD_ENCRYPTION_KEY_ID: str            # KMS key id or alias, never key bytes
    CORS_ORIGINS: list[str] = []
    SESSION_MODE: Literal["bearer", "cookie"] = "bearer"

    @field_validator("DATABASE_URL")
    @classmethod
    def _require_tls(cls, v: PostgresDsn) -> PostgresDsn:
        if v.host not in ("localhost", "127.0.0.1") and "ssl" not in (v.query or ""):
            raise ValueError("DATABASE_URL must require TLS (?ssl=require / sslmode=verify-full)")   # SOC2:DATA-03
        return v

    @model_validator(mode="after")
    def _prod_guards(self):
        # SOC2:SEC-06 — production cannot boot with debug on, debug logging, or a wildcard origin
        if self.ENV == "production":
            if self.DEBUG: raise ValueError("DEBUG must be false in production")
            if self.LOG_LEVEL == "DEBUG": raise ValueError("LOG_LEVEL=DEBUG not allowed in production")
            if any(o == "*" for o in self.CORS_ORIGINS): raise ValueError("wildcard CORS origin not allowed")
        return self

try:
    settings = Settings()          # raises ValidationError listing variable NAMES only
except Exception as e:             # noqa: BLE001
    raise SystemExit(f"invalid configuration: {e}") from None

# SOC2:SEC-02 — rotating secrets are fetched with a TTL, not frozen at import
_cache: dict[str, tuple[str, float]] = {}
def get_secret(name: str, ttl: float = 300) -> str:
    if name in _cache and _cache[name][1] > time.monotonic():
        return _cache[name][0]
    value = boto3.client("secretsmanager").get_secret_value(SecretId=name)["SecretString"]
    _cache[name] = (value, time.monotonic() + ttl)
    return value
```

- `os.environ.get("SECRET_KEY", "dev")` is the Python spelling of the most common SEC-01/SEC-06 finding. Grep `os\.environ\.get\(\s*["'][A-Z_]*(SECRET|KEY|PASSWORD|TOKEN)[A-Z_]*["']\s*,`. Django's generated `settings.py` ships with a hard-coded `SECRET_KEY`; it must be replaced with `os.environ["DJANGO_SECRET_KEY"]`.
- `env_file=".env"` is for local dev. `.env` must be in `.gitignore`; `.env.example` with placeholder values is committed.
- `SecretStr` protects against accidental `logger.info(settings)`; use `.get_secret_value()` at the single point of use.
- Nothing outside `config.py` reads `os.environ`. A stray `os.getenv` in a router is where undocumented, unrotated secrets live.

### 11. Password hashing and approved crypto helpers (AUTH-04, SEC-07)

```python
# app/core/security.py
import hashlib, hmac, secrets
import httpx
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from fastapi import HTTPException

# SOC2:AUTH-04 — argon2id with OWASP parameters (19 MiB, t=2, p=1)
_ph = PasswordHasher(time_cost=2, memory_cost=19_456, parallelism=1, hash_len=32, salt_len=16)   # type defaults to argon2id

async def hash_password(plain: str) -> str:
    if not 12 <= len(plain) <= 256:
        raise HTTPException(400, "password_policy")
    if await is_breached(plain):
        raise HTTPException(400, "password_breached")
    return _ph.hash(plain)

def verify_password(stored_hash: str, plain: str) -> bool:
    try:
        return _ph.verify(stored_hash, plain)
    except (VerifyMismatchError, InvalidHashError):
        return False

def needs_rehash(stored_hash: str) -> bool:
    return _ph.check_needs_rehash(stored_hash)          # migrate legacy bcrypt / weaker params on next login

# SOC2:AUTH-04 — HIBP k-anonymity: only 5 hex chars of SHA-1 leave the process (SHA-1 is the HIBP protocol, not storage)
async def is_breached(plain: str) -> bool:
    digest = hashlib.sha1(plain.encode()).hexdigest().upper()
    async with httpx.AsyncClient(timeout=3.0) as client:
        r = await client.get(f"https://api.pwnedpasswords.com/range/{digest[:5]}", headers={"Add-Padding": "true"})
    if r.status_code != 200:
        return False                                     # fail open on HIBP outage; log it
    return any(line.split(":")[0] == digest[5:] for line in r.text.splitlines())

# SOC2:SEC-07 — approved primitives only
def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)                  # never random.random() / uuid1

def safe_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())    # webhook signatures, API keys, reset tokens
```

- `passlib` with `bcrypt` is acceptable at `rounds=12+`, but passlib is unmaintained and breaks with bcrypt 4.1+; prefer `argon2-cffi` directly.
- Django: `PASSWORD_HASHERS = ["django.contrib.auth.hashers.Argon2PasswordHasher", ...]` first, plus `django-pwned-passwords` or a custom validator in `AUTH_PASSWORD_VALIDATORS` with `MinimumLengthValidator` at 12.
- SEC-07 grep targets: `hashlib.md5(`, `hashlib.sha1(` (outside HIBP), `Crypto.Cipher.DES`, `ARC4`, `AES.MODE_ECB`, `AES.MODE_CBC` without an HMAC, `random.` for anything security-relevant, `ssl._create_unverified_context`, `verify=False` on requests/httpx.
- Reset and verification tokens are stored hashed (`sha256_hex`) and compared with `safe_equal`; a plaintext token column is a DATA-02 finding.

### 12. Field-level encryption for a restricted column (DATA-02)

```python
# app/core/crypto.py
import base64, os
import boto3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.core.config import settings

_kms = boto3.client("kms")
_KEY_ID = settings.FIELD_ENCRYPTION_KEY_ID

# Envelope: KMS wraps a fresh 256-bit data key per value; AES-256-GCM encrypts; AAD binds to table/column/row.
# Stored: "v1.<b64 wrapped>.<b64 nonce>.<b64 ct||tag>"
# SOC2:DATA-02 SOC2:SEC-07 — AES-256-GCM, KMS-managed key, authenticated with AAD
def encrypt_field(plain: str, *, table: str, column: str, record_id: str) -> str:
    dk = _kms.generate_data_key(KeyId=_KEY_ID, KeySpec="AES_256")
    nonce = os.urandom(12)
    aad = f"{table}.{column}.{record_id}".encode()
    ct = AESGCM(dk["Plaintext"]).encrypt(nonce, plain.encode(), aad)
    b64 = lambda b: base64.b64encode(b).decode()
    return ".".join(["v1", b64(dk["CiphertextBlob"]), b64(nonce), b64(ct)])

def decrypt_field(stored: str, *, table: str, column: str, record_id: str) -> str:
    version, wrapped, nonce, ct = stored.split(".")
    if version != "v1":
        raise ValueError("unknown ciphertext version")
    key = _kms.decrypt(CiphertextBlob=base64.b64decode(wrapped), KeyId=_KEY_ID)["Plaintext"]
    aad = f"{table}.{column}.{record_id}".encode()
    return AESGCM(key).decrypt(base64.b64decode(nonce), base64.b64decode(ct), aad).decode()

# app/models/user.py — SQLAlchemy TypeDecorator keeps handlers away from the raw column
from sqlalchemy import String, TypeDecorator
from sqlalchemy.orm import Mapped, mapped_column

class EncryptedRestricted(TypeDecorator):
    impl = String; cache_ok = True
    def __init__(self, table: str, column: str): super().__init__(); self.table, self.column = table, column
    # record_id binding requires an event hook; shown simplified with a per-column AAD
    def process_bind_param(self, value, dialect):
        return None if value is None else encrypt_field(value, table=self.table, column=self.column, record_id="")
    def process_result_value(self, value, dialect):
        return None if value is None else decrypt_field(value, table=self.table, column=self.column, record_id="")

class User(Base):
    # SOC2:DATA-01 — classification=restricted pii=true purpose="tax reporting" retention=7y
    tax_id: Mapped[str | None] = mapped_column(EncryptedRestricted("users", "tax_id"))
    tax_id_bidx: Mapped[str | None] = mapped_column(String(64), index=True)   # HMAC blind index for equality lookups
```

- Automatic decryption on read via `TypeDecorator` is convenient but makes "access to restricted data is audited" (LOG-01) hard. Prefer loading with `defer(User.tax_id)` by default and an explicit repository method that decrypts and audits.
- Blind index = `hmac.new(index_key, normalize(value).encode(), "sha256").hexdigest()`; store it in a separate column so equality queries work without decrypting the table.
- Rotation (SEC-02): change the KMS alias target, then a background job re-wraps `wrapped` for every row; the data key itself is not touched, so the job is fast.
- Django: `django-fernet-fields` uses Fernet (AES-128-CBC + HMAC), which is approved-adjacent but not AES-256-GCM; prefer `django-encrypted-model-fields` with a custom AES-GCM backend or the same `cryptography` code above in a custom `Field`.

### 13. Retention/purge job skeleton (DATA-04, DATA-05)

```python
# app/jobs/retention.py
import asyncio, uuid
from datetime import datetime, timedelta, timezone
from sqlalchemy import delete, select
import structlog
from app.core.config import settings
from app.core.db import job_engine, JobSession        # separate role with DELETE grants; API role has none
from app.models import Session, PasswordResetToken, User, UserPreference, ApiKey
from app.audit.log import audit, AuditEvent
from app.core.cache import redis
from app.core.search import search_client

log = structlog.get_logger("retention")

# SOC2:DATA-04 — every retention period in one config-driven table (days)
RETENTION_DAYS = {
    "audit_log": settings.RETENTION_AUDIT_DAYS,      # >= 365 (LOG-04)
    "sessions": 30,
    "password_reset_tokens": 1,
    "deleted_users_grace": 30,
    "invoices_archived": 7 * 365,
}

def cutoff(days: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)

async def run_retention(correlation_id: str) -> None:
    async with JobSession() as db:
        n_sessions = (await db.execute(delete(Session).where(Session.last_seen_at < cutoff(RETENTION_DAYS["sessions"])))).rowcount
        n_resets = (await db.execute(delete(PasswordResetToken).where(PasswordResetToken.created_at < cutoff(RETENTION_DAYS["password_reset_tokens"])))).rowcount
        await db.commit()

        # SOC2:DATA-05 — subject erasure after grace: cascade to derived rows, cache, search index; audit each
        users = (await db.scalars(select(User).where(User.deleted_at < cutoff(RETENTION_DAYS["deleted_users_grace"])).limit(500))).all()
        for u in users:
            async with db.begin_nested():
                await db.execute(delete(UserPreference).where(UserPreference.user_id == u.id))
                await db.execute(delete(ApiKey).where(ApiKey.user_id == u.id))
                await db.delete(u)                               # FK ON DELETE CASCADE covers the rest
            await db.commit()
            await redis.delete(f"user:{u.id}")
            await search_client.delete(index="users", id=u.id)
            await audit(AuditEvent(actor_id="retention-job", actor_type="system", action="data.delete", target_type="user", target_id=u.id,
                                   outcome="success", ip=None, correlation_id=correlation_id, tenant_id=u.tenant_id))

    log.info("retention_complete", sessions=n_sessions, resets=n_resets, users=len(users))

if __name__ == "__main__":       # run by a K8s CronJob / Celery beat / ECS scheduled task, not inside the API process
    asyncio.run(run_retention(str(uuid.uuid4())))
```

- The job uses its own DB role. If it shares the API's engine, DELETE privileges are live on every request path.
- Bound each batch (`limit(500)`, `rowcount` logged) so a large backlog cannot hold locks for minutes; run more often rather than bigger.
- Backup snapshots are not touched here; DATA-05 needs the backup retention window documented so erased data is known to age out of backups on a schedule.
- Celery/APScheduler inside the web process is tempting but couples the job's lifecycle and privileges to the API. Django: a management command (`manage.py purge_expired`) scheduled externally.

### 14. Health/readiness endpoints (LOG-06)

```python
# app/routers/health.py
import asyncio
from fastapi import APIRouter, Response
from sqlalchemy import text
from app.core.db import engine
from app.core.cache import redis

router = APIRouter(tags=["health"])   # in PUBLIC_ROUTERS: no auth, excluded from rate limit and access log noise

# SOC2:LOG-06 — liveness: process is up; no dependency checks
@router.get("/healthz", include_in_schema=False)
async def healthz():
    return {"status": "ok"}

# SOC2:LOG-06 — readiness: dependencies reachable with a hard timeout; 503 pulls the pod from the LB
@router.get("/readyz", include_in_schema=False)
async def readyz(response: Response):
    async def db_check():
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    async def redis_check():
        await redis.ping()

    results = await asyncio.gather(
        asyncio.wait_for(db_check(), timeout=1.5),
        asyncio.wait_for(redis_check(), timeout=1.0),
        return_exceptions=True,
    )
    checks = {"database": "ok" if not isinstance(results[0], BaseException) else "fail",
              "redis": "ok" if not isinstance(results[1], BaseException) else "fail"}
    ready = all(v == "ok" for v in checks.values())
    response.status_code = 200 if ready else 503
    return {"status": "ready" if ready else "degraded", "checks": checks}
```

- Return status strings only. Exception text, hostnames, versions, and connection strings in the body are a finding.
- Without `wait_for` a stalled pool hangs the probe; Kubernetes then treats a hung pod as healthy until its own timeout, which is usually longer.
- Keep `include_in_schema=False` so the probes stay out of the OpenAPI document and the routes manifest's auth checks (they are still listed as public in `PUBLIC_ROUTERS`).
- LOG-06 also requires SLO monitoring; point the uptime checker at `/readyz` and export p95 latency from the ASGI metrics middleware (`prometheus-fastapi-instrumentator`).

### 15. Route metadata and routes manifest (API-07, EVD-01)

```python
# app/routers/route_meta.py
from dataclasses import dataclass, asdict
from typing import Literal
from fastapi import APIRouter

Classification = Literal["public", "internal", "confidential", "restricted"]

@dataclass(frozen=True)
class RouteMeta:
    auth: Literal["public", "user", "tenant_admin", "platform_admin", "service"]
    classification: Classification
    owner: str                          # "@payments-team"
    pii: bool = False

class MetaRouter(APIRouter):
    """APIRouter that refuses routes without metadata."""
    # SOC2:API-07 — meta is a required keyword on every route decorator
    def api_route(self, path, *, meta: RouteMeta, **kwargs):
        if not isinstance(meta, RouteMeta):
            raise TypeError(f"route {path} is missing RouteMeta")
        kwargs.setdefault("openapi_extra", {})["x-soc2"] = asdict(meta)
        return super().api_route(path, **kwargs)

# app/routers/invoices.py
router = MetaRouter(prefix="/v1", tags=["invoices"])

@router.delete("/invoices/{invoice_id}", status_code=204,
               meta=RouteMeta(auth="user", classification="confidential", owner="@payments-team", pii=True),
               dependencies=[Depends(require_role("member", "tenant_admin"))])
async def delete_invoice(invoice: Invoice = Depends(owned_invoice()), db: AsyncSession = Depends(get_session)):
    ...

# scripts/routes_manifest.py — CI regenerates and diffs against .soc2/routes.json
# SOC2:EVD-01 — the manifest is the auditor-facing evidence for API-07
import json, sys
from datetime import datetime, timezone
from fastapi.routing import APIRoute
from app.main import app
from app.routers.health import router as health_router
public_paths = {r.path for r in health_router.routes}
missing, manifest = [], []
for route in app.routes:
    if not isinstance(route, APIRoute):
        continue
    meta = (route.openapi_extra or {}).get("x-soc2")
    if meta is None and route.path not in public_paths:
        missing.append(f"{sorted(route.methods)} {route.path}")
        continue
    manifest.append({"methods": sorted(route.methods), "path": route.path, **(meta or {"auth": "public", "classification": "public", "owner": "@platform"})})
if missing:
    print("routes without RouteMeta:", *missing, sep="\n  "); sys.exit(1)
json.dump({"generated_at": datetime.now(timezone.utc).isoformat(), "routes": manifest}, open(".soc2/routes.json", "w"), indent=2)
```

- Enforcement lives in `MetaRouter`; a plain `APIRouter` anywhere in `app/routers/` is the bypass, so the scanner greps `APIRouter(` outside `route_meta.py`.
- The manifest is evidence only if CI runs the script and fails on `git diff --exit-code .soc2/routes.json`.
- `x-soc2` in `openapi_extra` also surfaces in the OpenAPI document, which is a convenient second artifact for auditors; strip it in the public docs build if the owner handles are sensitive.
- DRF: a `soc2_meta` class attribute on each `APIView`/`ViewSet` and a management command that walks `get_resolver().url_patterns` to build the same manifest.

## CI additions for this stack

| Job | Tool | Requirement |
|-----|------|-------------|
| `test` | `pytest` with `pytest-cov`; `--strict-markers` | CHG-02 |
| `lint-type` | `ruff check` (rules `S` = bandit, `T20` = no print, `B`), `mypy --strict` | CHG-02, LOG-03 |
| `sast` | Semgrep (`p/python`, `p/fastapi`, `p/owasp-top-ten`, `p/jwt`) or CodeQL `python`; `bandit -ll` as a second opinion | SEC-04 |
| `sca` | `pip-audit -r requirements.txt --strict` (or `pip-audit` against `uv.lock`/`poetry export`) | SEC-03 |
| `secrets` | gitleaks (full history on `main`, diff on PRs) | SEC-01 |
| `routes-manifest` | `python scripts/routes_manifest.py && git diff --exit-code .soc2/` | API-07, EVD-01 |
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
      - uses: actions/setup-python@v5
        with: { python-version: "3.12", cache: pip }
      - run: pip install --require-hashes -r requirements.txt -r requirements-dev.txt   # lockfile with hashes
      - run: ruff check . && mypy app
      - run: pytest --cov=app --cov-fail-under=80
  sca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install pip-audit && pip-audit -r requirements.txt --strict --desc   # SOC2:SEC-03
  sast:
    runs-on: ubuntu-latest
    container: returntocorp/semgrep
    steps:
      - uses: actions/checkout@v4
      - run: semgrep ci --config p/python --config p/fastapi --config p/owasp-top-ten --config p/jwt   # SOC2:SEC-04
  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: gitleaks/gitleaks-action@v2        # SOC2:SEC-01
        env: { GITHUB_TOKEN: "${{ secrets.GITHUB_TOKEN }}" }
```

Branch protection must list `test`, `sca`, `sast`, and `secrets` as required status checks (CHG-01, CHG-02).

## Known pitfalls in this stack

- **Router included outside the protected loop.** `app.include_router(admin.router)` in a feature module or a plugin path skips `dependencies=[Depends(current_user)]` entirely. FastAPI gives no warning.
- **`extra="ignore"` (Pydantic default).** `{"role": "admin"}` in a signup body is silently dropped, and nobody notices the probe. `StrictModel` with `extra="forbid"` on every request schema.
- **Validation errors echo `input`.** FastAPI's default 422 body includes the submitted value. Passwords and card numbers end up in browser dev tools, proxy logs, and error trackers. Override `RequestValidationError`.
- **`os.environ.get("SECRET", "dev-secret")` and Django's generated `SECRET_KEY`.** A working default credential in the repo is a SEC-01 and SEC-06 finding at once.
- **`echo=True` on the engine, `DEBUG` log level, or uvicorn access logs with query strings.** All three put bound parameters or URL-borne data into shipped logs (LOG-03, DATA-06).
- **Stateless JWT with long expiry and no `jti` revocation.** Deactivating a user (AUTH-07) has no effect until the token expires. Cap at 1 h and check revocation.
- **`allow_origin_regex=".*"` to "fix" CORS with credentials.** Any origin can make authenticated requests; with cookie sessions and no CSRF middleware it is a full CSRF primitive.
- **`FastAPI(debug=True)` or `--reload` in the production image.** Debug returns HTML tracebacks with source lines; `--reload` watches the filesystem and is a sign the same Dockerfile serves dev and prod.
