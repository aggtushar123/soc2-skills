# Go (net/http with chi or gin) — SOC 2 patterns

Go's `net/http` gives you a router and nothing else, so every registry control is a piece of middleware or a small package you write and wire deliberately. That is an advantage for audits: the enforcement points are explicit functions in `internal/middleware/`, and the middleware chain in `main.go` is the single place a reviewer reads to confirm order. Patterns assume Go 1.22+ (method-pattern `ServeMux` and `slog` in stdlib), `github.com/go-chi/chi/v5` (gin equivalents noted), `github.com/go-playground/validator/v10`, `log/slog` (zap equivalents noted), `golang.org/x/crypto/argon2`, `github.com/golang-jwt/jwt/v5`, `github.com/jackc/pgx/v5` (with `sqlc` for generated queries), `golang.org/x/time/rate` with a Redis-backed store for multi-instance, `github.com/go-chi/cors`, and `github.com/aws/aws-sdk-go-v2/service/kms` for envelope keys.

## Detection

- `go.mod` at the root; `require` lines with `github.com/go-chi/chi/v5`, `github.com/gin-gonic/gin`, `github.com/labstack/echo/v4`, `github.com/gofiber/fiber/v2`, or just stdlib `net/http`.
- `go.sum` present (SEC-03); `vendor/` optional. Absence of `go.sum` is a finding.
- Layout: `cmd/<service>/main.go` entry; `internal/handlers/` or `internal/api/` for routes; `internal/middleware/`; `internal/store/` or `internal/db/` with `sqlc` output (`*.sql.go`, `sqlc.yaml`); models in `internal/model/` or `internal/domain/`; config in `internal/config/`; migrations in `migrations/` or `db/migrations/` (goose/migrate/atlas).
- Router construction is greppable: `chi.NewRouter()`, `gin.Default()` / `gin.New()`, `http.NewServeMux()`. Handlers are `func(w http.ResponseWriter, r *http.Request)` or gin `func(c *gin.Context)`.
- `gin.Default()` installs its own logger and recovery middleware; note it when auditing (its access log includes the query string).

## Project scaffold for compliance

```
cmd/api/main.go                     # API-04, API-06 — server timeouts, middleware order
internal/
  config/config.go                  # SEC-01, SEC-02, SEC-06 — env parsing with required secrets
  middleware/
    requestid.go                    # API-05, LOG-02 — correlation ID
    auth.go                         # AUTH-01, AUTH-05 — deny-by-default JWT, public allow-list
    authz.go                        # AUTH-02, AUTH-09, DATA-08 — role + ownership
    ratelimit.go                    # API-04, AUTH-06 — token buckets, login limiter
    bodylimit.go                    # API-04 — http.MaxBytesReader
    headers.go                      # API-06, DATA-03 — HSTS/CSP/nosniff, CORS
    recover.go                      # API-05, SEC-06 — panic → generic 500 with correlation ID
  httpx/
    errors.go                       # API-05 — typed errors, generic JSON writer
    validate.go                     # API-01 — strict JSON decode + validator
    routemeta.go                    # API-07, EVD-01 — route registration with metadata
  audit/audit.go                    # LOG-01, LOG-02 — append-only structured events
  logging/
    logger.go                       # LOG-04, LOG-07 — slog JSON handler
    redact.go                       # LOG-03 — ReplaceAttr + value redaction
  crypto/
    password.go                     # AUTH-04 — argon2id + HIBP
    aead.go                         # DATA-02, SEC-07 — AES-256-GCM envelope encryption
  store/                            # API-03, DATA-08 — sqlc queries with tenant_id params
  jobs/retention.go                 # DATA-04, DATA-05
  handlers/health.go                # LOG-06
cmd/routes-manifest/main.go         # API-07, EVD-01 — emits .soc2/routes.json
.soc2/CONTROL_MAP.md                # EVD-01
```

## Patterns

### 1. Authentication middleware, deny by default (AUTH-01, AUTH-05)

```go
// internal/middleware/auth.go  (imports: context, net/http, strings, time, golang-jwt/jwt/v5, MicahParks/keyfunc/v3)
package middleware

type Principal struct {
	ID, TenantID, SessionID string
	Roles                   map[string]struct{}
}

type ctxKey int

const principalKey ctxKey = 0

func PrincipalFrom(ctx context.Context) (Principal, bool) { p, ok := ctx.Value(principalKey).(Principal); return p, ok }

// SOC2:AUTH-01 — the complete list of routes reachable without a verified token
var publicRoutes = map[string]struct{}{
	"GET /healthz": {}, "GET /readyz": {},
	"POST /v1/auth/login": {}, "POST /v1/auth/refresh": {},
}

type Revoker interface{ IsRevoked(ctx context.Context, jti string) (bool, error) }

func RequireAuth(jwks keyfunc.Keyfunc, issuer, audience string, rev Revoker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := publicRoutes[r.Method+" "+r.URL.Path]; ok {
				next.ServeHTTP(w, r); return
			}
			raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok || raw == "" {
				writeError(w, r, http.StatusUnauthorized, "unauthenticated"); return
			}
			// SOC2:AUTH-05 — algorithm family pinned; iss, aud, exp, iat required; 1h ceiling enforced here
			tok, err := jwt.ParseWithClaims(raw, &appClaims{}, jwks.Keyfunc,
				jwt.WithValidMethods([]string{"RS256", "ES256"}), jwt.WithIssuer(issuer), jwt.WithAudience(audience),
				jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(30*time.Second))
			ac, _ := tok.Claims.(*appClaims)
			if err != nil || !tok.Valid || ac.ExpiresAt.Sub(ac.IssuedAt.Time) > time.Hour {
				writeError(w, r, http.StatusUnauthorized, "unauthenticated"); return
			}
			if revoked, rerr := rev.IsRevoked(r.Context(), ac.ID); rerr != nil || revoked {
				writeError(w, r, http.StatusUnauthorized, "unauthenticated"); return
			}
			p := Principal{ID: ac.Subject, TenantID: ac.TenantID, SessionID: ac.ID, Roles: toSet(ac.Roles)}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey, p)))
		})
	}
}
```

- `r.Use(RequireAuth(...))` must be on the top-level router before any `r.Mount`/`r.Route`. A sub-router built with `chi.NewRouter()` and mounted before the `Use` line has no auth; chi panics if you `Use` after routes are registered, which helps, but only for the same router.
- Match on `r.URL.Path` only for the allow-list; if you need pattern routes public (`/v1/public/{slug}`), register them on a separate router that is mounted without the middleware and list that mount prefix in the manifest.
- `jwt.ParseWithClaims` without `WithValidMethods` accepts whatever `alg` the token claims, including `none` on older versions. Always pin.
- gin: `router.Use(RequireAuth())` before any `router.Group`; gin groups inherit parent middleware, so the same ordering rule applies.

### 2. Authorization: role + object ownership (AUTH-02, AUTH-09, DATA-08)

```go
// internal/middleware/authz.go
package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
)

// SOC2:AUTH-09 — admin capabilities are distinct roles; no `is_admin bool` on the user row
func RequireRole(allowed ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := PrincipalFrom(r.Context())
			if !ok { writeError(w, r, http.StatusUnauthorized, "unauthenticated"); return }
			for _, role := range allowed {
				if _, has := p.Roles[role]; has { next.ServeHTTP(w, r); return }
			}
			writeError(w, r, http.StatusForbidden, "forbidden")
		})
	}
}

type Owned interface{ OwnerID() string }

// SOC2:AUTH-02 — object-level check; the loader is scoped by tenant, never by client-supplied tenant
// SOC2:DATA-08 — tenant ID is taken from the verified principal only
func RequireOwnership[T Owned](param string, load func(ctx context.Context, id, tenantID string) (T, error)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, _ := PrincipalFrom(r.Context())
			rec, err := load(r.Context(), chi.URLParam(r, param), p.TenantID)
			if errors.Is(err, pgx.ErrNoRows) { writeError(w, r, http.StatusNotFound, "not_found"); return } // 404: no cross-tenant enumeration
			if err != nil { writeError(w, r, http.StatusInternalServerError, "internal_error"); return }
			if _, admin := p.Roles["tenant_admin"]; rec.OwnerID() != p.ID && !admin {
				writeError(w, r, http.StatusForbidden, "forbidden"); return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), recordKey, rec)))
		})
	}
}

// wiring — sqlc-generated GetInvoice takes (id, tenant_id) as parameters
r.With(RequireRole("member", "tenant_admin"),
	RequireOwnership("id", func(ctx context.Context, id, tenant string) (store.Invoice, error) {
		return q.GetInvoice(ctx, store.GetInvoiceParams{ID: id, TenantID: tenant})
	})).Delete("/invoices/{id}", h.DeleteInvoice)
```

- Write every sqlc query with `tenant_id = $N` in the WHERE clause; `sqlc vet` with a custom rule (or a grep in CI for `FROM invoices` without `tenant_id`) catches omissions.
- Postgres RLS is the backstop: `SET LOCAL app.tenant_id = $1` at the start of each transaction via a `pgxpool.Config.BeforeAcquire`/`AfterConnect` hook, then policies on every tenant table. Raw SQL cannot bypass it.
- Never decode `tenant_id`, `owner_id`, or `role` from the request body into the struct that becomes the write. Use separate request DTOs (pattern 3).
- gin: same logic with `c.Param("id")`, `c.Set("principal", p)` / `c.MustGet`, and `c.AbortWithStatusJSON`.

### 3. Input validation with strict decoding + validator (API-01)

```go
// internal/httpx/validate.go  (imports: encoding/json, errors, io, net/http, strings, go-playground/validator/v10)
package httpx

var validate = validator.New(validator.WithRequiredStructEnabled())

// SOC2:API-01 — DisallowUnknownFields rejects mass-assignment probes; single JSON value only; then struct tags
func DecodeJSON[T any](w http.ResponseWriter, r *http.Request, maxBytes int64) (T, bool) {
	var v T
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		WriteError(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type"); return v, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) { WriteError(w, r, http.StatusRequestEntityTooLarge, "payload_too_large"); return v, false }
		WriteError(w, r, http.StatusBadRequest, "malformed_json"); return v, false
	}
	if dec.More() || dec.Decode(&struct{}{}) != io.EOF {
		WriteError(w, r, http.StatusBadRequest, "malformed_json"); return v, false
	}
	if err := validate.Struct(v); err != nil {
		WriteValidationError(w, r, err); return v, false   // field names + tags only, never values
	}
	return v, true
}

// internal/handlers/invoices.go
type CreateInvoiceRequest struct {
	CustomerID string `json:"customer_id" validate:"required,uuid4"`
	AmountCents int64 `json:"amount_cents" validate:"required,gt=0,lte=10000000"`
	Currency   string `json:"currency" validate:"required,oneof=USD EUR GBP"`
	Memo       string `json:"memo" validate:"omitempty,max=500"`
	// TenantID / OwnerID deliberately absent: set from the principal
}

type ListInvoicesQuery struct {
	Status string `validate:"omitempty,oneof=draft sent paid"`
	Limit  int    `validate:"gte=1,lte=100"`
}

func (h *Handlers) CreateInvoice(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[CreateInvoiceRequest](w, r, 64<<10)
	if !ok { return }
	p, _ := middleware.PrincipalFrom(r.Context())
	_ = p // ... q.CreateInvoice(ctx, store.CreateInvoiceParams{TenantID: p.TenantID, OwnerID: p.ID, ...})
}
```

- `json.Unmarshal(body, &v)` silently ignores unknown fields; only `Decoder.DisallowUnknownFields()` rejects them. The scanner greps `json.Unmarshal(` in handlers as a likely finding.
- Path params (`chi.URLParam`) and query params are strings with no validation; run them through `validate.Var(id, "uuid4")` or a typed query struct as above before they reach the store.
- gin's `ShouldBindJSON` uses `json.Unmarshal` semantics (unknown fields ignored). Set `gin.EnableJsonDecoderDisallowUnknownFields()` at startup, and `binding:"required,..."` tags map to the same validator.
- Headers you rely on (`X-Idempotency-Key`, `X-Tenant-Hint`) need length and charset checks too; anything you copy into a log or a query is input.

### 4. Parameterized data access and the anti-pattern (API-03)

```go
// internal/store/query.sql  (sqlc input)
-- name: GetInvoice :one
-- SOC2:API-03 SOC2:DATA-08 — generated code binds $1/$2; tenant_id is a mandatory parameter
SELECT id, tenant_id, owner_id, number, amount_cents FROM invoices WHERE id = $1 AND tenant_id = $2;

-- name: SearchInvoices :many
SELECT id, number, amount_cents FROM invoices
WHERE tenant_id = $1 AND number ILIKE '%' || $2 || '%' ORDER BY created_at DESC LIMIT 100;

// internal/store/invoices.go — hand-written pgx for anything sqlc cannot express
package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SOC2:API-03 — values are always positional parameters; identifiers come from an allow-list
var sortable = map[string]string{"created": "created_at", "amount": "amount_cents"}

func (s *Store) ListSorted(ctx context.Context, tenantID, sortKey string, limit int32) ([]Invoice, error) {
	col, ok := sortable[sortKey]
	if !ok { return nil, fmt.Errorf("invalid sort key") }
	// column name is from our map, never from the caller; values are $1/$2
	sql := fmt.Sprintf("SELECT id, number, amount_cents FROM invoices WHERE tenant_id = $1 ORDER BY %s DESC LIMIT $2", col)
	rows, err := s.pool.Query(ctx, sql, tenantID, limit)
	if err != nil { return nil, err }
	defer rows.Close()
	return pgx.CollectRows(rows, pgx.RowToStructByName[Invoice])
}

// ANTI-PATTERN — flag on sight
// s.pool.Query(ctx, "SELECT * FROM invoices WHERE number = '"+term+"'")
// s.pool.Query(ctx, fmt.Sprintf("SELECT * FROM users WHERE email = '%s'", email))
// exec.Command("sh", "-c", "convert "+filename)   -> exec.Command("convert", filename, "out.png")
// template.HTML(userInput)                          -> let html/template escape it
```

- Grep targets: `fmt.Sprintf(` whose result is passed to `Query`/`Exec`/`QueryRow` with a `%s` that is not from an allow-list map; string concatenation with `+` inside those calls; `exec.Command("sh", "-c"`, `exec.Command("bash"`; `template.HTML(`, `template.JS(` on request data; `text/template` used for HTML output.
- `database/sql` with `lib/pq` uses the same `$1` binds; `?` is MySQL syntax. Both are fine; `Sprintf` into either is not.
- `pgxpool` connection string must carry `sslmode=verify-full` (DATA-03); `sslmode=disable` outside `localhost` is a finding. The `pgx` default is `prefer`, which silently falls back to plaintext.
- `sqlc` also removes the temptation to build SQL dynamically, and its generated parameter structs make missing `tenant_id` a compile error when you add it to the query.

### 5. Rate limiting and body size limits (API-04, AUTH-06)

```go
// internal/middleware/ratelimit.go  (imports: net, net/http, strings, sync, time, golang.org/x/time/rate)
package middleware

type limiterStore struct { mu sync.Mutex; m map[string]*entry; r rate.Limit; b int }
type entry struct { lim *rate.Limiter; seen time.Time }

func newStore(perMinute, burst int) *limiterStore {
	s := &limiterStore{m: map[string]*entry{}, r: rate.Every(time.Minute / time.Duration(perMinute)), b: burst}
	go s.gc() // evicts entries not seen for 10 minutes
	return s
}
func (s *limiterStore) get(key string) *rate.Limiter {
	s.mu.Lock(); defer s.mu.Unlock()
	e, ok := s.m[key]
	if !ok { e = &entry{lim: rate.NewLimiter(s.r, s.b)}; s.m[key] = e }
	e.seen = time.Now()
	return e.lim
}

// clientIP trusts X-Forwarded-For only when the direct peer is a known proxy, and takes the LAST hop
func clientIP(r *http.Request, trustedProxies []*net.IPNet) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	peer := net.ParseIP(host)
	for _, cidr := range trustedProxies {
		if xff := r.Header.Get("X-Forwarded-For"); cidr.Contains(peer) && xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	return host
}

// SOC2:API-04 — global per-IP limit on every route (use a Redis-backed limiter when running >1 replica)
func RateLimit(store *limiterStore, keyFn func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !store.get(keyFn(r)).Allow() {
				w.Header().Set("Retry-After", "60")
				writeError(w, r, http.StatusTooManyRequests, "rate_limited"); return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SOC2:AUTH-06 — login/reset/MFA: 10 per 15 min keyed by ip+identifier; the handler also tracks per-account lockout
var loginStore = newStore(10/15, 10)

// internal/middleware/bodylimit.go
// SOC2:API-04 — cap every body before any handler reads it; multipart handlers set a larger explicit cap
func BodyLimit(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > maxBytes { writeError(w, r, http.StatusRequestEntityTooLarge, "payload_too_large"); return }
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes); next.ServeHTTP(w, r)
		})
	}
}
```

- `x/time/rate` is in-process. With more than one replica the effective limit multiplies; use `go-redis/redis_rate` or the same algorithm backed by Redis `INCR`/`EXPIRE`, keyed identically.
- Taking the first `X-Forwarded-For` entry, or trusting the header from any peer, lets clients choose their own bucket. Take the last hop added by your trusted proxy.
- `http.Server` timeouts are part of API-04: `ReadHeaderTimeout: 5s`, `ReadTimeout: 15s`, `WriteTimeout: 30s`, `IdleTimeout: 60s`, `MaxHeaderBytes: 1<<20`. The zero values are unlimited and a slowloris finding.
- gin: `github.com/ulule/limiter/v3` with gin middleware, and `router.MaxMultipartMemory` for uploads; `c.Request.Body = http.MaxBytesReader(...)` in a middleware for JSON.

### 6. Recover + error writer: generic response, correlation ID (API-05, SEC-06)

```go
// internal/middleware/requestid.go  (imports: context, crypto/rand, encoding/hex, net/http, regexp)
package middleware

var idRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
const requestIDKey ctxKey = 1

func RequestIDFrom(ctx context.Context) string { s, _ := ctx.Value(requestIDKey).(string); return s }

// SOC2:LOG-02 — accept a well-formed upstream ID, otherwise mint 128 bits of randomness
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if !idRe.MatchString(id) { b := make([]byte, 16); _, _ = rand.Read(b); id = hex.EncodeToString(b) }
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}

// internal/httpx/errors.go  (imports: encoding/json, log/slog, net/http, runtime/debug)
package httpx

type errBody struct {
	Error         string `json:"error"`
	CorrelationID string `json:"correlation_id"`
}

// SOC2:API-05 — the only way a handler writes an error; body is a code + correlation ID, nothing else
func WriteError(w http.ResponseWriter, r *http.Request, status int, code string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")   // API-02: explicit content type
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errBody{Error: code, CorrelationID: middleware.RequestIDFrom(r.Context())})
}

// SOC2:SEC-06 — panics never reach the client as text; stack goes to the log under the correlation ID
func Recover(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					if rec == http.ErrAbortHandler { panic(rec) }
					log.ErrorContext(r.Context(), "panic", "correlation_id", middleware.RequestIDFrom(r.Context()),
						"panic", rec, "stack", string(debug.Stack()), "path", r.URL.Path)
					WriteError(w, r, http.StatusInternalServerError, "internal_error")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
```

- `http.Error(w, err.Error(), 500)` is the Go spelling of a stack trace in the response: pgx errors include table and constraint names, `os.PathError` includes the path. Grep `http.Error(w, err.Error()` and `fmt.Fprintf(w, ..., err)`.
- `pgx.ErrNoRows`, unique-violation (`pgconn.PgError.Code == "23505"`), and context deadline errors need explicit mapping to 404/409/504 in the handler; the fallback for any other `error` is `internal_error`.
- Log the wrapped error chain (`%+v` or `errors.Unwrap` loop) server-side; that is where the detail belongs, keyed by `correlation_id`.
- gin: `gin.New()` plus `gin.CustomRecovery(handler)`; do not use `gin.Default()`'s recovery, which writes nothing but also logs to stdout in non-JSON.

### 7. Security headers, CORS allow-list, CSRF (API-06, DATA-03)

```go
// internal/middleware/headers.go
package middleware

import (
	"net/http"

	"github.com/go-chi/cors"
)

// SOC2:API-06 — set on every response, including errors, before the handler runs
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'") // API-only; loosen for HTML
		// SOC2:DATA-03 — HSTS one year, subdomains, preload
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// SOC2:API-06 — explicit origins from config; never "*" with credentials; AllowOriginFunc must not return true blindly
func CORS(allowed []string) func(http.Handler) http.Handler {
	return cors.Handler(cors.Options{
		AllowedOrigins:   allowed, // e.g. []string{"https://app.example.com"}
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "X-Request-Id", "X-CSRF-Token"},
		AllowCredentials: true,
		MaxAge:           600,
	})
}

// cmd/api/main.go — cookie sessions only; Bearer APIs skip CSRF
// SOC2:API-06 — double-submit CSRF via the maintained fork; __Host- prefix requires Secure + Path=/ + no Domain
if cfg.SessionMode == "cookie" {
	csrf := gorilla.Protect(cfg.CSRFKey, gorilla.Secure(true), gorilla.HttpOnly(true),
		gorilla.SameSite(gorilla.SameSiteStrictMode), gorilla.CookieName("__Host-csrf"), gorilla.Path("/"),
		gorilla.RequestHeader("X-CSRF-Token"), gorilla.ErrorHandler(http.HandlerFunc(csrfFail)))
	r.Use(csrf)
}

// TLS on the listener when not behind a terminating LB (DATA-03)
srv := &http.Server{Addr: ":8443", Handler: r, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
```

- `AllowedOrigins: []string{"*"}` with `AllowCredentials: true` is refused by browsers, and developers then reach for `AllowOriginFunc: func(r, o) bool { return true }`, which is worse. Both are findings.
- Behind a TLS-terminating LB, the Go server sees plaintext; HSTS is still correct to set (the browser sees HTTPS) but `Secure` cookies require checking `X-Forwarded-Proto` from a trusted peer, not blindly.
- `gorilla/csrf` was archived and revived; pin a maintained version (`github.com/gorilla/csrf` ≥ 1.7.2 fixes the origin-check bypass) or use `SameSite=Strict` plus a custom-header check.
- gin: `github.com/gin-contrib/cors` with `AllowOrigins` (never `AllowAllOrigins: true` with credentials) and `gin-contrib/secure` for the headers.

### 8. Audit logger: append-only structured events (LOG-01, LOG-02)

```go
// internal/audit/audit.go  (imports: context, log/slog, time, jackc/pgx/v5/pgxpool)
package audit

type Action string

const (
	LoginSuccess   Action = "auth.login.success"
	LoginFailure   Action = "auth.login.failure"
	MFAVerify      Action = "auth.mfa.verify"
	PasswordChange Action = "user.password.change"
	RoleGrant      Action = "user.role.grant"
	RoleRevoke     Action = "user.role.revoke"
	UserDeactivate Action = "user.deactivate"
	RestrictedRead Action = "data.restricted.read"
	DataExport     Action = "data.export"
	DataDelete     Action = "data.delete"
	ConfigChange   Action = "admin.config.change"
)

type Event struct {
	ActorID, ActorType string            // user | service | system
	Action             Action
	TargetType, TargetID string
	Outcome            string            // success | failure | denied
	IP                 string
	CorrelationID      string
	TenantID           string            // "" for platform-level events
	Metadata           map[string]string // primitives only — LOG-03
}

type Logger struct {
	pool *pgxpool.Pool // SOC2:LOG-02 — separate pool, role has INSERT on audit_log and nothing else
	log  *slog.Logger  // separate slog handler tagged stream=audit
}

func New(pool *pgxpool.Pool, base *slog.Logger) *Logger {
	return &Logger{pool: pool, log: base.With("stream", "audit")}
}

// SOC2:LOG-01 — single entry point; every security-relevant event goes through here
func (l *Logger) Write(ctx context.Context, e Event) error {
	ts := time.Now().UTC() // SOC2:LOG-07
	l.log.InfoContext(ctx, "audit", "actor", e.ActorID, "actor_type", e.ActorType, "action", string(e.Action),
		"target_type", e.TargetType, "target_id", e.TargetID, "outcome", e.Outcome, "ip", e.IP,
		"correlation_id", e.CorrelationID, "tenant_id", e.TenantID, "timestamp", ts.Format(time.RFC3339Nano), "metadata", e.Metadata)
	// SOC2:LOG-02 — append-only table: migration REVOKEs UPDATE/DELETE from the app role and adds a raising trigger
	_, err := l.pool.Exec(ctx, `INSERT INTO audit_log
		(actor_id, actor_type, action, target_type, target_id, outcome, ip, correlation_id, tenant_id, ts, metadata)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,''),$10,$11)`,
		e.ActorID, e.ActorType, e.Action, e.TargetType, e.TargetID, e.Outcome, e.IP, e.CorrelationID, e.TenantID, ts, e.Metadata)
	return err
}
```

- Use `context.WithoutCancel(ctx)` (Go 1.21+) for the insert so a client disconnect mid-request does not cancel the audit write for an action that already happened.
- Emit from `RequireRole`/`RequireOwnership` with `Outcome: "denied"`; denied authorization is the most useful signal and the most commonly missing one.
- Do not run the insert inside the business transaction; a rollback would erase a "success" entry. Write after `Commit()`, or in the error branch for failures.
- `Metadata` is `map[string]string` by design. Passing a decoded request struct is how card numbers land in the audit table.

### 9. Log redaction of secrets and PII (LOG-03, LOG-04)

```go
// internal/logging/logger.go  (imports: log/slog, os, regexp, time)
package logging

var (
	sensitiveKey = regexp.MustCompile(`(?i)(pass(word)?|secret|token|authorization|cookie|ssn|card|cvv|api[-_]?key|private[-_]?key)`)
	piiKey       = regexp.MustCompile(`(?i)^(email|phone|date_of_birth|dob|address|tax_id|national_id)$`)
	bearerRe     = regexp.MustCompile(`Bearer\s+[A-Za-z0-9._~+/=-]{20,}`)
	cardRe       = regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`)
)

// SOC2:LOG-03 — ReplaceAttr runs on every attribute before the JSON handler serializes it
func redact(groups []string, a slog.Attr) slog.Attr {
	key := a.Key
	switch {
	case sensitiveKey.MatchString(key):
		return slog.String(key, "[REDACTED]")
	case piiKey.MatchString(key):
		if s := a.Value.String(); len(s) > 2 { return slog.String(key, s[:2]+"***") }
		return slog.String(key, "***")
	case a.Value.Kind() == slog.KindString:
		s := bearerRe.ReplaceAllString(a.Value.String(), "Bearer [REDACTED]")
		return slog.String(key, cardRe.ReplaceAllString(s, "[CARD]"))
	case key == slog.TimeKey:
		return slog.String(key, a.Value.Time().UTC().Format(time.RFC3339Nano)) // SOC2:LOG-07
	}
	return a
}

// SOC2:LOG-04 — JSON to stdout, shipped by the platform; level from config, never Debug in prod
func New(service, env string, level slog.Level) *slog.Logger {
	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level, ReplaceAttr: redact})
	return slog.New(h).With("service", service, "env", env)
}

// internal/middleware/accesslog.go — path only, never the query string (DATA-06); correlation ID always
func AccessLog(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := &statusWriter{ResponseWriter: w, status: 200}
			next.ServeHTTP(ww, r)
			p, _ := PrincipalFrom(r.Context())
			log.InfoContext(r.Context(), "request", "correlation_id", RequestIDFrom(r.Context()), "method", r.Method,
				"path", r.URL.Path, "status", ww.status, "duration_ms", time.Since(start).Milliseconds(),
				"user_id", p.ID, "tenant_id", p.TenantID, "ip", clientIP(r, trustedProxies))
		})
	}
}
```

- `ReplaceAttr` sees attributes, not groups' inner structs marshalled via `slog.Any(...)`; a struct logged with `slog.Any("user", u)` is serialized by `encoding/json` and bypasses key matching. Implement `slog.LogValuer` on domain types (`func (u User) LogValue() slog.Value`) to control what is emitted.
- `fmt.Println`, `log.Printf`, and `chi/middleware.Logger` all bypass the handler. Route the stdlib logger through slog (`slog.SetDefault`) and forbid `fmt.Print*` in non-`main` packages via `forbidigo` in `golangci-lint`.
- zap: the equivalent is a custom `zapcore.Core` wrapper or `zap.Hooks`; simpler is to keep a `RedactedString` type with a `MarshalLogObject` that masks.
- `pgx` tracelog at `LogLevelDebug` prints bound arguments. Use `LogLevelWarn` in production.

### 10. Secrets loading with startup validation (SEC-01, SEC-02, SEC-06)

```go
// internal/config/config.go  (imports: errors, fmt, net/url, os, strings, sync, time)
package config

type Config struct {
	Env, ServiceName, LogLevel string
	Port                       string
	DatabaseURL, RedisURL      string
	AuthJWKSURL, AuthIssuer, AuthAudience string
	CSRFKey                    []byte
	FieldKeyID                 string // KMS key id/alias, never key bytes
	CORSOrigins                []string
	SessionMode                string
	Debug                      bool
}

// SOC2:SEC-01 — required() has no default path; a missing secret is a fatal boot error listing the NAME only
func required(name string, errs *[]error) string {
	v, ok := os.LookupEnv(name)
	if !ok || v == "" { *errs = append(*errs, fmt.Errorf("%s is required", name)) }
	return v
}

func Load() (Config, error) {
	var errs []error
	c := Config{
		Env: required("APP_ENV", &errs), ServiceName: required("SERVICE_NAME", &errs),
		LogLevel: envOr("LOG_LEVEL", "info"), Port: envOr("PORT", "8080"),
		DatabaseURL: required("DATABASE_URL", &errs), RedisURL: required("REDIS_URL", &errs),
		AuthJWKSURL: required("AUTH_JWKS_URL", &errs), AuthIssuer: required("AUTH_ISSUER", &errs), AuthAudience: required("AUTH_AUDIENCE", &errs),
		CSRFKey: []byte(required("CSRF_KEY", &errs)), FieldKeyID: required("FIELD_ENCRYPTION_KEY_ID", &errs),
		CORSOrigins: split(os.Getenv("CORS_ORIGINS")), SessionMode: envOr("SESSION_MODE", "bearer"),
		Debug: os.Getenv("DEBUG") == "true",
	}
	if len(c.CSRFKey) < 32 { errs = append(errs, errors.New("CSRF_KEY must be at least 32 bytes")) }
	if u, err := url.Parse(c.DatabaseURL); err == nil && u.Hostname() != "localhost" && !strings.Contains(u.RawQuery, "sslmode=verify-full") {
		errs = append(errs, errors.New("DATABASE_URL must use sslmode=verify-full")) // SOC2:DATA-03
	}
	// SOC2:SEC-06 — production refuses to boot with debug on, debug logging, or wildcard CORS
	if c.Env == "production" {
		if c.Debug { errs = append(errs, errors.New("DEBUG must be false in production")) }
		if c.LogLevel == "debug" { errs = append(errs, errors.New("LOG_LEVEL=debug not allowed in production")) }
		for _, o := range c.CORSOrigins { if o == "*" { errs = append(errs, errors.New("wildcard CORS origin not allowed")) } }
	}
	return c, errors.Join(errs...)
}

// SOC2:SEC-02 — rotating secrets are fetched through a TTL cache, not frozen at boot
type SecretSource interface{ Get(name string) (string, error) }
type cached struct { src SecretSource; ttl time.Duration; mu sync.Mutex; m map[string]struct{ v string; exp time.Time } }
func (c *cached) Get(name string) (string, error) {
	c.mu.Lock(); defer c.mu.Unlock()
	if e, ok := c.m[name]; ok && time.Now().Before(e.exp) { return e.v, nil }
	v, err := c.src.Get(name); if err != nil { return "", err }
	c.m[name] = struct{ v string; exp time.Time }{v, time.Now().Add(c.ttl)}
	return v, nil
}
```

- `envOr("JWT_SECRET", "dev")` is the Go spelling of the most common SEC-01/SEC-06 finding. `envOr` must never be called with a secret name; the scanner greps `envOr\("[A-Z_]*(SECRET|KEY|PASSWORD|TOKEN)`.
- `os.Getenv` anywhere outside `internal/config` is a finding; scattered reads defeat startup validation and hide undocumented secrets.
- `main()` must `log.Fatal` (or `os.Exit(1)`) on `Load()` error before opening any listener; a server that starts and then 500s on every request hides the misconfiguration.
- Ship secrets via the platform (K8s Secret → env, ECS `secrets`, Vault agent). `ENV`/`ARG` in the Dockerfile and `-ldflags -X` baked secrets are both image-layer leaks.

### 11. Password hashing and approved crypto helpers (AUTH-04, SEC-07)

```go
// internal/crypto/password.go  (imports: crypto/rand, crypto/sha1, crypto/sha256, crypto/subtle, encoding/base64, encoding/hex, errors, fmt, strings, golang.org/x/crypto/argon2)
package crypto

// SOC2:AUTH-04 — argon2id with OWASP parameters (19 MiB, t=2, p=1), 16-byte salt, 32-byte key
const (
	argonTime = 2; argonMemory = 19 * 1024; argonThreads = 1; argonKeyLen = 32; saltLen = 16
)

func HashPassword(plain string) (string, error) {
	if l := len(plain); l < 12 || l > 256 { return "", errors.New("password_policy") }
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil { return "", err }
	key := argon2.IDKey([]byte(plain), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func VerifyPassword(encoded, plain string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" { return false }
	var m, t uint32; var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil { return false }
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil { return false }
	got := argon2.IDKey([]byte(plain), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1 // SOC2:SEC-07 — constant-time compare
}

func NeedsRehash(encoded string) bool { return !strings.HasPrefix(encoded, fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$", argonMemory, argonTime, argonThreads)) }

// SOC2:AUTH-04 — HIBP k-anonymity; SHA-1 here is the HIBP protocol, not storage (only 5 hex chars sent)
func HIBPPrefixSuffix(plain string) (prefix, suffix string) {
	sum := sha1.Sum([]byte(plain))
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	return h[:5], h[5:]
}

// SOC2:SEC-07 — approved helpers: SHA-256 for integrity, crypto/rand for tokens, constant-time compare for secrets
func SHA256Hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func NewToken(n int) (string, error) { b := make([]byte, n); if _, err := rand.Read(b); err != nil { return "", err }; return base64.RawURLEncoding.EncodeToString(b), nil }
func SafeEqual(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
```

- `golang.org/x/crypto/bcrypt` at `cost >= 12` is also acceptable; `bcrypt.DefaultCost` (10) is a finding, and bcrypt truncates at 72 bytes.
- Grep targets for SEC-07: `crypto/md5`, `crypto/sha1` (outside HIBP), `crypto/des`, `crypto/rc4`, `cipher.NewCBCEncrypter` without an HMAC, `math/rand` for anything security-relevant, `InsecureSkipVerify: true`, `tls.VersionTLS10/11` as `MinVersion`.
- Reset/verification tokens are stored as `SHA256Hex(token)` and compared with `SafeEqual`; plaintext token columns are a DATA-02 finding.
- Never include the password in the error returned to the caller or in an audit `Metadata` map, even on policy failure.

### 12. Field-level encryption for a restricted column (DATA-02)

```go
// internal/crypto/aead.go  (imports: context, crypto/aes, crypto/cipher, crypto/rand, encoding/base64, errors, fmt, strings, aws-sdk-go-v2/service/kms, .../kms/types)
package crypto

type FieldCipher struct { kms *kms.Client; keyID string }

func NewFieldCipher(k *kms.Client, keyID string) *FieldCipher { return &FieldCipher{kms: k, keyID: keyID} }

// Envelope: KMS wraps a fresh 256-bit data key per value; AES-256-GCM seals the value with AAD = table.column.id
// Stored: "v1.<b64 wrapped>.<b64 nonce>.<b64 ct||tag>"
// SOC2:DATA-02 SOC2:SEC-07 — AES-256-GCM under a KMS-managed key, authenticated with record-binding AAD
func (f *FieldCipher) Encrypt(ctx context.Context, plain string, table, column, recordID string) (string, error) {
	dk, err := f.kms.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{KeyId: &f.keyID, KeySpec: types.DataKeySpecAes256})
	if err != nil { return "", err }
	defer zero(dk.Plaintext)
	block, err := aes.NewCipher(dk.Plaintext); if err != nil { return "", err }
	gcm, err := cipher.NewGCM(block);          if err != nil { return "", err }
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil { return "", err }
	ct := gcm.Seal(nil, nonce, []byte(plain), []byte(table+"."+column+"."+recordID))
	e := base64.RawStdEncoding.EncodeToString
	return "v1." + e(dk.CiphertextBlob) + "." + e(nonce) + "." + e(ct), nil
}

func (f *FieldCipher) Decrypt(ctx context.Context, stored, table, column, recordID string) (string, error) {
	parts := strings.Split(stored, ".")
	if len(parts) != 4 || parts[0] != "v1" { return "", errors.New("unknown ciphertext version") }
	d := base64.RawStdEncoding.DecodeString
	wrapped, e1 := d(parts[1]); nonce, e2 := d(parts[2]); ct, e3 := d(parts[3])
	if err := errors.Join(e1, e2, e3); err != nil { return "", err }
	out, err := f.kms.Decrypt(ctx, &kms.DecryptInput{CiphertextBlob: wrapped, KeyId: &f.keyID})
	if err != nil { return "", err }
	defer zero(out.Plaintext)
	block, _ := aes.NewCipher(out.Plaintext)
	gcm, _ := cipher.NewGCM(block)
	plain, err := gcm.Open(nil, nonce, ct, []byte(table+"."+column+"."+recordID))
	if err != nil { return "", fmt.Errorf("decrypt: %w", err) }
	return string(plain), nil
}

func zero(b []byte) { for i := range b { b[i] = 0 } }

// internal/store/users.go — repository owns encryption; handlers never see the ciphertext column
// SOC2:DATA-01 — users.tax_id: classification=restricted pii=true purpose="tax reporting" retention=7y
func (s *Store) SetTaxID(ctx context.Context, userID, taxID string) error {
	ct, err := s.fc.Encrypt(ctx, taxID, "users", "tax_id", userID); if err != nil { return err }
	bidx := hmacHex(s.indexKey, normalize(taxID))            // blind index for equality lookups
	_, err = s.pool.Exec(ctx, `UPDATE users SET tax_id = $1, tax_id_bidx = $2 WHERE id = $3`, ct, bidx, userID)
	return err
}
```

- Keep decryption in a named repository method (`GetTaxID`) that also emits `audit.RestrictedRead`; scanning all rows with decryption in a loop is exactly what LOG-01's "access to restricted data" is meant to catch.
- `sqlc` will type the column as `string`/`pgtype.Text`; the ciphertext prefix `v1.` makes accidental plaintext writes visible in a data-quality check (`WHERE tax_id NOT LIKE 'v1.%'`).
- Rotation (SEC-02): point the KMS alias at a new key, then a job re-wraps only `parts[1]` per row; no data key or ciphertext changes.
- `github.com/aws/aws-sdk-go-v2` calls per row are slow; cache data keys per (table, column) for a bounded window if throughput matters, but never share one nonce.

### 13. Retention/purge job skeleton (DATA-04, DATA-05)

```go
// internal/jobs/retention.go  (imports: context, log/slog, time, jackc/pgx/v5, jackc/pgx/v5/pgxpool)
package jobs

// SOC2:DATA-04 — retention periods in one config-driven table (days); audit >= 365 (LOG-04)
type Retention struct {
	AuditLogDays, SessionsDays, ResetTokenDays, DeletedUserGraceDays, ArchivedInvoiceDays int
}

type Purger struct {
	pool   *pgxpool.Pool   // SOC2:DATA-05 — job-only role with DELETE; the API role has none
	cache  interface{ Del(ctx context.Context, keys ...string) error }
	search interface{ Delete(ctx context.Context, index, id string) error }
	audit  *audit.Logger
	log    *slog.Logger
	cfg    Retention
}

func cutoff(days int) time.Time { return time.Now().UTC().AddDate(0, 0, -days) }

func (p *Purger) Run(ctx context.Context, correlationID string) error {
	n1, err := p.pool.Exec(ctx, `DELETE FROM sessions WHERE last_seen_at < $1`, cutoff(p.cfg.SessionsDays)); if err != nil { return err }
	n2, err := p.pool.Exec(ctx, `DELETE FROM password_reset_tokens WHERE created_at < $1`, cutoff(p.cfg.ResetTokenDays)); if err != nil { return err }

	// SOC2:DATA-05 — subject erasure past grace: cascade to derived rows, cache, search index; one audit entry per subject
	rows, err := p.pool.Query(ctx, `SELECT id, tenant_id FROM users WHERE deleted_at < $1 LIMIT 500`, cutoff(p.cfg.DeletedUserGraceDays))
	if err != nil { return err }
	users, err := pgx.CollectRows(rows, pgx.RowToStructByName[struct{ ID, TenantID string }]); if err != nil { return err }
	for _, u := range users {
		tx, err := p.pool.Begin(ctx); if err != nil { return err }
		_, _ = tx.Exec(ctx, `DELETE FROM user_preferences WHERE user_id = $1`, u.ID)
		_, _ = tx.Exec(ctx, `DELETE FROM api_keys WHERE user_id = $1`, u.ID)
		if _, err := tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, u.ID); err != nil { _ = tx.Rollback(ctx); return err } // FKs ON DELETE CASCADE
		if err := tx.Commit(ctx); err != nil { return err }
		_ = p.cache.Del(ctx, "user:"+u.ID)
		_ = p.search.Delete(ctx, "users", u.ID)
		_ = p.audit.Write(ctx, audit.Event{ActorID: "retention-job", ActorType: "system", Action: audit.DataDelete,
			TargetType: "user", TargetID: u.ID, Outcome: "success", CorrelationID: correlationID, TenantID: u.TenantID})
	}
	p.log.InfoContext(ctx, "retention_complete", "sessions", n1.RowsAffected(), "resets", n2.RowsAffected(), "users", len(users))
	return nil
}

// cmd/retention/main.go — separate binary run by a CronJob; never a goroutine ticker inside the API process
```

- A separate binary with its own DB role keeps DELETE grants off the request path and gives the job its own IAM identity and log stream.
- Bound each pass (`LIMIT 500`) and log counts, never row contents; run frequently rather than in large sweeps that hold locks.
- Backups are outside this job. DATA-05 also needs the snapshot retention window documented so erased subjects are known to age out of backups.
- Every erasure must produce an audit event; a purge without an audit trail is indistinguishable from an attacker's DELETE.

### 14. Health/readiness endpoints (LOG-06)

```go
// internal/handlers/health.go
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type Health struct { pool *pgxpool.Pool; rdb *redis.Client }

// SOC2:LOG-06 — liveness: process is up; no dependency checks; listed in publicRoutes
func (h *Health) Live(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// SOC2:LOG-06 — readiness: each dependency probed with its own timeout; 503 pulls the pod from the LB
func (h *Health) Ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	checks := map[string]string{}
	if err := h.pool.Ping(ctx); err != nil { checks["database"] = "fail" } else { checks["database"] = "ok" }
	if err := h.rdb.Ping(ctx).Err(); err != nil { checks["redis"] = "fail" } else { checks["redis"] = "ok" }
	status := http.StatusOK
	state := "ready"
	for _, v := range checks { if v != "ok" { status, state = http.StatusServiceUnavailable, "degraded" } }
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": state, "checks": checks})
}
```

- Return "ok"/"fail" only. `err.Error()` from pgx includes the host and the SQLSTATE; from redis it includes the address. Both belong in the log, not the body.
- `pool.Ping` acquires a connection; if the pool is exhausted the probe hangs until `ctx` expires, which is why the timeout is mandatory.
- Exclude both endpoints from the rate limiter and (optionally) sample them out of the access log, but keep `RequestID` on them.
- The other half of LOG-06 is monitoring: expose `/metrics` (Prometheus) on a separate internal listener, and alert on p95 latency and error rate against the documented SLO.

### 15. Route metadata and routes manifest (API-07, EVD-01)

```go
// internal/httpx/routemeta.go  (imports: net/http, go-chi/chi/v5)
package httpx

type Auth string
type Classification string

const (
	AuthPublic Auth = "public"; AuthUser Auth = "user"; AuthTenantAdmin Auth = "tenant_admin"; AuthPlatformAdmin Auth = "platform_admin"; AuthService Auth = "service"
	ClassPublic Classification = "public"; ClassInternal Classification = "internal"; ClassConfidential Classification = "confidential"; ClassRestricted Classification = "restricted"
)

type RouteMeta struct {
	Method, Pattern string
	Auth            Auth           `json:"auth"`
	Classification  Classification `json:"classification"`
	Owner           string         `json:"owner"` // "@payments-team"
	PII             bool           `json:"pii"`
}

// Registry is populated at registration time and read by cmd/routes-manifest
var Registry []RouteMeta

// SOC2:API-07 — the only route-registration helper; meta is a required argument, and auth-level middleware is derived from it
func Route(r chi.Router, method, pattern string, m RouteMeta, h http.HandlerFunc, extra ...func(http.Handler) http.Handler) {
	if m.Owner == "" || m.Classification == "" || m.Auth == "" { panic("route " + method + " " + pattern + " is missing metadata") }
	m.Method, m.Pattern = method, pattern
	Registry = append(Registry, m)
	mw := append([]func(http.Handler) http.Handler{}, extra...)
	if m.Auth != AuthPublic { mw = append([]func(http.Handler) http.Handler{middleware.RequireRole(rolesFor(m.Auth)...)}, mw...) }
	r.With(mw...).Method(method, pattern, h)
}

// usage — internal/handlers/routes.go
httpx.Route(r, http.MethodDelete, "/v1/invoices/{id}",
	httpx.RouteMeta{Auth: httpx.AuthUser, Classification: httpx.ClassConfidential, Owner: "@payments-team", PII: true},
	h.DeleteInvoice, middleware.RequireOwnership("id", loadInvoice))

// cmd/routes-manifest/main.go — CI runs this and fails on `git diff --exit-code .soc2/routes.json`
// SOC2:EVD-01 — cross-checks chi.Walk against the Registry so a route registered outside httpx.Route fails the build
func main() {
	r := api.NewRouter(api.TestDeps()) // builds the router without listening
	declared := map[string]bool{}
	for _, m := range httpx.Registry { declared[m.Method+" "+m.Pattern] = true }
	var undeclared []string
	_ = chi.Walk(r, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if !declared[method+" "+route] && !publicProbe(route) { undeclared = append(undeclared, method+" "+route) }
		return nil
	})
	if len(undeclared) > 0 { fmt.Fprintln(os.Stderr, "routes without metadata:", undeclared); os.Exit(1) }
	out, _ := json.MarshalIndent(map[string]any{"generated_at": time.Now().UTC().Format(time.RFC3339), "routes": httpx.Registry}, "", "  ")
	_ = os.WriteFile(".soc2/routes.json", out, 0o644)
}
```

- `chi.Walk` enumerates every registered route, so a `r.Get(...)` that bypassed `httpx.Route` fails the manifest build; that cross-check is the enforcement, not the helper alone.
- Keep the router constructor free of side effects (no `Listen`, no DB connect) so the manifest binary can build it with stub dependencies.
- gin: `router.Routes()` returns `[]gin.RouteInfo`; keep the same `Registry` and cross-check by `Method + Path`.
- `.soc2/CONTROL_MAP.md` lists `cmd/routes-manifest` as the generator and `.soc2/routes.json` as the evidence artifact for API-07.

## CI additions for this stack

| Job | Tool | Requirement |
|-----|------|-------------|
| `test` | `go test -race -cover ./...`; `go vet ./...` | CHG-02 |
| `lint` | `golangci-lint` with `gosec`, `errcheck`, `forbidigo` (`fmt.Print*`, `http.Error(w, err.Error()`), `bodyclose` | CHG-02, SEC-04, LOG-03 |
| `sast` | `gosec ./...` (or via golangci-lint) plus Semgrep `p/golang`, `p/owasp-top-ten`; CodeQL `go` for deeper dataflow | SEC-04 |
| `sca` | `govulncheck ./...` (call-graph aware, stdlib included) | SEC-03 |
| `secrets` | gitleaks (full history on `main`, diff on PRs) | SEC-01 |
| `routes-manifest` | `go run ./cmd/routes-manifest && git diff --exit-code .soc2/` | API-07, EVD-01 |
| `container` | Trivy on the built image (distroless/static base, non-root) | SEC-05 |

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
      - uses: actions/setup-go@v5
        with: { go-version-file: go.mod, cache: true }
      - run: go mod verify                          # go.sum integrity (SEC-03)
      - run: go vet ./... && go test -race -cover ./...
  lint-sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version-file: go.mod }
      - uses: golangci/golangci-lint-action@v6
        with: { version: v1.60, args: --enable=gosec,errcheck,forbidigo,bodyclose }   # SOC2:SEC-04
      - uses: securego/gosec@master
        with: { args: -severity high -confidence medium ./... }
  sca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version-file: go.mod }
      - run: go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./...   # SOC2:SEC-03
  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: gitleaks/gitleaks-action@v2        # SOC2:SEC-01
        env: { GITHUB_TOKEN: "${{ secrets.GITHUB_TOKEN }}" }
```

Branch protection must list `test`, `lint-sast`, `sca`, and `secrets` as required status checks (CHG-01, CHG-02).

## Known pitfalls in this stack

- **Sub-router mounted before `r.Use(RequireAuth)`.** chi panics on `Use` after routes on the same router, but a child router built separately and mounted early inherits nothing. Read `main.go` top to bottom.
- **`http.Error(w, err.Error(), 500)`.** pgx, `os`, and `net` errors carry table names, paths, and hosts. This is the Go equivalent of a stack trace in the response body (API-05).
- **`json.Unmarshal` in handlers.** Unknown fields are silently ignored; `{"role":"admin"}` in a signup body vanishes and nobody sees the probe. `Decoder.DisallowUnknownFields()` only.
- **Zero-value `http.Server` timeouts.** `http.ListenAndServe(addr, h)` has no read/write/idle timeouts and no header cap; a single slowloris client exhausts the connection pool (API-04).
- **`sslmode=prefer` (pgx default).** Falls back to plaintext when the server does not offer TLS, and nothing tells you. `verify-full` in the DSN, validated in config (DATA-03).
- **Trusting `X-Forwarded-For` from any peer.** Rate limits, lockouts, and audit `ip` become attacker-chosen. Check `RemoteAddr` against the proxy CIDR first.
- **`math/rand` for tokens, `bcrypt.DefaultCost`, `InsecureSkipVerify: true` "for staging".** Each is a one-line SEC-07 finding that survives into production because nothing fails.
- **Stateless JWT with long expiry and no `jti` revocation.** `UserDeactivate` (AUTH-07) is a no-op until the token expires; cap at 1 h and check the revocation set on every request.
