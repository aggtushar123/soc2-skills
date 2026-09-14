# Authentication and Access Control

This file details AUTH-01 through AUTH-10 from `requirements.md`. It covers how a user or service proves identity, how the server decides what that identity may do, how credentials and sessions are protected, and how the identity lifecycle (create, change, deactivate, review) is made auditable. These requirements serve the Security criteria CC6.1 (logical access), CC6.2 (provisioning and removal), CC6.3 (role-based access and least privilege), and CC6.6 (protection against external threats). Access control is the single most-tested area in a SOC 2 audit: auditors will sample users, routes, and deprovisioning events and ask for evidence of each.

## When Claude must load this file

- Adding or modifying a route, controller, handler, resolver, or RPC method
- Adding or modifying authentication middleware, guards, decorators, or interceptors
- Touching login, logout, signup, password reset, MFA, or token issuance/refresh code
- Adding or changing a role, permission, policy, scope, or ownership check
- Modifying session storage, cookie settings, or JWT signing/verification
- Adding a service-to-service call, internal API client, or cron/worker that calls another service
- Writing user provisioning, deactivation, invitation, or SSO/SCIM code
- Adding an admin panel, admin-only capability, or "impersonate user" feature
- Writing scripts or reports that list users, roles, or access

## Requirements

### AUTH-01 — Deny by default; public routes are allow-listed

**Rule:** Every non-public endpoint requires authentication. The framework is configured so that a route with no explicit auth declaration is rejected, and the set of public routes is a short, reviewable allow-list.

**TSC:** CC6.1

**How to implement:**
- Register an authentication middleware globally (app-level), not per route. Public routes opt out by name; nothing opts in.
- Node/Express: mount `requireAuth` on the app before routers; keep `PUBLIC_ROUTES` as a static array checked by method+path. NestJS: a global `APP_GUARD` with a `@Public()` decorator read via `Reflector`.
- Python/FastAPI: put `Depends(current_user)` on an `APIRouter` and include all routers under it; public endpoints live in a separate `public_router`. Django: `LoginRequiredMiddleware` (Django 5.1+) or a custom middleware with a `PUBLIC_PATHS` list; DRF `DEFAULT_PERMISSION_CLASSES = [IsAuthenticated]`.
- Go: wrap the mux with an auth handler; `chi` `Group` for public routes, everything else under the authenticated group.
- Java/Spring: `http.authorizeHttpRequests(a -> a.requestMatchers("/health", "/login").permitAll().anyRequest().authenticated())`. `anyRequest().authenticated()` is the line reviewers must look for.
- Add a test that enumerates all registered routes and asserts each is either in the allow-list or returns 401 without credentials. This test is your best evidence.
- Health and readiness endpoints are public but must not leak internals (see LOG-06).

**Code example:**

```javascript
// middleware/requireAuth.js
const PUBLIC_ROUTES = new Set(['GET /health', 'POST /auth/login', 'POST /auth/refresh']);

// SOC2:AUTH-01 — deny by default; only allow-listed routes skip authentication
function requireAuth(req, res, next) {
  const key = `${req.method} ${req.path}`;
  if (PUBLIC_ROUTES.has(key)) return next();

  const token = req.cookies?.session ?? bearerFrom(req.headers.authorization);
  if (!token) return res.status(401).json({ error: 'unauthenticated' });

  try {
    req.user = verifySession(token); // throws on expired, revoked, or bad signature
    return next();
  } catch {
    return res.status(401).json({ error: 'unauthenticated' });
  }
}

app.use(requireAuth); // mounted before every router
```

**Common violations:**
- Auth applied per-router; a new router is added later without it.
- "Internal" endpoints (`/admin/*`, `/internal/*`, `/debug/*`) protected only by network position or obscurity.
- GraphQL or gRPC added with a separate server that bypasses the HTTP middleware.
- Webhook receivers that accept any payload without signature verification (HMAC with a per-integration secret is the minimum).

**Evidence to produce:**
- The global auth middleware/guard file (e.g. `src/middleware/requireAuth.*`, `SecurityConfig.java`) and the public allow-list
- A route-enumeration test in CI (e.g. `test/routes_require_auth.test.*`) with its passing job

### AUTH-02 — Server-side, per-object authorization

**Rule:** Authorization is enforced server-side on every request and every object touched (RBAC or ABAC plus an ownership or tenant check). Roles, tenant IDs, and user IDs supplied by the client are never trusted.

**TSC:** CC6.1, CC6.3

**How to implement:**
- Derive `user_id`, `tenant_id`, and roles from the verified session or token only. Strip or ignore any `user_id`/`tenant_id`/`role` field in request bodies and query strings.
- Do the object check in the data layer, not the controller: repositories accept the caller's principal and add `WHERE owner_id = ? AND tenant_id = ?` (see DATA-08 for tenant scoping).
- Use a policy library rather than ad hoc `if` chains: Node — `casl` or `@casl/ability`; Python — `django-guardian`, `oso`, or DRF `has_object_permission`; Go — `casbin` or hand-written policy functions with table-driven tests; Java — Spring `@PreAuthorize("hasRole('ADMIN') or #doc.ownerId == principal.id")` or Spring ACL; cloud — Cedar (AWS Verified Permissions) or OpenFGA.
- Return 404, not 403, for objects the caller cannot see when existence itself is sensitive (e.g. cross-tenant IDs).
- Test IDOR explicitly: for every object endpoint, a test that user A fetches user B's object and gets 404/403.
- Never rely on UUID unguessability as authorization.

**Code example:**

```python
# app/api/documents.py
from fastapi import APIRouter, Depends, HTTPException
from app.auth import Principal, current_principal
from app.repos import DocumentRepo

router = APIRouter()

@router.get("/documents/{doc_id}")
def get_document(doc_id: str, p: Principal = Depends(current_principal)):
    # SOC2:AUTH-02 — tenant and ownership derived from the verified principal, never from input
    doc = DocumentRepo.find_for_principal(doc_id, tenant_id=p.tenant_id)
    if doc is None:
        raise HTTPException(status_code=404)
    if doc.owner_id != p.user_id and not p.has_role("doc_admin"):
        raise HTTPException(status_code=404)  # do not confirm existence across owners
    return doc.to_public_dict()
```

**Common violations:**
- `GET /users/:id/orders` where `:id` is used directly without comparing to `req.user.id`.
- Role sent in a JWT that the client can mint, or role read from `X-Role` header behind a proxy.
- Authorization checked on list endpoints but not on the corresponding `GET /:id`, `PATCH`, or `DELETE`.
- Bulk endpoints (`POST /export?ids=1,2,3`) that check the first ID only.

**Evidence to produce:**
- Policy definitions (`src/authz/policies.*`, `casbin/model.conf`) and the repository methods that apply them
- IDOR/cross-tenant tests in CI (`test/authz/*idor*`)

### AUTH-03 — MFA for privileged accounts, available to all

**Rule:** MFA is mandatory for admin and privileged accounts and offered to every user. Enrollment and disablement are audited events.

**TSC:** CC6.1

**How to implement:**
- Prefer phishing-resistant factors: WebAuthn/passkeys (`@simplewebauthn/server` for Node, `py_webauthn` for Python, `go-webauthn/webauthn`, `webauthn4j` for Java). TOTP (RFC 6238) is acceptable as a second option (`otplib`, `pyotp`, `pquerna/otp`). Avoid SMS as the sole factor.
- Enforce at two layers: at login (`mfa_verified` claim in the session) and at role assignment (an admin role cannot be granted to a principal with `mfa_enrolled = false`).
- If you use an IdP (Okta, Entra ID, Google Workspace, Cognito, Auth0), enforce MFA in the IdP policy and require the `amr` claim (e.g. `["pwd","mfa"]` or `"hwk"`) in your token validation for admin routes.
- Cloud consoles: AWS IAM/SSO and GCP org policies must require MFA for human principals (see INFRA-03).
- Provide recovery codes (hashed at rest like passwords) and an audited recovery path; do not let support staff bypass MFA silently.
- Step-up: re-verify MFA before high-risk actions (role changes, exports, key rotation) if the last verification is older than a configured window (e.g. 15 min).

**Code example:**

```go
// internal/authz/mfa.go
package authz

import "time"

// SOC2:AUTH-03 — privileged routes require a fresh MFA assertion in the session
func RequireMFA(maxAge time.Duration) Middleware {
	return func(next Handler) Handler {
		return func(ctx *Ctx) {
			s := ctx.Session()
			if !s.MFAVerified || time.Since(s.MFAVerifiedAt) > maxAge {
				ctx.JSON(403, map[string]string{
					"error":  "mfa_required",
					"action": "/auth/mfa/verify",
				})
				return
			}
			next(ctx)
		}
	}
}

// usage: adminRouter.Use(RequireMFA(15 * time.Minute))
```

**Common violations:**
- MFA "available" in the UI but admin accounts created via script or seed without it.
- MFA checked at login only; a long-lived session issued before enrollment stays privileged.
- Recovery codes stored in plaintext, or support tooling that can disable MFA without a second approver.
- Break-glass or service accounts with console access and no MFA.

**Evidence to produce:**
- IdP MFA policy screenshot or export, or the `RequireMFA` middleware and its attachment to admin routes
- Query showing all admin-role users with `mfa_enrolled = true` (run quarterly, stored with access reviews)

### AUTH-04 — Password policy and storage

**Rule:** Passwords are at least 12 characters, checked against breached-password lists, and stored with argon2id or bcrypt (cost ≥ 12). Passwords are never logged, emailed, or returned in any response.

**TSC:** CC6.1

**How to implement:**
- argon2id parameters (OWASP baseline): memory 19 MiB (`m=19456`), iterations 2 (`t=2`), parallelism 1 (`p=1`); or `m=65536, t=3, p=4` when you can afford it. Libraries: `argon2` (Node), `argon2-cffi` (Python), `golang.org/x/crypto/argon2` (Go), `Argon2PasswordEncoder` (Spring Security 6). If using bcrypt, cost 12 minimum, and pre-hash with SHA-256 only if you must accept >72-byte passwords (document why).
- Breached-password check: Have I Been Pwned range API (k-anonymity: send first 5 hex chars of SHA-1 only), or a bundled offline list. Django: `CommonPasswordValidator` plus `pwned-passwords-django`. Do not block on outage; fail open with a warning log and a follow-up check.
- Length: minimum 12, maximum at least 128, no composition rules (NIST 800-63B). Reject the user's own email/name.
- Compare with the library's constant-time verify; never `===`.
- Password fields: `password`, `new_password`, `current_password` go in the logging redaction list (LOG-03). Send reset links with a single-use, 15-minute token, never a temporary password.
- Rehash on login when parameters change (`needsRehash`).

**Code example:**

```javascript
// services/password.js
const argon2 = require('argon2');
const { isPwned } = require('./hibp');

const ARGON2_OPTS = { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 };

async function setPassword(user, plaintext) {
  // SOC2:AUTH-04 — length + breach check + argon2id; plaintext never persisted or logged
  if (typeof plaintext !== 'string' || plaintext.length < 12 || plaintext.length > 128) {
    throw new PolicyError('password_length');
  }
  if (await isPwned(plaintext)) throw new PolicyError('password_breached');
  user.password_hash = await argon2.hash(plaintext, ARGON2_OPTS);
  user.password_changed_at = new Date();
  await user.save();
  audit.emit('password.changed', { actor: user.id, target: user.id });
}

async function verifyPassword(user, plaintext) {
  return argon2.verify(user.password_hash, plaintext); // constant-time
}
```

**Common violations:**
- bcrypt with cost 10 (the library default), or `crypto.createHash('sha256')` on passwords.
- Password included in the user object returned by an ORM `toJSON()`.
- Reset flow that emails a generated password, or reset tokens that never expire.
- "Complexity" rules (uppercase + symbol) enforced but no breach list and 8-character minimum.

**Evidence to produce:**
- The hashing module with parameters (`services/password.*`, `settings.PASSWORD_HASHERS`)
- Unit test asserting rejection of short and breached passwords; a grep showing no `password` key in log output

### AUTH-05 — Sessions and tokens

**Rule:** Access tokens live at most 1 hour; refresh tokens rotate on use and are revocable server-side; sessions have an idle timeout; cookies carry `Secure`, `HttpOnly`, and `SameSite`.

**TSC:** CC6.1

**How to implement:**
- JWT access tokens: set `exp` (≤ 60 min, 15 min for admin), `iat`, `nbf`, `iss`, `aud`, and a `jti`. Verify all of them; pin the algorithm (`RS256`/`ES256`/`EdDSA`), never accept `alg: none` or let the token choose. Libraries: `jose` (Node), `PyJWT` with `algorithms=[...]`, `golang-jwt/jwt/v5` with `WithValidMethods`, Spring `NimbusJwtDecoder`.
- Refresh tokens: opaque random 256-bit values stored hashed (SHA-256) in a table with `user_id`, `family_id`, `expires_at`, `revoked_at`. On use, issue a new one and revoke the old; if a revoked token from the same family is presented, revoke the whole family (reuse detection).
- Revocation: keep a denylist of `jti` values with TTL = remaining `exp` in Redis, or use a per-user `token_version` claim compared on each request. Deactivation (AUTH-07) bumps the version.
- Cookies: `Secure; HttpOnly; SameSite=Lax` (or `Strict` for admin), `Path=/`, `__Host-` prefix, no `Domain` attribute unless subdomains truly need it. Express `cookie-session`/`express-session` with `cookie: { secure: true, httpOnly: true, sameSite: 'lax' }`; Django `SESSION_COOKIE_SECURE = True`, `SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SAMESITE = 'Lax'`; Spring `server.servlet.session.cookie.*`.
- Idle timeout 30 min for admin, up to 24 h for regular users; absolute lifetime ≤ 30 days. Regenerate the session ID on login and privilege change.
- Do not store tokens in `localStorage`; use the `HttpOnly` cookie or in-memory only.

**Code example:**

```python
# app/auth/tokens.py
import secrets, hashlib, datetime as dt
import jwt
from app.db import RefreshToken, session

ACCESS_TTL = dt.timedelta(minutes=30)
REFRESH_TTL = dt.timedelta(days=14)

def issue_access(user, token_version: int) -> str:
    now = dt.datetime.now(dt.UTC)
    # SOC2:AUTH-05 — short exp, jti for revocation, pinned algorithm
    claims = {"sub": str(user.id), "tid": str(user.tenant_id), "ver": token_version,
              "iat": now, "nbf": now, "exp": now + ACCESS_TTL,
              "iss": "api.example.com", "aud": "example-web", "jti": secrets.token_hex(16)}
    return jwt.encode(claims, PRIVATE_KEY, algorithm="ES256")

def rotate_refresh(old_raw: str) -> str:
    old = RefreshToken.get(hash=hashlib.sha256(old_raw.encode()).hexdigest())
    if old is None or old.expires_at < dt.datetime.now(dt.UTC):
        raise AuthError("invalid_refresh")
    if old.revoked_at:                      # reuse detected -> revoke the whole family
        RefreshToken.revoke_family(old.family_id); raise AuthError("refresh_reuse")
    old.revoked_at = dt.datetime.now(dt.UTC)
    new_raw = secrets.token_urlsafe(32)
    session.add(RefreshToken(hash=hashlib.sha256(new_raw.encode()).hexdigest(),
                             user_id=old.user_id, family_id=old.family_id,
                             expires_at=dt.datetime.now(dt.UTC) + REFRESH_TTL))
    session.commit(); return new_raw
```

**Common violations:**
- 24-hour or 7-day access tokens "for convenience"; no `exp` at all.
- `jwt.decode(token)` without `verify` / `algorithms` (Python) or `jwt.Parse` without validating the method (Go).
- Refresh tokens that are static per user, stored plaintext, or never invalidated on logout.
- `SameSite=None` without `Secure`, or session cookies missing `HttpOnly` so a frontend can "read the user".

**Evidence to produce:**
- Token issuance/verification module and cookie configuration (`app/auth/tokens.*`, `settings.py`, `SecurityConfig`)
- Screenshot of a production `Set-Cookie` header from browser devtools, and the refresh-token table schema

### AUTH-06 — Brute-force protection

**Rule:** Login, password reset, MFA verification, and token endpoints are rate-limited and apply lockout or exponential backoff. Limits are keyed on both the target account and the source.

**TSC:** CC6.1, CC6.6

**How to implement:**
- Two keys: per-account (e.g. 5 failures per 15 min, then 15-min lock or backoff doubling) and per-IP/ASN (e.g. 100 attempts per 15 min). Per-account limits stop credential stuffing; per-IP limits stop spraying.
- Use a shared store (Redis) so limits hold across replicas: `rate-limiter-flexible` (Node), `django-ratelimit`/`slowapi` (Python), `ulule/limiter` or `golang.org/x/time/rate` backed by Redis (Go), `bucket4j` (Java). At the edge: AWS WAF rate-based rules, Cloudflare Rate Limiting, GCP Cloud Armor.
- MFA/TOTP verification: cap at 5 attempts per code window; a 6-digit TOTP is trivially brute-forced without this.
- Password reset: rate-limit both the request endpoint (per email and per IP) and the token-submit endpoint; use the same generic response for existing and non-existing accounts.
- Return the same 401 body and similar latency for "no such user" and "wrong password".
- Emit an audit event on lockout and alert on spikes (LOG-05). Do not permanently lock; use time-boxed locks to avoid a denial-of-service against victims.

**Code example:**

```go
// internal/auth/throttle.go
package auth

// SOC2:AUTH-06 — per-account and per-IP limits on credential endpoints
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	email, ip := normEmail(r), clientIP(r)
	if h.limiter.Exceeded(r.Context(), "login:acct:"+email, 5, 15*time.Minute) ||
		h.limiter.Exceeded(r.Context(), "login:ip:"+ip, 100, 15*time.Minute) {
		h.audit.Emit(r.Context(), "auth.login.throttled", map[string]any{"email": email, "ip": ip})
		w.Header().Set("Retry-After", "900")
		http.Error(w, `{"error":"too_many_attempts"}`, http.StatusTooManyRequests)
		return
	}
	ok := h.users.VerifyPassword(r.Context(), email, passwordFrom(r))
	if !ok {
		h.limiter.Hit(r.Context(), "login:acct:"+email)
		h.limiter.Hit(r.Context(), "login:ip:"+ip)
		http.Error(w, `{"error":"invalid_credentials"}`, http.StatusUnauthorized)
		return
	}
	h.limiter.Reset(r.Context(), "login:acct:"+email)
	h.sessions.Start(w, r, email)
}
```

**Common violations:**
- Rate limit on `/login` only; `/auth/mfa/verify`, `/auth/refresh`, and `/password/reset` are unlimited.
- In-memory limiter that resets on deploy or differs per pod.
- Limits keyed only on IP, defeated by rotating proxies; or only on account, enabling password spraying.
- Error messages that distinguish unknown user from wrong password.

**Evidence to produce:**
- Limiter configuration and the endpoints it is attached to (`internal/auth/throttle.go`, WAF rule export)
- Log query showing `auth.login.throttled` events, and an integration test that triggers a 429

### AUTH-07 — Auditable provisioning and immediate deprovisioning

**Rule:** Creating, modifying, and deactivating users are audited operations with actor, target, and timestamp. Deactivation takes effect immediately and revokes all active sessions, refresh tokens, API keys, and device registrations.

**TSC:** CC6.2, CC6.3

**How to implement:**
- Make deactivation a single service function that: sets `status = disabled`, bumps `token_version`, deletes/revokes refresh tokens and API keys, clears sessions in the session store, revokes OAuth grants, removes SSH/device certs, and emits `user.deactivated` to the audit log. Every caller (admin UI, SCIM, HR webhook, CLI) uses this one function.
- Make the middleware check `status` and `token_version` on every request (cheap cache with ≤ 60 s TTL is acceptable; document the window).
- If using an IdP: implement SCIM 2.0 (`/Users` with `active=false`) or consume the IdP's deprovisioning webhook. Tie HR system offboarding to the IdP so a single action cascades.
- Provisioning: no self-granted roles; invitations carry the intended role and are approved by someone with `user_admin`. Record who approved.
- Cloud: AWS IAM Identity Center / GCP Cloud Identity as the source of truth; no locally created console users.
- Keep a `user_events` audit table or ship to the central audit log (LOG-01/LOG-02) with `actor_id`, `target_user_id`, `action`, `before`, `after`, `ts_utc`, `correlation_id`.

**Code example:**

```javascript
// services/users/deactivate.js
async function deactivateUser({ actor, targetUserId, reason, correlationId }) {
  // SOC2:AUTH-07 — one code path: disable, revoke everything, audit
  await db.transaction(async (trx) => {
    const user = await trx('users').where({ id: targetUserId }).forUpdate().first();
    if (!user) throw new NotFound();
    await trx('users').where({ id: targetUserId })
      .update({ status: 'disabled', token_version: user.token_version + 1, disabled_at: trx.fn.now() });
    await trx('refresh_tokens').where({ user_id: targetUserId }).update({ revoked_at: trx.fn.now() });
    await trx('api_keys').where({ user_id: targetUserId }).update({ revoked_at: trx.fn.now() });
    await trx('user_role_assignments').where({ user_id: targetUserId }).del();
  });
  await sessionStore.destroyAllForUser(targetUserId);   // Redis-backed sessions
  await idp.revokeGrants(targetUserId);                  // OAuth/OIDC grants, if any
  await audit.emit('user.deactivated', {
    actor: actor.id, target: targetUserId, reason, correlation_id: correlationId,
  });
}
```

**Common violations:**
- Deactivation flips a flag but existing JWTs remain valid until `exp` (hours or days).
- Admin UI deactivates, but SCIM or a support script uses a different code path that forgets API keys.
- No record of who created a user or granted a role.
- Contractors and service accounts without an owner or end date, so nobody deprovisions them.

**Evidence to produce:**
- The deactivation service (`services/users/deactivate.*`) and a test that a revoked user's token returns 401 immediately
- Audit log query for `user.created|user.deactivated|role.granted` over the sample period

### AUTH-08 — Short-lived service-to-service credentials

**Rule:** Calls between services authenticate with short-lived, identity-bound credentials (mTLS, cloud workload identity, or signed JWTs with ≤ 1 h lifetime). No static API keys shared between services.

**TSC:** CC6.1, CC6.6

**How to implement:**
- Kubernetes: service mesh mTLS (Istio, Linkerd) with SPIFFE IDs, or projected service-account tokens (`audience`, `expirationSeconds: 3600`) verified by the callee via the TokenReview API or the cluster's OIDC JWKS.
- AWS: IAM roles for tasks/pods (IRSA, EKS Pod Identity) and SigV4-signed requests; API Gateway with IAM auth; Lambda invoking via SDK role. GCP: workload identity plus OIDC ID tokens (`google.auth` / `idtoken.NewClient`), audience = the callee's URL, verified with Google's JWKS.
- Self-hosted: OAuth 2.0 client credentials with a private_key_jwt or mTLS client auth, tokens ≤ 1 h; or SPIRE.
- The callee verifies `iss`, `aud`, `exp`, and maps the workload identity to an allow-list of permitted callers per route. The identity, not the network, is the authorization boundary.
- Where a static key is unavoidable (third-party webhooks), store it in the secret manager, scope it to one integration, rotate it (SEC-02), and verify HMAC signatures with a constant-time compare.
- Never pass a user's token through to downstream services as-is unless the downstream is the intended `aud`; use token exchange (RFC 8693) or a new service token that carries the user context as a claim.

**Code example:**

```go
// internal/clients/billing.go — caller side, GCP workload identity
package clients

import (
	"context"
	"net/http"
	"google.golang.org/api/idtoken"
)

// SOC2:AUTH-08 — OIDC ID token minted from workload identity, audience-bound, ~1h lifetime
func NewBillingClient(ctx context.Context, baseURL string) (*http.Client, error) {
	// idtoken.NewClient refreshes the token automatically before expiry
	return idtoken.NewClient(ctx, baseURL /* aud */)
}

// callee side: verify the token and map identity -> allowed caller
func verifyCaller(ctx context.Context, raw, expectedAud string) (string, error) {
	p, err := idtoken.Validate(ctx, raw, expectedAud)
	if err != nil {
		return "", err
	}
	email, _ := p.Claims["email"].(string) // e.g. orders-svc@proj.iam.gserviceaccount.com
	if !allowedCallers[email] {
		return "", errForbidden
	}
	return email, nil
}
```

**Common violations:**
- `INTERNAL_API_KEY` env var shared by every service and unchanged for years.
- Internal services trusting any request from the VPC CIDR ("it's behind the firewall").
- Long-lived AWS access keys baked into a container for cross-account calls instead of `AssumeRole`.
- Forwarding the end-user's JWT to five services, none of which check `aud`.

**Evidence to produce:**
- Mesh/mTLS policy (`PeerAuthentication` with `mtls.mode: STRICT`) or the token-minting client and callee verification code
- IAM role trust policies / workload identity bindings exported from the cloud account

### AUTH-09 — Least-privilege roles; admin is a separate role

**Rule:** Roles grant the minimum permissions needed. Admin capabilities are distinct roles, not boolean flags on regular users. No code path executes as a superuser or with a root database connection by default.

**TSC:** CC6.3

**How to implement:**
- Define permissions as fine-grained verbs on resources (`invoices:read`, `users:deactivate`) and compose roles from them in one file (`authz/roles.yml` or code). Reviewers can diff role changes.
- Separate roles per admin concern (`billing_admin`, `user_admin`, `security_admin`) instead of `is_admin`. Require CODEOWNERS review on the roles file (CHG-04).
- Database: the application connects as a role with only DML on its schema; migrations use a separate, elevated role invoked by CI only. No `postgres`/`root` connection string in app config. Same for cloud SDK roles (INFRA-03).
- Support "impersonation" as an explicit, time-boxed, audited capability rather than logging in as the user.
- Default-deny in the permission check: unknown permission → false. Never `if (user.isAdmin) return true` at the top of the policy function; admins should still be scoped by tenant.
- Run periodic reports of who holds each admin role (feeds AUTH-10).

**Code example:**

```python
# app/authz/roles.py
# SOC2:AUTH-09 — permissions composed into narrow roles; admin is a role, not a flag
PERMISSIONS = {
    "invoices:read", "invoices:write", "users:read", "users:invite",
    "users:deactivate", "roles:assign", "audit:read", "export:run",
}

ROLES = {
    "member":         {"invoices:read"},
    "finance":        {"invoices:read", "invoices:write"},
    "user_admin":     {"users:read", "users:invite", "users:deactivate"},
    "security_admin": {"users:read", "roles:assign", "audit:read"},
    "export_admin":   {"export:run"},
}

def can(principal, permission: str) -> bool:
    if permission not in PERMISSIONS:   # unknown permission is a bug, deny loudly
        raise ValueError(f"unknown permission {permission}")
    return any(permission in ROLES.get(r, set()) for r in principal.roles)
```

**Common violations:**
- `users.is_admin BOOLEAN` and `if user.is_admin: return True` short-circuits everywhere.
- Application connects to Postgres as the owner/superuser role; ORM has `DROP` rights in production.
- A "god mode" support token or a shared admin login.
- Roles assigned by editing the database directly, leaving no audit trail.

**Evidence to produce:**
- The roles/permissions definition file and its git history
- Database role grants (`\du`, `SHOW GRANTS`) for the application user; IAM policy for the app's cloud role

### AUTH-10 — Access review export

**Rule:** The system can produce, on demand, a current list of all users (human and service), their roles/permissions, status, MFA state, and last-login date, to support at least quarterly access reviews.

**TSC:** CC6.2, CC6.3

**How to implement:**
- Record `last_login_at` on every successful authentication (and `last_used_at` on API keys and service accounts). Update asynchronously if write load matters.
- Provide one query or CLI command (`scripts/access_review.py`, `make access-review`, an admin endpoint restricted to `security_admin`) that emits CSV/JSON with: `user_id, email, type (human|service), status, roles, mfa_enrolled, created_at, last_login_at, created_by`.
- Include third-party identities: IdP groups (Okta/Entra via SCIM or Graph API), cloud IAM (AWS `iam:GenerateCredentialReport`, GCP `gcloud asset search-all-iam-policies`), GitHub org members, database roles. The reviewer needs one place to look.
- Schedule it (CI cron or a scheduled job) to run on the first day of each quarter, upload the output to a restricted evidence bucket with a timestamp, and open a ticket assigned to the reviewer.
- Flag anomalies in the output: no login in 90 days, admin without MFA, service account without owner.
- The export itself is an audited action (LOG-01: "data exports").

**Code example:**

```javascript
// scripts/access-review.js — run by CI cron on the 1st of each quarter
const { db } = require('../src/db');
const { audit } = require('../src/audit');

async function main() {
  // SOC2:AUTH-10 — quarterly user/role/last-login export for access review
  const rows = await db('users as u')
    .leftJoin('user_role_assignments as ra', 'ra.user_id', 'u.id')
    .groupBy('u.id')
    .select('u.id', 'u.email', 'u.type', 'u.status', 'u.mfa_enrolled',
            'u.created_at', 'u.last_login_at',
            db.raw("string_agg(ra.role, ',' order by ra.role) as roles"))
    .orderBy('u.email');

  const stale = rows.filter(r => !r.last_login_at || ageDays(r.last_login_at) > 90);
  const noMfaAdmin = rows.filter(r => /admin/.test(r.roles || '') && !r.mfa_enrolled);

  await writeCsv(`access-review-${isoDate()}.csv`, rows);
  await audit.emit('export.access_review', { actor: 'ci-cron', rows: rows.length,
                                             stale: stale.length, no_mfa_admin: noMfaAdmin.length });
}
main();
```

**Common violations:**
- No `last_login_at` column, so reviews cannot identify dormant accounts.
- Review done by screenshotting the admin UI page by page; no complete, timestamped artifact.
- Service accounts and API keys omitted from the review.
- Reviews performed but no record of what was revoked as a result.

**Evidence to produce:**
- The export script and its scheduled job definition (`.github/workflows/access-review.yml`, Cloud Scheduler job)
- Quarterly output files in the evidence bucket plus the review ticket showing sign-off and revocations

## Review checklist

- [ ] AUTH-01: Is authentication applied globally with a deny-by-default, and is any new route either authenticated or added to the explicit public allow-list?
- [ ] AUTH-02: Does every object access derive user/tenant from the verified principal and check ownership or tenant in the data layer, with IDOR tests?
- [ ] AUTH-03: Are admin/privileged routes gated on a fresh MFA assertion, and can a role be granted only to an MFA-enrolled principal?
- [ ] AUTH-04: Are passwords ≥ 12 chars, breach-checked, hashed with argon2id or bcrypt(≥12), and absent from logs, emails, and responses?
- [ ] AUTH-05: Are access tokens ≤ 1 h with `exp`/`jti` and pinned algorithm, refresh tokens rotated and revocable, and cookies `Secure; HttpOnly; SameSite`?
- [ ] AUTH-06: Are login, reset, MFA, and refresh endpoints rate-limited per account and per source with a shared store and generic errors?
- [ ] AUTH-07: Does user create/modify/deactivate go through one audited path, and does deactivation revoke sessions, refresh tokens, and API keys immediately?
- [ ] AUTH-08: Do service-to-service calls use mTLS, workload identity, or ≤ 1 h signed JWTs, with the callee verifying `aud` and an allow-list of callers?
- [ ] AUTH-09: Are permissions fine-grained, admin capabilities separate roles (no `is_admin` flag), and does the app avoid superuser DB/cloud credentials?
- [ ] AUTH-10: Is `last_login_at` recorded and can a complete users/roles/MFA/last-login export be produced by a scheduled, audited job?
