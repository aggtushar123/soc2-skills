# Secrets, Dependencies, and Secure Configuration

This domain covers how credentials reach running code, how third-party and container code is kept free of known vulnerabilities, how the codebase is scanned for its own weaknesses, how the system is configured so that production is safe by default, and which cryptographic primitives are allowed. It serves CC6.1 (logical access and credential protection), CC6.6 (boundary protection and encryption in transit), CC6.8 (malicious software prevention), CC7.1 (vulnerability identification), CC8.1 (change management, since scanners gate merges), and C1.2 (confidentiality of data via approved encryption). Auditors sample CI runs, scanner reports, and secret-manager access logs; a control that runs but does not block, or runs only on some branches, is treated as absent.

## When Claude must load this file

- Adding any credential, connection string, API key, certificate, or private key to code, config, `.env`, Dockerfile, Helm values, or CI variables
- Editing `.gitignore`, `.pre-commit-config.yaml`, `.gitleaks.toml`, or secret-scanning CI steps
- Reading configuration from environment variables or a secret manager (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, HashiCorp Vault, Doppler, 1Password Connect)
- Adding, upgrading, or removing a dependency; editing `package.json`, `requirements.txt`, `pyproject.toml`, `go.mod`, `pom.xml`, `Gemfile`, `Cargo.toml`, or any lockfile
- Editing Dependabot/Renovate config or SCA/SAST workflow steps (npm audit, pip-audit, govulncheck, Trivy, Grype, Semgrep, CodeQL, bandit, gosec)
- Touching a Dockerfile, base image tag, `docker-compose.yml`, or container runtime user
- Changing framework settings such as `DEBUG`, `ENV`, `NODE_ENV`, error handler verbosity, CORS defaults, or default admin accounts
- Introducing feature flags for risky functionality (bulk delete, impersonation, data export, payment capture)
- Calling any hashing, encryption, signing, random-number, or key-derivation function, or importing a crypto library

## Requirements

### SEC-01 — No secrets in source, config, images, or CI logs

**Rule:** Secrets never appear in source, committed config, container images, or CI logs. They are fetched from a secret manager or injected as environment at runtime; `.env` files are git-ignored; a secret scanner runs pre-commit and in CI.

**TSC:** CC6.1

**How to implement:**
- Load secrets at process start from AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, or Vault via the SDK or a sidecar/CSI driver (Secrets Store CSI, External Secrets Operator). Fail fast if a required secret is absent; never fall back to a hard-coded default.
- Git-ignore `.env`, `.env.*`, `*.pem`, `*.key`, `*.p12`, `*.jks`, `credentials.json`, `service-account*.json`. Commit `.env.example` with placeholder values only.
- Run `gitleaks` (or `trufflehog`) as a pre-commit hook and as a required CI status check on every PR and on the full history weekly. Enable GitHub secret scanning with push protection on the org.
- Never `COPY .env` or bake credentials into an image layer; use Docker BuildKit `--mount=type=secret` for build-time tokens (private registries), which leaves no layer trace.
- Mask secrets in CI: use GitHub `secrets.*` (auto-masked), `::add-mask::` for derived values, and never `echo` or `env` in workflows. Prefer OIDC federation (`aws-actions/configure-aws-credentials` with `role-to-assume`) over stored cloud keys.
- If a secret is committed, treat it as compromised: rotate immediately, then purge history (`git filter-repo`) and record in `.soc2/EXCEPTIONS.md` or the incident log.

**Code example:**

Minimal pre-commit config for gitleaks:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.21.2
    hooks:
      - id: gitleaks        # SOC2:SEC-01 blocks commits containing secrets
```

CI gate and runtime loading:

```yaml
# .github/workflows/security.yml
jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: gitleaks/gitleaks-action@v2   # SOC2:SEC-01 required status check
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

```python
# config.py
import boto3, json, os

def load_db_password() -> str:
    # SOC2:SEC-01 secret fetched at runtime; no default, no file fallback
    sm = boto3.client("secretsmanager")
    resp = sm.get_secret_value(SecretId=os.environ["DB_SECRET_ARN"])
    return json.loads(resp["SecretString"])["password"]
```

**Common violations:**
- `config/settings.py` with `SECRET_KEY = "dev-key-change-me"` that is never changed in production.
- A committed `docker-compose.yml` with `POSTGRES_PASSWORD: hunter2` reused in staging.
- CI workflow prints `env` for debugging, exposing masked-but-transformed values (base64) in logs.
- gitleaks runs in CI but is marked `continue-on-error: true` or not listed as a required check.

**Evidence to produce:**
- `.pre-commit-config.yaml` and `.github/workflows/security.yml` (job `secret-scan`) with a green run link.
- GitHub org settings screenshot showing secret scanning and push protection enabled.
- Secret manager access log query showing the application role reading secrets at deploy time.

### SEC-02 — Secrets rotate without code change

**Rule:** Every secret can be rotated without a code change or redeploy of source. Rotation is documented and performed at least annually and on personnel change.

**TSC:** CC6.1

**How to implement:**
- Reference secrets by name or ARN, never by value, and read the current version at startup or on a cache TTL (e.g. 5 minutes). Use the Secrets Manager caching client or `vault agent` templating so rotation propagates without a restart.
- Enable managed rotation where supported: AWS Secrets Manager rotation Lambdas for RDS/Redshift/DocumentDB, GCP Secret Manager rotation notifications, Vault database secrets engine with short TTL dynamic credentials.
- Support dual-key windows for tokens you issue: keep `current` and `previous` signing keys so JWT verification accepts both during rollover (JWKS with `kid`).
- Keep a rotation register (`docs/security/secret-rotation.md` or a ticket per secret) listing each secret, owner, rotation method, last rotated date, and next due date. Alert when a secret age exceeds 365 days (`aws secretsmanager describe-secret` `LastRotatedDate`, or a Config rule `secretsmanager-secret-unused` / custom rule).
- On offboarding of anyone with production access, rotate shared secrets they could have seen (break-glass credentials, root API keys) within the offboarding SLA.
- Never cache a secret to disk; in-memory only.

**Code example:**

```hcl
# secrets.tf
# SOC2:SEC-02 automatic 30-day rotation; app reads by ARN so no code change on rotate
resource "aws_secretsmanager_secret" "db" {
  name       = "prod/api/db"
  kms_key_id = aws_kms_key.secrets.arn
}

resource "aws_secretsmanager_secret_rotation" "db" {
  secret_id           = aws_secretsmanager_secret.db.id
  rotation_lambda_arn = aws_lambda_function.rds_rotator.arn
  rotation_rules {
    automatically_after_days = 30
  }
}
```

```go
// db.go — re-resolve credentials on reconnect instead of at compile/deploy time
cache, _ := secretcache.New()
func dsn() string {
    raw, _ := cache.GetSecretString(os.Getenv("DB_SECRET_ARN")) // SOC2:SEC-02
    var s struct{ Username, Password, Host string }
    json.Unmarshal([]byte(raw), &s)
    return fmt.Sprintf("postgres://%s:%s@%s/app?sslmode=verify-full", s.Username, s.Password, s.Host)
}
```

**Common violations:**
- JWT signing key is a single string; rotating it logs out every user and requires a coordinated deploy.
- Secrets are injected as build args and baked into the image, so rotation requires a rebuild.
- No record of when the Stripe or SendGrid key was last rotated; the key predates half the team.
- Rotation is "documented" as a Slack message from two years ago.

**Evidence to produce:**
- Rotation register path with last-rotated dates; Secrets Manager `LastRotatedDate` export.
- Terraform showing `aws_secretsmanager_secret_rotation` or Vault lease TTL config.

### SEC-03 — Pinned dependencies, SCA in CI, patch SLAs

**Rule:** Dependencies are pinned via a lockfile committed to the repo. Software composition analysis runs in CI on every PR and on a schedule. Vulnerabilities are patched within the SLA for their severity.

**TSC:** CC7.1, CC8.1

**How to implement:**
- Commit the lockfile (`package-lock.json`/`pnpm-lock.yaml`, `poetry.lock`/`uv.lock`/`requirements.txt` with hashes, `go.sum`, `Gemfile.lock`, `Cargo.lock`) and install with the frozen flag in CI (`npm ci`, `pnpm install --frozen-lockfile`, `pip install --require-hashes`, `poetry install --sync`).
- Run an SCA tool as a required check: `npm audit --audit-level=high`, `pip-audit`, `govulncheck ./...`, `bundler-audit`, `cargo audit`, OWASP dependency-check, or a multi-ecosystem scanner (Trivy `fs`, Grype, Snyk). Fail the job on high or critical.
- Enable Dependabot or Renovate for automated upgrade PRs, grouped by ecosystem, with security updates prioritized and auto-merge for patch-level bumps when tests pass.
- Run the scan on a nightly or weekly schedule against the default branch as well, because new CVEs appear without code changes.
- Track exceptions with expiry in `.soc2/EXCEPTIONS.md` (e.g. "CVE-2026-1234 not reachable, expires 2026-12-01"). Use tool-native ignore files (`.trivyignore`, `.nvmrc`-style `audit-ci.json`) that reference the exception ID.
- Pin GitHub Actions to full commit SHAs, not tags, and pin base images by digest (see SEC-05).

**Patch SLA:**

| Severity (CVSS) | Time to patch in production | Typical action |
|-----------------|-----------------------------|----------------|
| Critical (9.0-10.0) | 7 days | Hotfix branch, emergency change if needed (CHG-05) |
| High (7.0-8.9) | 30 days | Next sprint, prioritized over feature work |
| Medium (4.0-6.9) | 90 days | Scheduled upgrade PR |
| Low (0.1-3.9) | 180 days | Batched with routine dependency updates |

The SLA clock starts when the vulnerability is published in the scanner's database, not when someone reads the report.

**Code example:**

```yaml
# .github/workflows/security.yml
jobs:
  sca:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
      - uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8 # v4.0.2
        with: { node-version: 20, cache: npm }
      - run: npm ci                       # SOC2:SEC-03 frozen lockfile install
      - run: npm audit --audit-level=high # SOC2:SEC-03 fails on high/critical
      - uses: aquasecurity/trivy-action@18f2510ee396bbf400402947b394f2dd8c87dbb0 # 0.29.0
        with:
          scan-type: fs
          severity: HIGH,CRITICAL
          exit-code: "1"
          ignore-unfixed: true
```

```json
// .github/dependabot.yml equivalent for Renovate: renovate.json
{
  "extends": ["config:recommended", ":pinAllExceptPeerDependencies"],
  "vulnerabilityAlerts": { "labels": ["security"], "prPriority": 10 },
  "packageRules": [{ "matchUpdateTypes": ["patch"], "automerge": true }]
}
```

**Common violations:**
- `package-lock.json` is in `.gitignore`, or CI runs `npm install` and silently resolves different versions than the developer tested.
- `npm audit` runs but is piped through `|| true`, so it never fails.
- Dependabot PRs sit open for months; no one owns merging them and no SLA is tracked.
- Vulnerable transitive dependency is "not our code" and left unpatched with no exception record.

**Evidence to produce:**
- Lockfile path and CI job name `sca` with a run link showing the failing-on-high configuration.
- Dependabot/Renovate config path and a report of open security PRs with age.
- `.soc2/EXCEPTIONS.md` entries for any accepted vulnerabilities with expiry dates.

### SEC-04 — SAST blocks merge on high findings

**Rule:** Static application security testing with security rulesets runs in CI on every PR and blocks merge on high-severity findings.

**TSC:** CC7.1, CC8.1

**How to implement:**
- Choose a scanner with security rules for each language: Semgrep (`p/security-audit`, `p/owasp-top-ten`, plus language packs), CodeQL (`security-extended` query suite), bandit for Python, gosec for Go, ESLint security plugins, Brakeman for Rails, SpotBugs with Find Security Bugs for Java.
- Run it as a required status check named consistently (`sast`) across all repos so branch protection can reference it.
- Fail the job on `ERROR`/high severity; report `WARNING`/medium as PR annotations without blocking. Upload SARIF to GitHub code scanning for a persistent record.
- Add custom rules that encode this skill's requirements: string-built SQL, `datetime.now()` without tz, `logger.*(req.body)`, `crypto.createHash("md5")`, `subprocess(shell=True)`.
- Suppress findings inline only with a justification comment (`# nosemgrep: rule-id -- reason, ticket`) and make unjustified suppressions a review blocker.
- Scan the full default branch weekly, not just the diff, to catch rule updates.

**Code example:**

```yaml
# .github/workflows/security.yml
jobs:
  sast:
    runs-on: ubuntu-latest
    permissions: { contents: read, security-events: write }
    steps:
      - uses: actions/checkout@v4
      - uses: semgrep/semgrep-action@v1     # SOC2:SEC-04 required check; fails on ERROR severity
        with:
          config: >-
            p/security-audit
            p/owasp-top-ten
            p/secrets
            .semgrep/soc2-rules.yml
          generateSarif: "1"
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: semgrep.sarif }
```

```yaml
# .semgrep/soc2-rules.yml (excerpt)
rules:
  - id: soc2-sec07-weak-hash
    pattern-either:
      - pattern: hashlib.md5(...)
      - pattern: hashlib.sha1(...)
    message: "SOC2:SEC-07 MD5/SHA-1 are banned; use hashlib.sha256 or blake2b"
    severity: ERROR
    languages: [python]
```

**Common violations:**
- SAST runs only on a nightly schedule, so vulnerable code is merged and deployed before the report exists.
- Findings are uploaded to a dashboard but the job always exits 0.
- A blanket `.semgrepignore` covers `src/` "temporarily".
- Suppression comments with no reason or ticket.

**Evidence to produce:**
- Workflow file path and CI job name `sast`; branch protection showing it as required.
- GitHub code scanning alerts page export showing open/closed high findings with timestamps.

### SEC-05 — Minimal, non-root, scanned, rebuilt containers

**Rule:** Container images use a minimal base, run as a non-root user, are scanned for vulnerabilities before push, and are rebuilt when the base image updates.

**TSC:** CC7.1, CC6.8

**How to implement:**
- Use multi-stage builds: build in a full image, copy artifacts into `distroless`, `alpine`, `ubuntu:*-minimal`, or `scratch`. No shells, package managers, or compilers in the runtime stage where possible.
- Declare `USER` with a fixed non-zero UID (e.g. `10001`) and make only the directories the process writes to owned by that user. Set `readOnlyRootFilesystem: true` and drop all capabilities in the pod security context.
- Pin base images by digest (`python:3.12-slim@sha256:...`) and let Renovate/Dependabot bump the digest so rebuilds happen on upstream patches. Also schedule a weekly rebuild-and-scan of all production images.
- Scan with Trivy or Grype in CI before push, failing on high/critical with a fix available. Enable registry scanning (ECR enhanced scanning, GCR/Artifact Registry vulnerability scanning, Harbor) for continuous re-evaluation of already-pushed images.
- Generate an SBOM (`syft`, `trivy sbom`, `docker buildx --sbom`) and attach it to the image or release.
- Add a `HEALTHCHECK` or rely on orchestrator probes (LOG-06); never run `latest` in production.

**Code example:**

```dockerfile
# Dockerfile
FROM golang:1.23-bookworm@sha256:2f1e4b9c... AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api

# SOC2:SEC-05 distroless runtime, pinned by digest, non-root UID
FROM gcr.io/distroless/static-debian12:nonroot@sha256:8a1b2c3d...
COPY --from=build /out/api /api
USER 65532:65532
ENV TZ=UTC
EXPOSE 8080
ENTRYPOINT ["/api"]
```

```yaml
# CI step
- uses: aquasecurity/trivy-action@0.29.0   # SOC2:SEC-05 image scan gates push
  with: { image-ref: "${{ env.IMAGE }}", severity: "HIGH,CRITICAL", exit-code: "1", ignore-unfixed: true }
```

**Common violations:**
- `FROM node:latest` with the full Debian toolchain shipped to production and running as root.
- Image is scanned once at build; a CVE published a month later is never re-evaluated because nothing rebuilds.
- `USER` is set but the app writes to `/app/tmp` owned by root, so operators "fix" it by removing `USER`.
- Secrets copied into the image during build (see SEC-01).

**Evidence to produce:**
- Dockerfile path showing base digest and `USER`; CI job name `image-scan` with run link.
- Registry scanning configuration export and the most recent scan report per production image.

### SEC-06 — Secure defaults in production

**Rule:** Production runs with debug mode off, no default or seeded credentials, verbose error output disabled, and risky features behind explicit flags that default to off.

**TSC:** CC6.1, CC8.1

**How to implement:**
- Make the production settings module the default and require an explicit `APP_ENV=development` opt-in to enable debug, verbose errors, permissive CORS, or hot reload. Add a startup assertion: if `APP_ENV=production` and `DEBUG` is true, exit non-zero.
- Remove framework defaults that are unsafe: Django `SECRET_KEY` placeholder, Rails `config.consider_all_requests_local`, Spring Boot Actuator endpoints exposed without auth, Express `X-Powered-By`, Flask `debug=True`, GraphQL introspection and playground in production.
- Never seed admin users with known passwords in migrations. Bootstrap the first admin via a one-time invite token or an out-of-band CLI that reads a randomly generated password from the secret manager.
- Gate risky operations (bulk delete, impersonation, mass export, payment capture, raw SQL console) behind feature flags (LaunchDarkly, Unleash, Flipt, or a config table) that default off and whose changes emit `config.changed` (LOG-01).
- Return generic error bodies with a correlation ID (API-05); keep stack traces in server logs only.
- Add a `config` test that boots the app with production env and asserts each secure default.

**Code example:**

```python
# settings/production.py
import os

DEBUG = False                                  # SOC2:SEC-06 never true in production
ALLOWED_HOSTS = os.environ["ALLOWED_HOSTS"].split(",")
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]   # KeyError on missing, no default
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000

FEATURE_FLAGS = {
    "bulk_delete": False,                      # SOC2:SEC-06 risky feature default off
    "admin_impersonation": False,
}

if os.environ.get("APP_ENV") == "production" and DEBUG:
    raise SystemExit("refusing to start: DEBUG=True in production")
```

**Common violations:**
- `DEBUG = os.environ.get("DEBUG", "True") == "True"` (default is on).
- A `seed.sql` creating `admin@example.com / admin123` that also runs in production migrations.
- Spring Boot `/actuator/env` and `/actuator/heapdump` reachable without authentication.
- Stack traces returned to API clients "only when an `X-Debug` header is present".

**Evidence to produce:**
- Production settings file path and the startup assertion; config test file and CI job name.
- Feature-flag service export showing risky flags off in production.

### SEC-07 — Approved cryptography with KMS-managed keys

**Rule:** Only approved algorithms are used: AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption, RSA ≥ 2048 / ECDSA P-256 / Ed25519 for asymmetric, SHA-256 or stronger for hashing, argon2id or bcrypt for passwords. MD5, SHA-1, DES/3DES, RC4, ECB mode, and custom algorithms are banned. Keys are generated and stored in a KMS.

**TSC:** CC6.6, C1.2

**How to implement:**
- Use the platform's vetted library and its high-level API: `cryptography` (Python, Fernet or `AESGCM`), Node `crypto` with `aes-256-gcm`, Go `crypto/aes` + `cipher.NewGCM` or `golang.org/x/crypto/chacha20poly1305`, Java `Cipher.getInstance("AES/GCM/NoPadding")`, libsodium/NaCl bindings. Never implement primitives yourself.
- Generate a unique 96-bit random nonce per AES-GCM encryption; never reuse a nonce with the same key. Bind context with associated data (AAD) such as tenant ID and field name.
- Use envelope encryption: a data key from AWS KMS `GenerateDataKey`, GCP Cloud KMS, Azure Key Vault, or Vault Transit encrypts the payload; the KMS-encrypted data key is stored alongside the ciphertext. Restrict `kms:Decrypt` to the application role and enable key rotation.
- Passwords: argon2id (memory ≥ 64 MiB, iterations ≥ 3, parallelism 1-4) or bcrypt cost ≥ 12. Never encrypt passwords; hash them.
- Use `SHA-256`/`SHA-512`/`BLAKE2` for integrity, and HMAC-SHA-256 for MACs. Use CSPRNG (`secrets`, `crypto.randomBytes`, `crypto/rand`) for tokens; never `Math.random` or `random.random`.
- Enforce with SAST rules (SEC-04) that flag banned algorithm identifiers and hard-coded IVs.

**Approved vs banned algorithms:**

| Purpose | Approved | Banned |
|---------|----------|--------|
| Symmetric encryption | AES-256-GCM, ChaCha20-Poly1305, AES-256-GCM-SIV | DES, 3DES, RC4, Blowfish, AES-ECB, AES-CBC without MAC |
| Asymmetric / signatures | RSA ≥ 2048 (PSS or OAEP), ECDSA P-256/P-384, Ed25519 | RSA < 2048, RSA PKCS#1 v1.5 for new systems, DSA |
| Hashing / integrity | SHA-256, SHA-384, SHA-512, SHA-3, BLAKE2/3 | MD5, SHA-1, CRC as security control |
| Password storage | argon2id, bcrypt (cost ≥ 12), scrypt | Plain SHA-*, MD5, unsalted anything, reversible encryption |
| Key derivation | HKDF-SHA-256, PBKDF2-SHA-256 (≥ 600k iterations) | Single-round hash of a passphrase |
| MAC | HMAC-SHA-256 or stronger, Poly1305 (via AEAD) | HMAC-MD5, HMAC-SHA-1, CBC-MAC |
| TLS | TLS 1.2 with AEAD suites, TLS 1.3 | SSLv3, TLS 1.0/1.1, NULL or EXPORT ciphers |
| Randomness | OS CSPRNG (`/dev/urandom`, `getrandom`) | `Math.random`, `rand()`, time-seeded PRNGs |

**Code example:**

```javascript
// crypto/envelope.js
const { KMSClient, GenerateDataKeyCommand } = require("@aws-sdk/client-kms");
const crypto = require("node:crypto");
const kms = new KMSClient({});

// SOC2:SEC-07 AES-256-GCM with per-message nonce; data key from KMS, never from config
async function encryptField(plaintext, { tenantId, field }) {
  const { Plaintext: dataKey, CiphertextBlob: wrappedKey } = await kms.send(
    new GenerateDataKeyCommand({ KeyId: process.env.KMS_KEY_ARN, KeySpec: "AES_256" })
  );
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", dataKey, nonce);
  cipher.setAAD(Buffer.from(`${tenantId}:${field}`));
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  dataKey.fill(0);
  return { v: 1, wrappedKey, nonce, ct, tag: cipher.getAuthTag() };
}
```

**Common violations:**
- `crypto.createHash("md5")` used to "fingerprint" session tokens or API keys.
- AES-CBC with a static IV stored as a constant in the source file.
- A raw 32-byte encryption key stored in an environment variable rather than wrapped by KMS.
- `random.random()` or `Math.random()` used to generate password-reset tokens.

**Evidence to produce:**
- Crypto helper module path with the `SOC2:SEC-07` annotation; SAST rule IDs for banned algorithms.
- KMS key policy export showing rotation enabled and `kms:Decrypt` limited to application roles.

## Review checklist

- [ ] SEC-01 — Are all new credentials read from the secret manager or injected environment with no defaults, and does gitleaks pass as a required check (pre-commit and CI)?
- [ ] SEC-02 — Can every secret introduced or touched be rotated without a code change (referenced by name/ARN, read at runtime, dual-key window where applicable), and is it in the rotation register?
- [ ] SEC-03 — Is the lockfile updated and committed, does the `sca` job still fail on high/critical, and is any accepted vulnerability recorded in `.soc2/EXCEPTIONS.md` with an expiry within the SLA?
- [ ] SEC-04 — Does the `sast` job pass with no new high findings, and does every inline suppression carry a reason and ticket?
- [ ] SEC-05 — Does any Dockerfile change keep a minimal base pinned by digest, a non-root `USER`, and a passing `image-scan` step?
- [ ] SEC-06 — Are debug, verbose errors, default credentials, and risky features all off by default in production config, with the startup assertion intact?
- [ ] SEC-07 — Do all crypto calls use approved algorithms from the table with per-message nonces and KMS-managed keys, and are tokens generated from a CSPRNG?
