# Data Handling

This file details DATA-01 through DATA-10 from `requirements.md`. It covers the lifecycle of persisted data: how each field is classified, how confidential and restricted data is encrypted at rest and in transit, how long it is kept, how it is deleted completely, how little of it is collected in the first place, how backups are protected and restore-tested, how tenants are isolated, how subjects can export their data, and how production data is kept out of non-production. These requirements serve Confidentiality C1.1–C1.3, Privacy P3.1, P4.1, P4.2, and P5.1 (only when Privacy is in scope in `.soc2/config.yml`), Availability A1.2–A1.3 (backups), and Security CC6.1, CC6.6, CC6.7. Auditors will pick a data store, ask for its classification, its encryption configuration, its retention job, and evidence that a deletion actually removed the data.

## When Claude must load this file

- Adding, renaming, or changing the type of a model field, column, table, collection, or migration
- Adding a new datastore, cache, search index, queue, or object-storage bucket
- Writing code that reads or writes PII, PHI, payment data, credentials, or tokens
- Adding or modifying a query in a multi-tenant codebase, or adding a new repository/DAO
- Changing database, cache, or message-broker connection settings or TLS configuration
- Adding a scheduled job, cron, or worker that touches stored data
- Implementing delete, anonymize, export, or "download my data" functionality
- Changing backup, snapshot, or replication configuration
- Writing seed data, fixtures, test databases, or a database-copy/refresh script
- Adding a form, signup field, analytics event, or SDK that collects data from users

## Classification scheme

Every persisted entity and field gets exactly one classification. When unsure, pick the higher level. The level determines the minimum protections; `.soc2/config.yml` may raise them.

| Level | Definition | Examples | Required protections |
|-------|------------|----------|----------------------|
| **public** | Intended for anyone; disclosure causes no harm | Marketing pages, public API docs, published pricing, open-source code | Integrity controls only (signed releases, change management). No confidentiality controls required. |
| **internal** | For employees and contractors; disclosure is embarrassing, not damaging | Internal runbooks, non-sensitive config, feature flags, aggregated non-identifying metrics, ticket titles | Authentication required (AUTH-01). TLS in transit (DATA-03). Standard at-rest encryption via the platform default (INFRA-04). |
| **confidential** | Customer or business data whose disclosure harms a customer or the company | Customer names, emails, phone numbers, addresses, account settings, invoices, contracts, support ticket bodies, source code, business plans, application logs | Everything above plus: per-object authorization (AUTH-02), tenant scoping (DATA-08), encryption at rest with KMS-managed keys (DATA-02), defined retention (DATA-04), audited bulk export (LOG-01), masked in non-production (DATA-10). |
| **restricted** | Data whose disclosure causes severe harm or legal liability; regulated | Government IDs (SSN, passport), full payment card numbers, bank account numbers, passwords and password hashes, API keys, session and refresh tokens, private keys, health records (PHI), biometrics, precise geolocation history, security audit logs | Everything above plus: field-level encryption or tokenization with a dedicated key (DATA-02), access logged per read (LOG-01), MFA for any human access (AUTH-03), never in logs, URLs, or client storage (DATA-06, LOG-03), shortest defensible retention (DATA-04), separate KMS key with restricted key policy, never present in non-production even masked (use synthetic values). |

Flags are orthogonal to level and drive specific handling: `pii` (any identifier tied to a natural person), `phi` (health information; HIPAA if applicable), `payment` (card or bank data; PCI DSS scope — prefer a tokenization provider so raw PANs never touch your systems). Any field flagged `phi` or `payment` is at least `restricted`; any field flagged `pii` is at least `confidential`.

## Retention defaults

These are defaults. `.soc2/config.yml` `retention:` overrides them per data type; legal, contractual, or regulatory obligations (tax, HIPAA, contracts with customers) take precedence and must be recorded in the config with a reason.

| Data type | Default retention | Action at end of period | Notes |
|-----------|------------------|-------------------------|-------|
| Authentication logs (login success/failure, MFA, token issuance) | 1 year | Delete | Longer if required by customer contracts; keep aggregated counts indefinitely |
| Audit logs (admin actions, permission changes, data access, exports, deletions) | 1 year minimum; 7 years where financial or regulatory | Archive to cold storage, then delete | Must be append-only for the whole period (LOG-02) |
| Application logs (debug, request logs) | 30 days hot, 90 days total | Delete | Must not contain restricted data (LOG-03) |
| User PII (account profile) | Life of account + 30 days after deletion request or account closure | Anonymize or delete; cascade per DATA-05 | Shorter where Privacy is in scope and the subject requests erasure |
| Inactive user accounts | Notify at 12 months inactive; delete at 24 months | Anonymize | Applies to end-user accounts, not employee identities |
| Backups (database, object storage) | 35 days of daily snapshots; 12 monthly snapshots | Expire automatically | Erased records age out of backups within this window; document it in the deletion policy (DATA-05) |
| Support tickets and attachments | 3 years after closure | Delete attachments; anonymize ticket body | Attachments may hold restricted data pasted by customers; scan and redact on ingest where possible |
| Analytics and product telemetry | 14 months raw (identifiable); aggregated indefinitely | Delete raw events; keep aggregates | Raw events must be keyed by a pseudonymous ID, not email |
| Session and refresh tokens | Until expiry or revocation; rows purged 7 days after `expires_at` | Delete | See AUTH-05 |
| Temporary uploads / quarantine | 24 hours | Delete | See API-10 |
| Payment data (tokens from provider) | Life of the payment method | Delete token at provider and locally | Raw PAN retention is zero: never stored |

## Requirements

### DATA-01 — Classify every entity and field

**Rule:** Every persisted entity and field carries a classification (public, internal, confidential, restricted) and boolean flags for PII, PHI, and payment data, declared in code alongside the schema so it is versioned and reviewable.

**TSC:** C1.1, P3.1

**How to implement:**
- Attach classification where the schema is defined so it cannot drift: Prisma `/// @classification confidential @pii` doc comments parsed by a generator; TypeORM/Sequelize column decorator or a sibling `classification` map; SQLAlchemy `Column(..., info={"classification": "restricted", "pii": True})`; Django a custom `Field` subclass or a `Meta.classification` dict; Go struct tags `soc2:"restricted,pii"`; JPA a custom `@Classified(level = RESTRICTED, pii = true)` annotation; Postgres `COMMENT ON COLUMN users.ssn IS 'classification=restricted;pii=true'` as a mirror for DBAs.
- Maintain a generated data inventory (`.soc2/data-inventory.yml` or `build/data-inventory.json`) from those declarations: table, column, classification, flags, datastore, retention key, encryption method. Regenerate in CI and fail if any column is unclassified.
- Cloud tagging: S3 bucket and GCS bucket tags `classification=<level>`; BigQuery/Redshift column-level policy tags; DynamoDB table tags. Tags let you write org policies (e.g. no public ACL on `confidential+`).
- Classification applies to derived stores too: search indexes, caches, analytics warehouses, message queues. A `restricted` field copied into Elasticsearch is still `restricted`.
- Model reviews: any migration adding a column requires the classification in the same PR (CHG-03 checklist).
- Default in the linter is "fail", not "internal".

**Code example:**

```python
# app/models/user.py — SQLAlchemy with classification metadata used by the inventory generator
from sqlalchemy import Column, String, DateTime
from app.db import Base
from app.crypto import EncryptedString  # see DATA-02

def classified(level: str, **flags):
    return {"classification": level, **{k: True for k, v in flags.items() if v}}

class User(Base):
    __tablename__ = "users"
    # SOC2:DATA-01 — every column declares classification and PII/PHI/payment flags
    id            = Column(String, primary_key=True, info=classified("internal"))
    tenant_id     = Column(String, nullable=False, info=classified("internal"))
    email         = Column(String, nullable=False, info=classified("confidential", pii=True))
    display_name  = Column(String, info=classified("confidential", pii=True))
    password_hash = Column(String, info=classified("restricted"))
    tax_id        = Column(EncryptedString, info=classified("restricted", pii=True))
    last_login_at = Column(DateTime(timezone=True), info=classified("internal"))

# scripts/gen_data_inventory.py walks Base.metadata and fails on any column missing `classification`
```

**Common violations:**
- Classification policy exists as a PDF; no field in the codebase references it.
- New columns added by migration with no classification and nobody notices until the audit.
- JSONB/`metadata` columns used as a dumping ground, containing restricted data under an `internal` label.
- Search index, cache, and data warehouse never classified because "it's just a copy."

**Evidence to produce:**
- Model files with classification metadata and the generated inventory (`.soc2/data-inventory.yml`)
- CI job output from the inventory check failing on an unclassified column (a deliberate test PR works as evidence)

### DATA-02 — Encryption at rest; field-level for restricted

**Rule:** Confidential and restricted data is encrypted at rest with KMS-managed keys. Restricted fields (government IDs, card data, credentials, tokens) additionally use field-level encryption or tokenization so a database dump or backup alone does not expose them.

**TSC:** C1.2, CC6.6

**How to implement:**
- Storage-level: enable encryption on every datastore with a customer-managed KMS key (RDS/Aurora, EBS, S3 SSE-KMS, DynamoDB, ElastiCache, Cloud SQL CMEK, GCS CMEK). This is INFRA-04's job; DATA-02 requires you to confirm it for any new store.
- Field-level: envelope encryption. Generate a per-record or per-tenant data encryption key (DEK), encrypt the field with AES-256-GCM (unique 96-bit nonce per encryption, AAD = record ID + column name), and encrypt the DEK with a KMS key encryption key (KEK): AWS KMS `GenerateDataKey`/`Decrypt`, GCP Cloud KMS `encrypt`/`decrypt`, HashiCorp Vault Transit. Store `ciphertext || nonce || tag || wrapped_dek || key_version`. Libraries: AWS Encryption SDK, Google Tink (`AEAD` + `KmsEnvelopeAead`), `@aws-crypto/client-node`, `cryptography` (Python) for the AES-GCM primitive.
- Cache decrypted DEKs briefly in memory (≤ 5 min) to limit KMS calls; never persist them.
- Tokenization for payment data: use the provider's vault (Stripe, Adyen, Braintree, VGS) so raw PANs never reach your systems. Store only the provider token plus last-four and brand.
- Searchable restricted fields: store a blind index (HMAC-SHA-256 with a separate key, truncated) in a sibling column for exact-match lookup; never a plain hash.
- Key rotation: KMS key rotates annually (automatic); re-wrap DEKs lazily on read/write, tracked by `key_version`. Key policy grants `Decrypt` only to the application role (INFRA-03).
- Passwords and tokens are hashed, not encrypted (AUTH-04, AUTH-05); credentials your service uses for others (OAuth tokens to third parties) are encrypted with this mechanism.

**Code example:**

```go
// internal/crypto/envelope.go — AES-256-GCM with a KMS-wrapped data key
package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

type Sealed struct{ Ciphertext, Nonce, WrappedDEK []byte; KeyVersion string }

// SOC2:DATA-02 — envelope encryption: field encrypted with a DEK, DEK wrapped by KMS KEK
func (e *Envelope) Seal(ctx context.Context, plaintext, aad []byte) (*Sealed, error) {
	dek, wrapped, version, err := e.kms.GenerateDataKey(ctx, e.keyID) // AWS KMS GenerateDataKey / GCP Tink KmsEnvelopeAead
	if err != nil {
		return nil, err
	}
	defer zero(dek)
	block, _ := aes.NewCipher(dek)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, aad) // aad = tableName|columnName|recordID, binds ciphertext to its row
	return &Sealed{Ciphertext: ct, Nonce: nonce, WrappedDEK: wrapped, KeyVersion: version}, nil
}
```

**Common violations:**
- "Encrypted at rest" means the EBS volume only; a `pg_dump` in a developer's Downloads folder is plaintext.
- AES-CBC without authentication, ECB mode, a static IV, or a key in an environment variable instead of KMS.
- The same KMS key for everything, with `kms:Decrypt` granted to `*`.
- Restricted fields copied into a search index or analytics warehouse in plaintext.

**Evidence to produce:**
- The envelope encryption module and the migration showing ciphertext columns; KMS key policy and rotation status
- Cloud console or CLI output showing CMEK/SSE-KMS enabled on each datastore listed in the data inventory

### DATA-03 — TLS 1.2+ everywhere, including internal and database traffic

**Rule:** All network transport uses TLS 1.2 or higher with modern cipher suites, including service-to-service traffic, database, cache, and queue connections. Public endpoints send HSTS.

**TSC:** CC6.7

**How to implement:**
- Public edge: TLS 1.2 minimum, prefer 1.3; AWS ALB/CloudFront policy `TLS13-1-2-2021-06` or newer, GCP SSL policy `MODERN` with min TLS 1.2, nginx `ssl_protocols TLSv1.2 TLSv1.3;` with an intermediate-compatibility cipher list (Mozilla SSL config generator). Certificates from ACM, Google-managed certs, or Let's Encrypt with automated renewal; alert 14 days before expiry.
- HSTS `max-age=31536000; includeSubDomains; preload` on every public response (API-06). HTTP → HTTPS redirect only for GET; reject other methods over HTTP.
- Databases: Postgres `sslmode=verify-full` with the CA bundle (`sslrootcert`); MySQL `ssl-mode=VERIFY_IDENTITY`; RDS enforces via parameter `rds.force_ssl=1`; Cloud SQL via the Auth Proxy or `require_ssl`. Redis `rediss://` with `tls` options; Kafka `security.protocol=SSL`/`SASL_SSL`; RabbitMQ `amqps://`. `sslmode=require` without CA verification is not enough — it is MITM-able.
- Internal HTTP: service mesh mTLS with `STRICT` mode (Istio `PeerAuthentication`, Linkerd default), or terminate TLS in each service with certificates from an internal CA (cert-manager, AWS Private CA, GCP CAS). Do not send plaintext HTTP between pods on the assumption that the VPC is private.
- Client code: `NODE_TLS_REJECT_UNAUTHORIZED=0`, `verify=False` (requests), `InsecureSkipVerify: true`, `TrustAllCerts` are never merged; SAST rule for each (SEC-04).
- Go server `tls.Config{MinVersion: tls.VersionTLS12}`; Java `-Djdk.tls.client.protocols=TLSv1.2,TLSv1.3` and `jdk.tls.disabledAlgorithms` covers old suites; Node `tls.DEFAULT_MIN_VERSION = 'TLSv1.2'`.

**Code example:**

```javascript
// db/pool.js — Postgres with full certificate verification
const { Pool } = require('pg');
const fs = require('fs');

// SOC2:DATA-03 — TLS to the database with CA verification and hostname check; no rejectUnauthorized:false
const pool = new Pool({
  host: process.env.PGHOST,
  port: 5432,
  database: process.env.PGDATABASE,
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,       // injected from the secret manager (SEC-01)
  ssl: {
    rejectUnauthorized: true,
    ca: fs.readFileSync('/etc/ssl/certs/rds-global-bundle.pem', 'utf8'),
    minVersion: 'TLSv1.2',
    servername: process.env.PGHOST,        // enables hostname verification (equivalent of sslmode=verify-full)
  },
});

module.exports = { pool };
```

**Common violations:**
- `sslmode=require` or `ssl: { rejectUnauthorized: false }` to make a certificate error go away.
- Redis, Memcached, or Kafka in plaintext because "it's in the private subnet."
- Load balancer terminates TLS and forwards HTTP to instances (acceptable only when the segment is inside a mesh with mTLS or a documented, reviewed exception in `.soc2/EXCEPTIONS.md`).
- TLS 1.0/1.1 still enabled on an ALB listener policy from 2019; expired internal certificates ignored with skip-verify.

**Evidence to produce:**
- Load balancer TLS policy export, `ssl-labs`/`testssl.sh` report for public hostnames, and mesh `PeerAuthentication` manifests
- Database connection configuration showing `verify-full`/`VERIFY_IDENTITY`; RDS `rds.force_ssl` parameter

### DATA-04 — Retention defined in config and enforced by jobs

**Rule:** Each data type has a retention period declared in `.soc2/config.yml` (falling back to the defaults above), and a scheduled job enforces it by deleting or anonymizing data past its period. Retention is not enforced by hand.

**TSC:** C1.3, P4.1

**How to implement:**
- Config first: `.soc2/config.yml` `retention:` map of data type → `{ period: "365d", action: "delete|anonymize|archive", reason: "..." }`. Code reads this config; no retention values hard-coded in jobs.
- Every table with a retention policy has a timestamp the job can use (`created_at`, `closed_at`, `expires_at`, `deleted_at`) and an index on it.
- Jobs: a scheduled worker per data type (cron in Kubernetes, EventBridge Scheduler + Lambda/ECS task, Cloud Scheduler + Cloud Run job, Celery beat, `node-cron`, Spring `@Scheduled`), batched deletes (`DELETE ... WHERE id IN (SELECT ... LIMIT 1000)`) to avoid long locks, with metrics for rows affected and an alert if a job has not run in 2× its interval.
- Use native TTLs where available: S3 lifecycle rules, GCS object lifecycle, DynamoDB TTL attribute, MongoDB TTL index, Redis `EXPIRE`, Elasticsearch ILM, CloudWatch/Cloud Logging retention settings, Postgres partition dropping for high-volume logs. Native TTL still has to be recorded in config and inventory.
- Legal hold: a `legal_hold` flag or table that the job respects; holds are audited when set and cleared.
- Anonymize when the record is needed for integrity (invoices, ledger): replace PII with irreversible placeholders (`deleted-user-<hash>`), keep the foreign key.
- Log every job run to the audit log with data type, cutoff timestamp, and row count (LOG-01 "data deletions").

**Code example:**

```python
# jobs/retention.py — runs daily from the scheduler; periods come from .soc2/config.yml
import datetime as dt
from app.config import soc2_config
from app.db import session
from app.audit import audit

POLICIES = {
    # data_type: (table, timestamp column, action)
    "auth_logs":       ("auth_events", "created_at", "delete"),
    "support_tickets": ("tickets", "closed_at", "anonymize"),
    "temp_uploads":    ("uploads", "created_at", "delete"),
}

def run():
    for data_type, (table, ts_col, action) in POLICIES.items():
        period = soc2_config.retention_period(data_type)        # e.g. timedelta(days=365), from config
        cutoff = dt.datetime.now(dt.UTC) - period
        # SOC2:DATA-04 — retention enforced by scheduled job; period sourced from config, legal holds respected
        total = 0
        while True:
            n = session.execute(RETENTION_SQL[action].format(table=table, ts_col=ts_col),
                                {"cutoff": cutoff, "batch": 1000}).rowcount
            session.commit(); total += n
            if n < 1000: break
        audit.emit("data.retention.enforced", {"data_type": data_type, "action": action,
                                              "cutoff": cutoff.isoformat(), "rows": total})
```

**Common violations:**
- Retention policy says 1 year; the table has 6 years of rows and no job exists.
- Job exists but was disabled after a slow-query incident and never re-enabled; nobody alerts on it.
- S3 buckets with no lifecycle rule; CloudWatch log groups set to "Never expire."
- Retention values hard-coded in five different jobs, disagreeing with the policy document.

**Evidence to produce:**
- `.soc2/config.yml` retention block, the job source, and its schedule definition (`k8s/cronjobs/retention.yaml`, EventBridge rule)
- Audit log query for `data.retention.enforced` over the past 90 days; lifecycle rule exports for buckets and log groups

### DATA-05 — Complete deletion and subject erasure

**Rule:** Deleting a record removes it from the primary store and cascades to derived data (caches, search indexes, analytics, file storage, third-party processors) and ages out of backups per the documented schedule. Where Privacy is in scope, a subject-erasure flow exists, is audited, and completes within the committed window.

**TSC:** C1.3, P4.2

**How to implement:**
- Build a deletion map from the data inventory (DATA-01): for each subject-linked entity, list every place it is replicated — Postgres tables (use `ON DELETE CASCADE` or explicit ordered deletes), Redis keys, Elasticsearch/OpenSearch documents, S3/GCS objects by prefix, warehouse tables (BigQuery `DELETE`, Snowflake), CDN caches, and third parties (Stripe customer, SendGrid contact, Intercom user, Segment `delete` API). The map lives in code (`app/deletion/map.py`) and the CI inventory check fails if a new PII table is missing from it.
- Erasure is an asynchronous, idempotent, resumable job: enqueue `erasure(subject_id)`, execute each step, record per-step status, retry failures, and emit `data.erasure.completed` with the list of stores touched. Expose status to the requester.
- Soft delete is acceptable as a first step (grace period for accidental deletion, default 30 days), but the hard delete must actually run afterwards and soft-deleted rows must be excluded from every query (a default scope or RLS predicate).
- Backups: document that backups expire within N days (retention table above) and that restored backups re-run pending erasures (keep an `erasure_ledger` of subject IDs outside the backed-up dataset, or replay from the audit log).
- Where deletion would break integrity (invoices, ledger), anonymize instead and record that decision in the map.
- Verification: a post-erasure check that queries each store for the subject ID and asserts zero results; run it as part of the job and keep the result as evidence.
- Privacy in scope: intake via authenticated self-service or verified support request, identity verification before erasure, SLA (30 days GDPR, 45 days CCPA), and a record of the request, verification, and completion.

**Code example:**

```go
// internal/erasure/runner.go
package erasure

// SOC2:DATA-05 — erasure cascades across every store in the deletion map; each step audited and verified
var steps = []Step{
	{"postgres.user_rows", pg.DeleteUserGraph},        // ordered deletes / ON DELETE CASCADE
	{"redis.sessions_cache", cache.PurgeUser},
	{"opensearch.user_docs", search.DeleteByUserID},
	{"s3.user_uploads", objects.DeletePrefix},         // tenant/user/ prefix
	{"bigquery.events", warehouse.DeleteBySubject},
	{"stripe.customer", billing.DeleteCustomer},
	{"sendgrid.contact", email.DeleteContact},
}

func (r *Runner) Run(ctx context.Context, req ErasureRequest) error {
	for _, s := range steps {
		if r.ledger.Done(req.ID, s.Name) { continue }               // resumable
		if err := s.Fn(ctx, req.SubjectID); err != nil {
			r.audit.Emit(ctx, "data.erasure.step_failed", req.ID, s.Name, err); return err // retried by queue
		}
		r.ledger.MarkDone(req.ID, s.Name)
	}
	if left := r.verify(ctx, req.SubjectID); len(left) > 0 { return fmt.Errorf("residue in %v", left) }
	r.audit.Emit(ctx, "data.erasure.completed", req.ID, len(steps))
	return nil
}
```

**Common violations:**
- `deleted_at` set, but the row remains forever and still appears in search results, exports, and the warehouse.
- Primary DB row deleted; Elasticsearch, Redis, S3 attachments, and Stripe customer remain.
- Third-party processors (email, analytics, support desk) never included in erasure.
- No verification step; the team cannot prove to an auditor or a data subject that erasure actually happened.

**Evidence to produce:**
- The deletion map and erasure runner, plus the CI check tying them to the data inventory
- Audit log entries for a sample `data.erasure.completed` with its verification result; the DSAR request register (where Privacy is in scope)

### DATA-06 — Data minimization; no PII or secrets in URLs or client storage

**Rule:** Collect and store only fields with a documented purpose. PII, secrets, and tokens never appear in URLs, query strings, referrers, browser storage (`localStorage`, `sessionStorage`, non-HttpOnly cookies), or client-side logs.

**TSC:** P3.1, CC6.7

**How to implement:**
- Purpose per field: the classification metadata (DATA-01) gets a `purpose` entry for any `pii` field (`"billing"`, `"account_recovery"`, `"fraud_prevention"`). A PR adding a PII field without a purpose fails the inventory check. Optional fields without a purpose are removed, not stored "in case."
- Identifiers in paths, not PII: `/users/{uuid}` not `/users/{email}`; tokens and codes in `POST` bodies or `Authorization` headers, never `?token=`. If a link must carry a token (password reset, magic link, unsubscribe), make it single-use and short-lived, set `Referrer-Policy: no-referrer` on the landing page, and strip it from the URL on load (`history.replaceState`).
- Analytics: never send email, name, or free-text fields to third-party analytics; key events by a pseudonymous ID. Review `track()`/`identify()` calls and SDK auto-capture settings; disable session replay on pages with restricted data or mask inputs.
- Browser storage: session state in `HttpOnly` cookies (AUTH-05) or in memory; never `localStorage.setItem('token', ...)`. Lint rule (ESLint `no-restricted-syntax`/`no-restricted-properties` on `localStorage.setItem`) in the frontend.
- Server logs: full URLs are logged by default by most servers and load balancers — another reason PII must not be in the query string. Configure the access log format to drop query strings on sensitive paths, and apply LOG-03 redaction.
- Forms: do not pre-fill or echo restricted values (SSN, card numbers) back to the browser; use masked display (`***-**-1234`).
- Mobile: no PII in push notification payloads, crash reports, or analytics breadcrumbs.

**Code example:**

```javascript
// routes/passwordReset.js — token via POST body, not query string; landing page strips it from the URL
const express = require('express');
const router = express.Router();

// SOC2:DATA-06 — reset token accepted only in the POST body; email lookup by opaque id, never PII in URL
router.post('/password/reset/confirm', async (req, res) => {
  const { token, newPassword } = ResetSchema.parse(req.body);     // schema from API-01
  const record = await resetTokens.consume(hash(token));          // single-use, 15-minute TTL
  if (!record) return res.status(400).json({ error: 'invalid_or_expired' });
  await passwords.set(record.userId, newPassword);                // AUTH-04
  res.status(204).end();
});

// GET /password/reset?t=... renders a page that immediately moves the token out of the URL:
router.get('/password/reset', (req, res) => {
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.render('reset', { inlineScript: `
    const t = new URLSearchParams(location.search).get('t');
    history.replaceState(null, '', location.pathname);   // keep it out of history, referrers, and logs
    window.__resetToken = t;                              // memory only; submitted in the POST body
  ` });
});
```

**Common violations:**
- `GET /api/users?email=jane@example.com` and `?ssn=` appearing in load balancer access logs.
- JWT stored in `localStorage`; exposed by any XSS.
- Signup form collecting date of birth, phone, and address "for later" with no feature using them.
- Session replay tools recording password and card fields; analytics `identify(email)` calls.

**Evidence to produce:**
- Data inventory with `purpose` per PII field; ESLint config forbidding `localStorage` token storage
- Access log sample from the load balancer showing no PII in paths/queries; analytics SDK config with masking enabled

### DATA-07 — Backups encrypted, restricted, and restore-tested

**Rule:** Backups are encrypted with KMS-managed keys, readable only by a backup role, taken on a schedule that meets a documented RPO, and restore-tested on a schedule that proves the documented RTO.

**TSC:** A1.2, A1.3

**How to implement:**
- Managed backups: RDS/Aurora automated backups plus point-in-time recovery (PITR), Cloud SQL automated backups with PITR, DynamoDB PITR, S3 versioning plus cross-region replication for critical buckets, GCS versioning/turbo replication. Set retention to match the retention table (35 days default).
- Encryption: snapshots inherit the CMEK of the source; cross-region copies need a key in the target region. Logical dumps (`pg_dump`) written to S3 with SSE-KMS under a dedicated backup key.
- Access: a `backup-operator` IAM role is the only principal with `rds:RestoreDBInstanceFromDBSnapshot`, `s3:GetObject` on the backup bucket, `kms:Decrypt` on the backup key. Human access requires MFA and is logged (CloudTrail/Cloud Audit Logs). Enable S3 Object Lock or bucket policies denying delete for immutability against ransomware.
- Copy snapshots to a separate account/project (AWS Backup vault with cross-account copy, GCP separate project) so a compromised production account cannot delete them.
- RPO/RTO: write them in `.soc2/config.yml` or the DR runbook (e.g. RPO 15 min via PITR, RTO 4 h). Backup frequency must satisfy RPO.
- Restore test: at least quarterly (monthly for critical systems), automated where possible — restore the latest snapshot into an isolated environment, run integrity checks (row counts, checksums, application smoke test), measure elapsed time against RTO, record the result, and destroy the restored instance. AWS Backup restore testing plans can automate this.
- Alert on backup job failure and on "no successful backup in RPO × 2."

**Code example:**

```python
# scripts/restore_test.py — run monthly by CI; produces evidence for DATA-07
import time, boto3, datetime as dt
from app.audit import audit

rds = boto3.client("rds")
RTO = dt.timedelta(hours=4)

def run(source_db: str):
    snap = latest_snapshot(source_db)
    started = time.monotonic()
    # SOC2:DATA-07 — restore latest encrypted snapshot into an isolated instance and verify
    rds.restore_db_instance_from_db_snapshot(
        DBInstanceIdentifier="restore-test", DBSnapshotIdentifier=snap["DBSnapshotIdentifier"],
        DBSubnetGroupName="isolated-restore", PubliclyAccessible=False,
        VpcSecurityGroupIds=["sg-restore-test-no-ingress"], Tags=[{"Key": "purpose", "Value": "restore-test"}])
    wait_available("restore-test")
    checks = {"encrypted": snap["Encrypted"], "row_counts_match": compare_row_counts("restore-test", source_db),
              "app_smoke": smoke_test("restore-test")}
    elapsed = dt.timedelta(seconds=time.monotonic() - started)
    audit.emit("backup.restore_test", {"snapshot": snap["DBSnapshotIdentifier"], "checks": checks,
                                       "elapsed_s": elapsed.total_seconds(), "rto_met": elapsed <= RTO})
    rds.delete_db_instance(DBInstanceIdentifier="restore-test", SkipFinalSnapshot=True)
    assert all(checks.values()) and elapsed <= RTO
```

**Common violations:**
- Backups configured but never restored; the first restore attempt happens during an incident and fails.
- Snapshots in the same account with the same admin role that could be compromised or deleted by ransomware.
- Nightly `pg_dump` to an unencrypted bucket with public-read on a misconfigured prefix.
- RPO and RTO never written down, so there is nothing to test against.

**Evidence to produce:**
- Backup configuration (Terraform for RDS backup retention/PITR, AWS Backup plan, lifecycle) and the backup-role IAM policy
- Restore test job source plus its run history and `backup.restore_test` audit entries; the DR runbook stating RPO/RTO

### DATA-08 — Tenant scoping on every query

**Rule:** In a multi-tenant system, every query is scoped to the caller's tenant by a mechanism that cannot be forgotten: Postgres row-level security, a mandatory repository-layer scope injected from the authenticated context, or per-tenant schemas/databases.

**TSC:** CC6.1, C1.2

**How to implement:**
- Postgres RLS (strongest): `ALTER TABLE t ENABLE ROW LEVEL SECURITY; ALTER TABLE t FORCE ROW LEVEL SECURITY;` and a policy `USING (tenant_id = current_setting('app.tenant_id')::uuid)`. The application role must not be the table owner or `BYPASSRLS`. Middleware sets `SET LOCAL app.tenant_id = '<id>'` inside each transaction from the verified principal (AUTH-02). Every tenant-owned table has a `tenant_id NOT NULL` column and a composite index `(tenant_id, ...)`.
- Repository scoping (when RLS is unavailable): a `TenantScopedRepository` base that takes `tenant_id` from request context (`AsyncLocalStorage`, `contextvars`, `context.Context`, `ThreadLocal`/`RequestScope`) and appends `WHERE tenant_id = ?` to every read, sets it on every insert, and refuses to run without it. Prisma client extension `$allOperations` adding the filter; SQLAlchemy `do_orm_execute` event with `with_loader_criteria`; Django a custom `Manager` that requires the tenant from context; GORM scope; Hibernate `@Filter`/`@TenantId` (Hibernate 6.x); Spring Data specification. Ban the raw client outside the repository layer with a lint rule.
- Per-tenant schema or database: strongest isolation, highest ops cost; use for regulated or enterprise tenants. Connection routing by tenant from the principal, never from a header.
- Cross-tenant admin operations use an explicit, audited `withTenant(id)`/`SET app.tenant_id` with a `reason`, never a "bypass" flag on the regular client.
- Caches and search: include `tenant_id` in every cache key and search query filter; object storage keys are prefixed by tenant.
- Tests: for each tenant-scoped table, a test that tenant A cannot read, update, or delete tenant B's row via any endpoint or repository method; and a test that an insert without tenant context fails.

**Code example:**

```sql
-- migrations/0042_rls_invoices.sql
-- SOC2:DATA-08 — row-level security forces tenant scoping regardless of application code paths
ALTER TABLE invoices ADD COLUMN IF NOT EXISTS tenant_id uuid NOT NULL;
CREATE INDEX IF NOT EXISTS invoices_tenant_idx ON invoices (tenant_id, created_at DESC);

ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoices FORCE ROW LEVEL SECURITY;   -- applies to the table owner too

CREATE POLICY invoices_tenant_isolation ON invoices
  USING      (tenant_id = current_setting('app.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- app role: DML only, no BYPASSRLS, not the owner
GRANT SELECT, INSERT, UPDATE, DELETE ON invoices TO app_rw;
```

```javascript
// db/tenantTx.js — every request runs inside a transaction that sets the tenant from the verified principal
async function withTenant(principal, fn) {
  return pool.transaction(async (trx) => {
    // SOC2:DATA-08 — tenant_id comes from the session, never from the request; SET LOCAL scopes to this tx
    await trx.raw('SET LOCAL app.tenant_id = ?', [principal.tenantId]);
    return fn(trx);
  });
}
```

**Common violations:**
- `WHERE tenant_id = ?` present in most queries, missing in the one added last week (report, export, admin search).
- `tenant_id` read from `X-Tenant-Id` header or a query parameter.
- RLS enabled but the app connects as the table owner without `FORCE`, so policies are skipped.
- Cache keys like `user:123` shared across tenants; search queries without a tenant filter.

**Evidence to produce:**
- RLS migration and policy list (`\d+ invoices` or `pg_policies` query) or the scoped repository base class and the lint rule banning the raw client
- Cross-tenant isolation test suite in CI (`test/tenancy/*`)

### DATA-09 — Data export and subject access requests

**Rule:** Where Privacy is in scope, a subject can obtain a complete, machine-readable export of their personal data, and the organization can fulfil a data subject access request (DSAR) within the committed window. Exports are authenticated, rate-limited, and audited.

**TSC:** P5.1

**How to implement:**
- Reuse the deletion map (DATA-05): the same list of stores that hold a subject's data is the list the export must cover. Generate the export from that map so new PII stores are automatically included.
- Format: JSON (and optionally CSV per entity) in a zip; include a `manifest.json` with generation timestamp, subject ID, and the list of categories. Exclude other people's PII (e.g. messages from other users need redaction or partial inclusion), internal notes about the subject only where required by law — decide this with legal and record it.
- Delivery: asynchronous job; store the archive in a private bucket with envelope encryption (DATA-02); notify the subject; deliver via a signed URL valid ≤ 24 h that requires re-authentication (and MFA if enrolled); delete the archive after 7 days.
- Rate limit exports (one in-flight per subject; API-04) and treat each as an audited `data.export` event with actor, subject, categories, and delivery time (LOG-01).
- Identity verification for requests that arrive via support rather than self-service: verify against the account (login plus MFA challenge, or a verification link to the registered email) before generating.
- Tenant-level (B2B) export: an admin export of all tenant data uses the same machinery but requires an admin role with MFA, is scoped by DATA-08, and is logged as a bulk export.
- Register: keep a DSAR register (ticket queue with a dedicated type) recording receipt date, verification, completion date, and SLA status (30 days GDPR / 45 days CCPA).

**Code example:**

```python
# jobs/subject_export.py
import json, io, zipfile, datetime as dt
from app.deletion.map import SUBJECT_STORES   # shared with DATA-05 erasure
from app.storage import private_bucket
from app.audit import audit

def export_subject(request_id: str, subject_id: str, requested_by: str) -> str:
    # SOC2:DATA-09 — export built from the same store map as erasure, encrypted at rest, audited
    buf = io.BytesIO()
    manifest = {"subject_id": subject_id, "generated_at": dt.datetime.now(dt.UTC).isoformat(), "categories": []}
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for store in SUBJECT_STORES:
            records = store.export(subject_id)         # each store implements export(); redaction inside
            zf.writestr(f"{store.name}.json", json.dumps(records, default=str, indent=2))
            manifest["categories"].append({"name": store.name, "count": len(records)})
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))
    key = f"exports/{subject_id}/{request_id}.zip"
    private_bucket.put(key, buf.getvalue(), sse_kms=True, expires_days=7)
    audit.emit("data.export", {"request_id": request_id, "subject": subject_id, "actor": requested_by,
                               "categories": [c["name"] for c in manifest["categories"]]})
    return private_bucket.signed_url(key, ttl=dt.timedelta(hours=24))
```

**Common violations:**
- Export covers the `users` table only; uploads, support tickets, and analytics events are missing.
- Export delivered as an email attachment or a permanent public link.
- No verification of the requester; a support agent generates exports on request from any sender.
- No register, so the organization cannot show how many DSARs were received or whether SLAs were met.

**Evidence to produce:**
- Export job source and its shared store map; bucket policy for the exports prefix with lifecycle expiry
- DSAR register export showing request dates and completion times; `data.export` audit log sample

### DATA-10 — Synthetic or masked data in non-production

**Rule:** Development, test, staging, and CI environments use synthetic data or irreversibly masked copies. Production data (including backups, dumps, and exports) is never copied to non-production, and the pipeline that would allow it does not exist or is blocked.

**TSC:** C1.2, CC6.1

**How to implement:**
- Seed and fixtures: generate synthetic records with `@faker-js/faker`, `Faker` (Python), `go-faker/faker`, `datafaker` (Java), or `factory_boy`/`FactoryBot`-style factories. Fixture files are checked in and reviewed; no fixture may contain a real email domain you own or a real customer name (lint with a regex for your domains and a small denylist).
- If a production-shaped dataset is genuinely needed (performance testing, migration rehearsal), produce it through an automated masking pipeline that runs inside the production boundary: restore a snapshot into an isolated instance, run masking (replace PII with fakes preserving format and referential integrity, null out restricted columns, re-hash identifiers with a per-run salt), verify with a scan for known production values, then publish the masked dump to a non-production bucket. Tools: `pg_anonymizer`/`PostgreSQL Anonymizer` extension, `greenmask`, `pynonymizer`, AWS DMS with transformation rules, Tonic, Delphix, Gretel. Restricted fields are replaced with synthetic values, never masked-in-place derivations.
- Block the direct path: no non-production IAM principal has `s3:GetObject` on production backup buckets or `rds:CopyDBSnapshot` from production; production secrets are not resolvable from non-production (separate secret manager paths/accounts); network policy denies non-prod → prod database ports. Use separate cloud accounts/projects per environment (INFRA-02).
- Enforce in CI: a job that scans the test database and fixtures for production markers (real customer IDs, your production email domains, Luhn-valid card numbers, SSN patterns). Fail on any hit.
- Staging with real third parties: use sandbox/test modes (Stripe test keys, SendGrid sandbox, Twilio test credentials) so real emails and charges cannot leak.
- Logs and error trackers from production must not be mirrored to non-production tools with wider access.
- Record the exception if any environment legitimately holds production data (e.g. a customer-facing "demo" with real data) in `.soc2/EXCEPTIONS.md` with compensating controls (EVD-03).

**Code example:**

```go
// cmd/seed/main.go — synthetic seed data for local, CI, and staging
package main

import (
	"fmt"
	"github.com/go-faker/faker/v4"
)

// SOC2:DATA-10 — non-production data is synthetic; real customer data never enters this path
func seedUsers(db *DB, tenantID string, n int) error {
	for i := 0; i < n; i++ {
		u := User{
			TenantID:     tenantID,
			Email:        fmt.Sprintf("user%03d@example.test", i), // .test TLD: never deliverable
			DisplayName:  faker.Name(),
			PasswordHash: mustHash("Local-Dev-Password-123!"),   // argon2id, AUTH-04
			TaxID:        seal(faker.CCNumber()[:9]),           // synthetic, still encrypted, DATA-02
		}
		if err := db.Insert(&u); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	if env := os.Getenv("APP_ENV"); env == "production" {
		panic("seed refuses to run in production") // guard against misuse in the other direction
	}
	// ...
}
```

**Common violations:**
- "Refresh staging from prod" script run monthly by an engineer with a `pg_dump | psql` pipeline and no masking.
- Masking that replaces names but leaves emails, free-text notes, and JSONB blobs with real PII.
- A shared staging environment that every contractor can reach, holding a three-year-old production copy nobody remembers.
- Test fixtures copied from a real support ticket, including a customer's real address.

**Evidence to produce:**
- Seed/fixture source and the CI scan for production markers; masking pipeline definition if one exists
- IAM policy and network policy proving non-production cannot read production backups or connect to production databases

### DATA-11 — Processing completeness and accuracy checks

**Rule:** Where Processing Integrity is in scope, every data pipeline, batch job, and multi-stage processing flow verifies completeness and accuracy: record counts or checksums are reconciled between input and output, failed records are quarantined and reported rather than silently dropped, and each run logs totals and outcome.

**TSC:** PI1.1, PI1.2, PI1.3

**How to implement:**
- Compute an input count (and a hash or sum of a key numeric column for financial data) at ingest; compare with output plus quarantined counts at the end of the run. A mismatch fails the run and alerts (LOG-05).
- Validate every record against a schema at the pipeline boundary (API-01 applies to pipelines too). Route invalid records to a dead-letter queue or quarantine table with the validation error, never `continue`.
- Make stages idempotent (API-08) so a retry does not double-count; key on a stable record ID plus run ID.
- Enforce timeliness: a run that exceeds its SLA emits an alert; downstream consumers check a freshness watermark.
- Write a `pipeline.run` audit event with input, output, quarantined counts, duration, and status.

**Code example:**

```python
# jobs/settlements.py
def run_settlement(batch_id: str) -> RunResult:
    rows = load_batch(batch_id)
    expected_count, expected_sum = len(rows), sum(r.amount_cents for r in rows)
    ok, quarantined = [], []
    for r in rows:
        try:
            ok.append(SettlementRecord.model_validate(r))       # schema at the boundary
        except ValidationError as e:
            quarantined.append(Quarantined(record_id=r.id, error=str(e)))
    written = write_settlements(ok, run_id=batch_id)             # idempotent on (record_id, run_id)
    # SOC2:DATA-11 reconcile input vs output + quarantine; fail loudly on mismatch
    if written + len(quarantined) != expected_count or sum(x.amount_cents for x in ok) != expected_sum - sum(q.amount_cents for q in quarantined):
        audit.log(event_type="pipeline.run", target_id=batch_id, outcome="failure", metadata={"expected": expected_count, "written": written, "quarantined": len(quarantined)})
        raise ReconciliationError(batch_id)
    audit.log(event_type="pipeline.run", target_id=batch_id, outcome="success", metadata={"expected": expected_count, "written": written, "quarantined": len(quarantined)})
    return RunResult(written, quarantined)
```

**Common violations:**
- `except Exception: continue` inside the processing loop.
- Output count never compared with input count; partial failures reported as success.
- Retried job reprocesses the same records and double-posts.

**Evidence to produce:**
- Audit log query for `pipeline.run` events showing counts per run.
- Dead-letter queue or quarantine table with error reasons; alert rule for reconciliation failures.

### DATA-12 — Consent capture and consent checks

**Rule:** Where Privacy is in scope, consent is captured with purpose, privacy-policy version, timestamp, and source, stored as an auditable record, and checked in code before any processing that depends on it. Withdrawal takes effect immediately and propagates to downstream processors.

**TSC:** P2.1, P3.1, P4.1

**How to implement:**
- Model consent as its own table: `subject_id, purpose, policy_version, granted (bool), granted_at, withdrawn_at, source (web form, API, import), evidence (form ID or request ID)`. Never a single boolean on the user row.
- Gate processing with a helper (`requireConsent(subject, purpose)`) called at the entry point of any purpose-specific processing (marketing, analytics, profiling, third-party sharing). Missing consent is a hard stop, not a warning.
- Re-prompt when the policy version changes; treat old-version consent as expired for new purposes.
- On withdrawal, emit a `consent.withdrawn` audit event and enqueue propagation to downstream systems (email provider, analytics, CRM); record completion.
- Expose consent state in the DSAR export (DATA-09).

**Code example:**

```go
// internal/privacy/consent.go
// SOC2:DATA-12 processing for a purpose is blocked unless a current, unwithdrawn consent record exists
func (s *Service) RequireConsent(ctx context.Context, subjectID, purpose string) error {
	c, err := s.repo.LatestConsent(ctx, subjectID, purpose)
	if err != nil {
		return err
	}
	if c == nil || !c.Granted || c.WithdrawnAt != nil || c.PolicyVersion != s.currentPolicyVersion {
		s.audit.Log(ctx, audit.Event{Type: "consent.check", Outcome: "denied", TargetID: subjectID, Metadata: map[string]any{"purpose": purpose}})
		return ErrConsentRequired
	}
	return nil
}
```

**Common violations:**
- Marketing email sent to every user because `marketing_opt_in` defaulted to true.
- Consent stored as a flag with no timestamp or policy version, so it cannot be proven.
- Withdrawal updates the app database but the email provider keeps sending.

**Evidence to produce:**
- Consent table schema and a sample record; call sites of the consent check for each purpose.
- Audit log query for `consent.granted` / `consent.withdrawn` and propagation completion.

## Review checklist

- [ ] DATA-01: Does every new or changed field/table declare a classification (public/internal/confidential/restricted) plus PII/PHI/payment flags in code, and does the generated inventory include it?
- [ ] DATA-02: Is any new datastore encrypted at rest with a KMS-managed key, and does every restricted field use envelope encryption (AES-256-GCM with a KMS-wrapped DEK) or a tokenization provider?
- [ ] DATA-03: Do all new connections (HTTP, database, cache, queue) enforce TLS 1.2+ with CA and hostname verification, with no skip-verify flags, and do public responses send HSTS?
- [ ] DATA-04: Does each new data type have a retention entry in `.soc2/config.yml` and a scheduled job or native TTL that enforces it, with runs written to the audit log?
- [ ] DATA-05: Is every new store holding subject data added to the deletion map, and does deletion cascade to caches, indexes, object storage, and third parties with a verification step?
- [ ] DATA-06: Does every new PII field have a documented purpose, and is PII or any token absent from URLs, query strings, browser storage, and analytics calls?
- [ ] DATA-07: Are backups for any new datastore encrypted, restricted to a backup role in a separate account, scheduled to meet the documented RPO, and covered by the restore test?
- [ ] DATA-08: Is every new tenant-owned table covered by RLS or the mandatory scoped repository, with `tenant_id` derived from the verified principal and a cross-tenant isolation test added?
- [ ] DATA-09: Where Privacy is in scope, does the export flow cover every store in the map, deliver via a short-lived signed URL after re-authentication, and log a `data.export` audit event?
- [ ] DATA-10: Are seeds and fixtures synthetic, does CI scan for production markers, and is there no IAM or network path for non-production to read production data?
- [ ] DATA-11: If Processing Integrity is in scope, does every new pipeline reconcile input and output counts, quarantine invalid records with reasons, and log run totals?
- [ ] DATA-12: If Privacy is in scope, is every purpose-specific processing path gated by a consent check against a versioned, timestamped consent record, and does withdrawal propagate downstream?
