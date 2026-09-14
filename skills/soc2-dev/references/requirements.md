# SOC 2 Engineering Requirement Registry

This is the canonical list of code-level and repo-level requirements the `soc2-dev`
skill enforces. Every other reference file, the scanner, the PR template, and
`CONTROL_MAP.md` refer to these IDs. Do not invent new IDs elsewhere; add them here.

Each requirement maps to one or more AICPA Trust Service Criteria (TSC). Security
(CC1-CC9) is always in scope. Availability (A1), Confidentiality (C1), Processing
Integrity (PI1), and Privacy (P1-P8) apply only if enabled in `.soc2/config.yml`.

Severity: **must** = audit finding if missing; **should** = expected for a mature
program; **may** = recommended.

## AUTH — Authentication and authorization (detail: `auth-and-access.md`)

| ID | Requirement | TSC | Severity |
|----|-------------|-----|----------|
| AUTH-01 | Every non-public endpoint requires authentication. Deny by default; public routes are explicitly allow-listed. | CC6.1 | must |
| AUTH-02 | Authorization is enforced server-side per request and per object (RBAC/ABAC plus ownership or tenant checks). Never trust client-supplied roles or IDs. | CC6.1, CC6.3 | must |
| AUTH-03 | MFA is required for admin and privileged accounts, and available to all users. | CC6.1 | must |
| AUTH-04 | Passwords (when auth is managed in-app, not by an external IdP): minimum length and complexity rules from config (default 12 chars, no composition rules, breached-password list check), optional maximum age from config (default none, per NIST 800-63B), stored with argon2id or bcrypt (cost ≥ 12). Never logged or emailed. | CC6.1 | must |
| AUTH-05 | Sessions and tokens: short-lived access tokens (≤ 1 h), rotating refresh tokens, server-side revocation, idle timeout, secure cookie flags. | CC6.1 | must |
| AUTH-06 | Brute-force protection on login, password reset, MFA, and token endpoints (rate limit plus lockout or backoff). | CC6.1, CC6.6 | must |
| AUTH-07 | User provisioning and deprovisioning are auditable operations. Deactivation is immediate and revokes all sessions and tokens. | CC6.2, CC6.3 | must |
| AUTH-08 | Service-to-service calls authenticate with short-lived credentials (mTLS, workload identity, signed JWT). No shared static API keys between services. | CC6.1, CC6.6 | should |
| AUTH-09 | Roles follow least privilege. Admin capabilities are separate roles, not flags on regular users. No code path runs as superuser by default. | CC6.3 | must |
| AUTH-10 | The system can export a current list of users, roles, and last-login dates to support quarterly access reviews. | CC6.2, CC6.3 | should |

## API — Endpoint and input handling (detail: `api-endpoint-checklist.md`)

| ID | Requirement | TSC | Severity |
|----|-------------|-----|----------|
| API-01 | All inputs (body, query, path, headers, files) are validated against a schema before use. Reject unknown fields. | CC6.1, PI1.1 | must |
| API-02 | Output is encoded for its context. Responses set an explicit content type. Untrusted data is never reflected raw into HTML, headers, or redirects. | CC6.1 | must |
| API-03 | Database, shell, LDAP, and template calls use parameterization or a safe API. No string-built queries or commands. | CC6.1, CC7.1 | must |
| API-04 | Public endpoints have rate limits and request body size limits. | CC6.6, A1.1 | must |
| API-05 | Error responses are generic (no stack traces, SQL, or internal paths) and carry a correlation ID that links to server logs. | CC6.1, CC7.2 | must |
| API-06 | Security headers set (HSTS, CSP, X-Content-Type-Options, frame options). CORS uses an explicit origin allow-list. CSRF protection for cookie-based sessions. | CC6.6 | must |
| API-07 | Each route declares its auth requirement, data classification, and owning team (via decorator, annotation, route metadata, or a routes manifest). | CC5.3 | should |
| API-08 | Mutating endpoints that may be retried are idempotent (idempotency key) and wrap multi-step writes in a transaction. | PI1.1, PI1.2 | should |
| API-09 | APIs are versioned. Breaking changes and deprecations are communicated to consumers with a timeline. | CC2.3, CC8.1 | should |
| API-10 | File uploads validate type and size, are stored outside the web root or in object storage with private ACLs, and are scanned or quarantined. | CC6.1, CC6.8 | must |
| API-11 | Inbound webhooks and third-party callbacks verify a signature (HMAC or provider SDK) with a constant-time comparison, reject stale timestamps (replay window ≤ 5 min), and are idempotent on the provider's event ID. Unsigned callbacks are rejected before any processing. | CC6.6, CC6.1 | must |

## DATA — Data classification, protection, and lifecycle (detail: `data-handling.md`)

| ID | Requirement | TSC | Severity |
|----|-------------|-----|----------|
| DATA-01 | Every persisted entity and field carries a classification (public, internal, confidential, restricted) and flags for PII, PHI, or payment data. | C1.1, P3.1 | must |
| DATA-02 | Confidential and restricted data is encrypted at rest. Restricted fields (government IDs, card data, credentials, tokens) use field-level encryption or tokenization. | C1.2, CC6.6 | must |
| DATA-03 | All network transport uses TLS 1.2 or higher, including internal service traffic and database connections. HSTS on public endpoints. | CC6.7 | must |
| DATA-04 | Retention periods are defined per data type in config and enforced by scheduled jobs. | C1.3, P4.1 | must |
| DATA-05 | Deletion is complete: cascades to derived data, caches, search indexes, and backups per schedule. A subject-erasure flow exists where Privacy is in scope. | C1.3, P4.2 | must |
| DATA-06 | Data minimization: collect only fields with a documented purpose. No PII or secrets in URLs, query strings, or client-side storage. | P3.1, CC6.7 | must |
| DATA-07 | Backups are encrypted, access-restricted, and restore-tested on a schedule. RPO and RTO are documented. | A1.2, A1.3 | must |
| DATA-08 | Multi-tenant data access is scoped by tenant on every query (row-level security, mandatory query scoping, or per-tenant schema). | CC6.1, C1.2 | must |
| DATA-09 | Data export and subject access request flows exist where Privacy is in scope. | P5.1 | should |
| DATA-10 | Non-production environments use synthetic or masked data. Production data is never copied to dev or test. | C1.2, CC6.1 | must |
| DATA-11 | Data processing pipelines and batch jobs verify completeness and accuracy: record counts or checksums are reconciled between stages, failed records are quarantined and reported rather than silently dropped, and processing outcomes are logged with totals. | PI1.1, PI1.2, PI1.3 | must (if Processing Integrity in scope) |
| DATA-12 | Where Privacy is in scope: consent is captured with purpose, policy version, timestamp, and source, stored as an auditable record, and checked in code before any processing that requires it. Withdrawal stops processing and is propagated to downstream systems. | P2.1, P3.1, P4.1 | must (if Privacy in scope) |

## LOG — Logging, audit trail, and monitoring (detail: `logging-and-audit.md`)

| ID | Requirement | TSC | Severity |
|----|-------------|-----|----------|
| LOG-01 | Security-relevant events are written to an audit log: login success and failure, MFA events, password and permission changes, role grants, access to restricted data, admin actions, config changes, data exports and deletions. | CC7.2, CC6.1 | must |
| LOG-02 | Each audit entry records actor, action, target, timestamp (UTC), source IP or client, outcome, and correlation ID. Audit logs are append-only and separate from application logs. | CC7.2, CC7.3 | must |
| LOG-03 | Logs never contain passwords, tokens, secrets, full card numbers, or unmasked PII. A redaction layer is applied before shipping. | C1.2, CC6.1 | must |
| LOG-04 | Logs are structured (JSON), centralized, and retained for at least the configured period (default 1 year) with restricted write access. | CC7.2, CC4.1 | must |
| LOG-05 | Alerts exist for repeated auth failures, privilege escalation, new admin creation, error-rate spikes, and unavailable dependencies. Alerts route to an on-call owner. | CC7.2, CC7.3 | must |
| LOG-06 | Services expose health and readiness checks. Uptime and latency are monitored against documented SLOs. | A1.1, CC7.1 | should |
| LOG-07 | All timestamps are UTC, and hosts use synchronized time. | CC7.2 | should |

## SEC — Secrets, dependencies, and secure configuration (detail: `secrets-and-config.md`)

| ID | Requirement | TSC | Severity |
|----|-------------|-----|----------|
| SEC-01 | No secrets in source, config files, containers, or CI logs. Secrets come from a secret manager or injected environment at runtime. `.env` files are git-ignored. A secret scanner runs pre-commit and in CI. | CC6.1 | must |
| SEC-02 | Secrets can be rotated without a code change. Rotation is documented and performed at least annually or on personnel change. | CC6.1 | should |
| SEC-03 | Dependencies are pinned via a lockfile. Software composition analysis (SCA) runs in CI. Patch SLAs: critical 7 days, high 30 days, medium 90 days. | CC7.1, CC8.1 | must |
| SEC-04 | Static analysis (SAST) with security rules runs in CI and blocks merge on high findings. | CC7.1, CC8.1 | must |
| SEC-05 | Container images are minimal, run as non-root, are scanned for vulnerabilities, and are rebuilt on base-image updates. | CC7.1, CC6.8 | should |
| SEC-06 | Secure defaults: debug mode off in production, no default credentials, risky features behind flags, verbose errors disabled. | CC6.1, CC8.1 | must |
| SEC-07 | Only approved cryptography: AES-256-GCM or ChaCha20-Poly1305 for symmetric, RSA ≥ 2048 or ECDSA P-256 or Ed25519 for asymmetric, SHA-256 or better for hashing, argon2id or bcrypt for passwords. No MD5, SHA-1, DES, RC4, ECB, or custom algorithms. Keys are managed by a KMS and are never stored in the same datastore, repository, config file, or container image as the data they protect. | CC6.6, C1.2 | must |

## CHG — Change management (detail: `change-management.md`)

| ID | Requirement | TSC | Severity |
|----|-------------|-----|----------|
| CHG-01 | The default branch is protected: pull request required, at least one approving reviewer who is not the author, no force pushes, no direct pushes. | CC8.1 | must |
| CHG-02 | CI must pass tests, SAST, SCA, and secret scanning before merge. Status checks are required, not advisory. | CC8.1 | must |
| CHG-03 | Every PR uses a template with a security and data-impact checklist and links to a ticket or issue. | CC8.1, CC3.4 | must |
| CHG-04 | CODEOWNERS requires review from the security or platform owner for auth, crypto, infra, CI, and data-model paths. | CC8.1 | should |
| CHG-05 | An emergency change path exists and requires post-hoc review within 2 business days. Emergency changes are labeled and reported. | CC8.1 | must |
| CHG-06 | Releases are tagged. Deployments are logged with who, what, when, and version. A rollback procedure is documented and tested. | CC8.1, A1.2 | must |
| CHG-07 | Production deploys run only through the pipeline with a deploy identity. Humans do not have standing write access to production. | CC8.1, CC6.1 | should |
| CHG-08 | Commits or build artifacts are signed, and build provenance is recorded. | CC8.1 | may |
| CHG-09 | Feature flags and runtime configuration changes are tracked: every change records who, when, old and new value, and a reason, either through a flag service with an audit log or through config-as-code reviewed in a PR. No silent hardcoded toggles. | CC8.1, CC7.2 | should |

## INFRA — Infrastructure and platform (detail: `infrastructure.md`)

| ID | Requirement | TSC | Severity |
|----|-------------|-----|----------|
| INFRA-01 | Infrastructure is defined as code, reviewed through the same PR process, and drift is detected. | CC8.1, CC6.6 | should |
| INFRA-02 | Network segmentation: databases and internal services are on private networks, security groups deny by default, and only load balancers are public. | CC6.6 | must |
| INFRA-03 | Cloud IAM follows least privilege. No wildcard actions or resources in production policies. No long-lived access keys; use roles or workload identity. | CC6.1, CC6.3 | must |
| INFRA-04 | Encryption at rest is enabled on every datastore, object bucket, queue, and volume, with KMS-managed keys and restricted key policies. | CC6.6, C1.2 | must |
| INFRA-05 | Managed services and hosts receive security patches within the SLAs in SEC-03. Auto-update is enabled where available. | CC7.1 | must |
| INFRA-06 | Where Availability is in scope: multi-zone redundancy, autoscaling or capacity headroom, and a tested disaster-recovery runbook. | A1.1, A1.2, A1.3 | should |
| INFRA-07 | Public edges sit behind a WAF and DDoS protection. | CC6.6, A1.1 | should |

## EVD — Evidence and traceability (detail: `SKILL.md` evidence mode)

| ID | Requirement | TSC | Severity |
|----|-------------|-----|----------|
| EVD-01 | `.soc2/CONTROL_MAP.md` maps each requirement to its implementation location, the evidence an auditor can inspect, and an owner. Updated in the same PR as the code. | CC5.3, CC4.1 | must |
| EVD-02 | Security-relevant code is annotated with `SOC2:<ID>` comments at the enforcement point so the control can be located by grep. | CC5.3 | should |
| EVD-03 | Exceptions are recorded in `.soc2/EXCEPTIONS.md` with rationale, compensating control, approver, and expiry date. | CC3.4, CC5.3 | must |
