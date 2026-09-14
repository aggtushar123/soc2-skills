# Audit checklist coverage map

Maps a typical auditor or security-review checklist of code-level SOC 2 pointers to the
requirement IDs in `requirements.md`. Use it to answer "is X covered" quickly, to
build the evidence index, and to hand an auditor a crosswalk from their checklist to
this repo's control map.

Severity in this skill: **must** is stricter than "good to have" in some auditor
lists (security headers, rate limiting, CI tests). Keep the stricter one; an auditor
never objects to more.

| # | Checklist pointer | TSC | Requirement IDs | Scanner check |
|---|-------------------|-----|-----------------|---------------|
| 1 | No hardcoded secrets, credentials, or API keys in source | CC6.1 | SEC-01 | yes: secret patterns, `.env`, Dockerfile ENV |
| 2 | Secrets pulled from vault or env, not committed to VCS | CC6.1 | SEC-01, SEC-02 | yes: `.env` git-ignored, secret scan in CI |
| 3 | Input validation and injection prevention (SQLi, XSS, command injection) | CC6.6, CC6.8 | API-01, API-02, API-03 | yes: string-built SQL, shell exec, eval, validation lib presence |
| 4 | Authentication implementation (password hashing, MFA hooks, session tokens) | CC6.1, CC6.2 | AUTH-03, AUTH-04, AUTH-05 | yes: hashing lib presence, MFA presence, fast-hash on password |
| 5 | Password complexity and rotation rules enforced in code (if auth is in-app) | CC6.1 | AUTH-04 (config: `password_min_length`, `password_max_age_days`, `external_idp`) | partial: weak hashing only |
| 6 | Session timeout and idle logout enforced in code | CC6.1 | AUTH-05 (config: `idle_timeout_minutes`, `access_token_ttl_minutes`) | no: manual review |
| 7 | Authorization and RBAC enforced in code (least privilege at app layer) | CC6.1, CC6.3 | AUTH-02, AUTH-09 | no: manual review |
| 8 | Multi-tenant data isolation in app code | CC6.1, CC6.3 | DATA-08 | no: manual review |
| 9 | TLS enforced in transit, cert validation never disabled | CC6.1, CC6.7 | DATA-03 | yes: skip-verify flags, `sslmode=disable`, plaintext service URLs, TLS < 1.2 in IaC |
| 10 | Sensitive data encrypted at application layer (PII fields, tokens) | CC6.1, CC6.7 | DATA-02 | no: manual review |
| 11 | Encryption keys never stored alongside the data they encrypt | CC6.1, CC6.7 | SEC-07, DATA-02 (envelope encryption with KMS-wrapped DEK) | partial: hardcoded key literals via SEC-01 |
| 12 | CSRF protection on state-changing endpoints | CC6.6 | API-06 | no: manual review |
| 13 | CORS reviewed, not wildcard on sensitive endpoints | CC6.6 | API-06 | yes: wildcard origin, wildcard with credentials |
| 14 | Security response headers (CSP, HSTS, X-Frame-Options) | CC6.6 | API-06 | yes: headers middleware presence |
| 15 | Secure file upload handling (type, size, content validation) | CC6.6, CC6.8 | API-10 | no: manual review |
| 16 | Webhook and third-party callback signature verification | CC6.6 | API-11 | yes: webhook route without a verifier in file |
| 17 | Rate limiting and brute-force protection on auth endpoints | CC6.1 | API-04, AUTH-06 | yes: rate-limit lib presence |
| 18 | Secure deletion and data-wipe functions for decommissioned data | CC6.5 | DATA-05, DATA-04 | no: manual review |
| 19 | Security event and audit logging (auth events, access changes, admin actions) | CC7.2 | LOG-01, LOG-02 | yes: audit primitive presence |
| 20 | Logs contain no secrets or PII in plaintext | CC6.1, CC7.2 | LOG-03 | yes: log call referencing secrets, tokens, raw request |
| 21 | Error handling leaks no stack traces or internal info | CC6.1 | API-05, SEC-06 | yes: unconditional debug mode |
| 22 | Dependency and SCA vulnerability scanning | CC7.1 | SEC-03 | yes: SCA in CI or Dependabot/Renovate, lockfile |
| 23 | SAST integrated in pipeline | CC7.1 | SEC-04 | yes: SAST tool in CI |
| 24 | CWE Top 25 weaknesses avoided | CC6.6, CC7.1 | see `cwe-top25-map.md` | partial: injection, crypto, secrets, eval |
| 25 | Pull request and code review approval before merge to main | CC8.1 (SOC 1 if financial logic) | CHG-01 | partial: PR template presence; protection itself is a platform setting |
| 26 | Branch protection: no direct push to production branch | CC8.1 (SOC 1 if financial logic) | CHG-01 | no: platform setting, evidence is the ruleset export |
| 27 | Segregation of duties: author is not sole approver | CC8.1 (SOC 1 if financial logic) | CHG-01 (non-author approval, last-push approval), CHG-04 | no: platform setting |
| 28 | Version control history preserved, no force-push on prod branch | CC8.1 (SOC 1 if financial logic) | CHG-01 | no: platform setting |
| 29 | CI/CD runs automated tests before deploy | CC8.1 | CHG-02 | yes: test step in CI |
| 30 | Feature flags and config changes tied to change tracking | CC8.1 | CHG-09, LOG-01 (`config.changed` event) | no: manual review |
| 31 | Idempotency and duplicate-transaction prevention | PI1.1, PI1.2 (only if PI in scope) | API-08 | no: manual review |
| 32 | Input completeness and accuracy checks on processing pipelines | PI1.1, PI1.2, PI1.3 (only if PI in scope) | DATA-11, API-01 | no: manual review |
| 33 | Data classification tagging in schema or code | C1.1 (only if Confidentiality in scope) | DATA-01 | no: manual review |
| 34 | Consent capture and consent-state checks before processing personal data | P2.1, P3.1 (only if Privacy in scope) | DATA-12 | no: manual review |
| 35 | DSAR and data export or delete handlers | P5.1, P4.2 (only if Privacy in scope) | DATA-09, DATA-05 | no: manual review |
| 36 | Health-check and graceful-degradation endpoints | A1.1 (only if Availability in scope) | LOG-06 | no: manual review |

## Items the scanner cannot see

Rows marked "no" or "partial" need the manual review in audit mode (SKILL.md, audit
step 2). The ones that produce the most audit exceptions and are invisible to any
scanner: AUTH-02 (object-level authorization), DATA-08 (tenant scoping), DATA-02
(field-level encryption), API-06 CSRF, AUTH-05 timeouts. Open the entry points and
check each one.

## Platform settings outside the repo

Rows 25 to 28 are GitHub, GitLab, or Bitbucket settings. Evidence is a ruleset or
branch-protection export, not code. `change-management.md` under CHG-01 has the
`gh api` command to configure and export it.
