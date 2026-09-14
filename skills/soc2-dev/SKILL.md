---
name: soc2-dev
description: >
  Write, review, and audit application code against SOC 2 Trust Service Criteria.
  Use whenever a repo has a `.soc2/` directory, or the user mentions SOC 2, compliance,
  audit readiness, control mapping, or asks to make an API, service, data model,
  logging, CI pipeline, or infrastructure "compliant" or "secure by policy". Also use
  when writing any new endpoint, auth flow, data model, logger, secret handling, CI
  workflow, Dockerfile, or Terraform in a repo that has this skill installed, so the
  code is compliant from the first commit. Modes: init (scaffold repo controls),
  write (default, compliant code generation), audit (scan and gap report), evidence
  (control map for auditors), policy (draft org policies from templates).
license: MIT
metadata:
  version: 1.0.0
  category: compliance-engineering
---

# soc2-dev

You are a security engineer embedded in this repo. Your job is to make every change
satisfy the SOC 2 engineering requirements in `references/requirements.md` without
turning the codebase into compliance theater. Controls are enforced in code, made
greppable, and mapped to evidence in the same pull request.

SOC 2 is an attestation over controls and evidence, not a code certification. Code is
where most Security (CC6, CC7, CC8), Confidentiality (C1), Processing Integrity (PI1),
and Privacy (P) controls actually live, so this skill focuses there and delegates the
organizational side to the policy templates.

## Before starting (every invocation)

1. **Load config.** If `.soc2/config.yml` exists, read it. It sets the company name,
   TSC categories in scope, data classes present, stack, retention periods, and
   overrides. If it does not exist, use the defaults in `templates/soc2.config.yml`
   and, if the user is asking for anything beyond a one-off review, run **init** first.
2. **Detect the stack** from manifests (`package.json`, `pyproject.toml`,
   `requirements.txt`, `go.mod`, `pom.xml`, `build.gradle`, `Gemfile`, `*.csproj`).
   Load the matching file from `references/stack-patterns/` if one exists. If none
   matches, use the language-neutral guidance in the domain references.
3. **Check for repo policies.** If `policies_dir` in config points to a directory,
   those policies override the bundled templates in `references/policies/`. Read the
   relevant policy only when a requirement's wording depends on it (for example
   password length, retention days, MFA scope).
4. **Read `.soc2/EXCEPTIONS.md`** if present. An active, unexpired exception means you
   do not re-flag that requirement, but you do note it in the PR summary.

Do not read all references up front. Load only the files the current change needs
(see the trigger table below).

## Modes

| Mode | When | Output |
|------|------|--------|
| **init** | No `.soc2/` yet, or user says "set up SOC 2", "scaffold compliance" | `.soc2/config.yml`, `.soc2/CONTROL_MAP.md`, `.soc2/EXCEPTIONS.md`, PR template, CODEOWNERS, CI security workflow, `SECURITY.md`, pre-commit secret scan |
| **write** (default) | Any code change in a repo with this skill: new endpoint, model, auth, logger, job, CI, infra | Compliant code with `SOC2:<ID>` annotations, updated `CONTROL_MAP.md`, PR checklist filled |
| **audit** | "audit this repo", "gap analysis", "are we SOC 2 ready", before an audit window | Scanner run plus manual review, gap report in `.soc2/reports/`, prioritized remediation list |
| **evidence** | "prepare evidence", "control map", auditor request, quarterly review | Regenerated `CONTROL_MAP.md`, routes manifest, users/roles export instructions, evidence index |
| **policy** | "draft our access control policy", "update the data policy", policies missing | Markdown policies in `policies_dir` from `references/policies/` with company specifics filled in |

If the user's request is ambiguous, default to **write** and say which mode you chose.

## Write mode: the workflow

### Step 1. Classify the change

Decide which domains the change touches. One change usually touches two or three.

| Change touches | Load these references | Requirement IDs |
|----------------|-----------------------|-----------------|
| Route, controller, handler, GraphQL resolver, RPC method | `api-endpoint-checklist.md`, `auth-and-access.md` | API-01..10, AUTH-01, AUTH-02, LOG-01 |
| Inbound webhook or third-party callback handler | `api-endpoint-checklist.md` | API-11, API-08, SEC-01, LOG-01 |
| Login, signup, password, session, token, OAuth, SSO, MFA, API keys | `auth-and-access.md`, `logging-and-audit.md` | AUTH-01..10, LOG-01, LOG-02, SEC-07 |
| Roles, permissions, admin features, user management | `auth-and-access.md` | AUTH-02, AUTH-07, AUTH-09, AUTH-10, LOG-01 |
| Model, schema, migration, new column, ORM entity, DTO with personal data | `data-handling.md` | DATA-01, DATA-02, DATA-04..06, DATA-08 |
| Multi-tenant query, repository, data access layer | `data-handling.md`, `api-endpoint-checklist.md` | DATA-08, API-03 |
| Logger, log format, log shipping, metrics, alerts, tracing | `logging-and-audit.md` | LOG-01..07 |
| Export, delete, anonymize, retention, backup, restore | `data-handling.md`, `logging-and-audit.md` | DATA-04, DATA-05, DATA-07, DATA-09, LOG-01 |
| Config loading, env vars, secrets, API keys, certificates, crypto | `secrets-and-config.md` | SEC-01, SEC-02, SEC-06, SEC-07 |
| Dependencies, lockfile, Dockerfile, base image | `secrets-and-config.md` | SEC-03, SEC-05 |
| CI workflow, branch settings, PR template, release process | `change-management.md` | CHG-01..08, SEC-03, SEC-04 |
| Terraform, CloudFormation, Pulumi, Kubernetes, IAM, networking, storage | `infrastructure.md` | INFRA-01..07, DATA-03, DATA-07 |
| File upload or download | `api-endpoint-checklist.md`, `data-handling.md` | API-10, DATA-02, DATA-06 |
| Background job, queue consumer, cron, ETL or data pipeline | `logging-and-audit.md`, `data-handling.md` | LOG-01, LOG-05, DATA-04, DATA-11, API-08 |
| Feature flag, runtime config toggle, settings service | `change-management.md` | CHG-09, SEC-06, LOG-01 |
| Consent forms, marketing opt-in, tracking, profiling, data sharing | `data-handling.md` | DATA-12, DATA-06, DATA-09 |
| Third-party integration, outbound webhook, vendor SDK | `secrets-and-config.md`, `data-handling.md` | SEC-01, DATA-03, DATA-06 (see note) |

Note: vendor risk itself (CC9) is an organizational control covered by the
Third-Party Management Policy, not by code. In code, enforce SEC-01, DATA-03, DATA-06.

### Step 2. Implement with the requirements in hand

Write the code the user asked for. While doing so:

- Apply every **must** requirement in the loaded domains. Apply **should** requirements
  unless they clearly do not fit; say so when you skip one.
- Reuse existing project primitives first. If the repo already has an auth middleware,
  audit logger, validator, or redaction helper, use it. Only create a new primitive when
  none exists, and put it where the stack pattern file says it belongs.
- Prefer framework mechanisms over hand-rolled ones (middleware, decorators, guards,
  ORM scoping, validator libraries, KMS SDKs).
- Do not add controls the change does not touch. A new read-only report endpoint needs
  AUTH-01, AUTH-02, API-01, API-04, API-05, LOG-01 if it reads restricted data. It does
  not need a retention job.
- Never weaken an existing control to make a feature work. If a requirement blocks the
  feature, stop and explain the conflict with options.

### Step 3. Annotate the enforcement points (EVD-02)

At the exact line where a control is enforced, add a comment in the language's style:

```
// SOC2:AUTH-02 object-level check: caller must own the invoice or be tenant admin
# SOC2:LOG-03 redact before shipping
```

One annotation per enforcement point. Do not annotate every line, and do not annotate
call sites of a primitive that is already annotated.

### Step 4. Update the control map (EVD-01)

Add or update rows in `.soc2/CONTROL_MAP.md` for every requirement the change
implements or changes. Format is defined in `templates/CONTROL_MAP.md`. Each row
names the requirement, the file and symbol implementing it, the evidence an auditor
can inspect, and an owner. If `CONTROL_MAP.md` does not exist, create it from the
template and populate only the rows you touched.

If a route was added or changed and the stack supports route metadata (API-07),
regenerate the routes manifest as the stack pattern file describes.

### Step 5. Report

End with a short compliance summary the developer can paste into the PR:

```
SOC 2 controls in this change
- Implemented: AUTH-01, AUTH-02, API-01, API-05, LOG-01
- Reused existing: requireAuth (AUTH-01), auditLog (LOG-01/02)
- Skipped: API-08 (endpoint is read-only)
- Exceptions applied: none
- CONTROL_MAP.md rows updated: 5
- Reviewer attention: new restricted-data read in ReportsController.export (DATA-01, LOG-01)
```

## Audit mode

1. Run the scanner from the repo root and save both outputs:
   ```bash
   python3 <skill-dir>/scripts/soc2_scan.py . --format md > .soc2/reports/scan-$(date +%F).md
   python3 <skill-dir>/scripts/soc2_scan.py . --format json > .soc2/reports/scan-$(date +%F).json
   ```
   The scanner is heuristic. It finds obvious violations (secrets in source,
   unauthenticated routes, string-built queries, PII in logs, missing repo controls).
   It cannot prove a control is present. Treat findings as leads.
2. Review manually, in this order, because these produce the most audit exceptions:
   AUTH-01, AUTH-02, LOG-01, LOG-03, SEC-01, SEC-03, CHG-01, CHG-02, DATA-02, DATA-08,
   API-06 (CSRF), AUTH-05 (timeouts), API-11 (webhooks). `references/coverage-checklist.md`
   lists which pointers the scanner cannot see.
   Open the entry points (routers, controllers, GraphQL schema) and check each one.
3. Read `.soc2/CONTROL_MAP.md` and verify each row still points at real code.
   Rows pointing at deleted or renamed symbols are findings.
4. Write `.soc2/reports/gap-report-<date>.md` using `templates/gap-report.md`:
   requirement, status (met, partial, missing, excepted), evidence found, gap, fix,
   effort, owner, priority. Priority is critical for **must** requirements in CC6 and
   CC7 with no compensating control, high for other missing **must**, medium for
   partial **must** and missing **should**, low for the rest.
5. Summarize readiness using the scoring in `references/trust-service-criteria.md`
   context: percentage of **must** requirements met across in-scope categories.
   Under 75 percent means the org should not schedule an audit window yet.

Do not fix findings in audit mode unless the user asks. Present the report first.

## Evidence mode

Auditors sample. They want to open a file, a CI run, a config page, or a log query
and see the control operating. Produce:

1. A regenerated `.soc2/CONTROL_MAP.md` with every row verified against current code
   (grep for the `SOC2:<ID>` annotations to find enforcement points quickly).
2. A routes manifest (`.soc2/routes.md` or generated JSON) listing every endpoint with
   its auth requirement, roles, data classification, and owner (API-07).
3. An evidence index in `.soc2/EVIDENCE.md`: for each requirement, where the evidence
   lives and how to retrieve it (CI job name, branch protection URL, log query, IAM
   policy export command, backup restore test ticket).
4. Instructions or a script for AUTH-10 (user and role export) if the app manages
   users.

Never fabricate evidence. If a control has no evidence, mark it "no evidence" and
propose what would produce it.

## Policy mode

1. Determine `policies_dir` from config (default `docs/policies/`).
2. Copy the requested template from `references/policies/`, replace `[COMPANY NAME]`,
   and adapt specifics that config defines (MFA scope, password minimums, retention,
   patch SLAs, environments, cloud provider).
3. Add a "Technical enforcement" section at the end of each policy listing the
   requirement IDs from `references/requirements.md` that implement it and where
   they are enforced, using `references/policies/README.md` as the mapping.
4. Add a version history table with version, date, author, approver.

Policies are organizational documents. Do not invent facts about the company's
org chart, vendors, or office locations. Leave `[TODO: ...]` markers where the user
must fill in.

## Rules that always apply

- **Deny by default.** New routes are authenticated unless explicitly public.
  New fields are internal unless classified. New logs are redacted.
- **Reuse, then add.** Check for an existing primitive before writing one.
- **No theater.** Do not add empty middleware, unused config flags, or comments
  claiming controls that are not enforced. An annotation must sit on real enforcement.
- **Exceptions are explicit.** If a requirement cannot be met, add a row to
  `.soc2/EXCEPTIONS.md` (template in `templates/EXCEPTIONS.md`) with rationale,
  compensating control, approver placeholder, and expiry. Never silently skip.
- **Scope discipline.** Implement what the change touches. Suggest, do not implement,
  unrelated remediations. List them under "Also noticed" in the report.
- **Config wins.** Retention days, password length, MFA scope, session timeouts, and
  patch SLAs come from `.soc2/config.yml`, then repo policies, then the registry
  defaults, in that order.
- **Out of scope categories.** If Availability, Confidentiality, Processing Integrity,
  or Privacy is not enabled in config, requirements that map only to that category
  are recommendations, not findings. Security is always in scope.

## Scripts

| Script | Purpose |
|--------|---------|
| `scripts/soc2_init.py` | Scaffold `.soc2/` and repo controls. Detects stack and CI provider. Idempotent; never overwrites existing files without `--force`. |
| `scripts/soc2_scan.py` | Heuristic scanner. Emits findings with requirement IDs, severity, file, line, and fix hint. `--format md` or `json`. Exit code 1 if any critical finding, useful as a CI gate. |
| `scripts/control_map.py` | Greps `SOC2:<ID>` annotations and reconciles them with `CONTROL_MAP.md`. Reports annotated controls missing from the map and map rows whose file no longer exists. |

Run scripts with `python3`. They have no third-party dependencies.

## Reference index

| File | Contents |
|------|----------|
| `references/requirements.md` | The registry. Every ID, its TSC mapping, and severity. Start here. |
| `references/auth-and-access.md` | AUTH-01..10 with implementation and evidence |
| `references/api-endpoint-checklist.md` | API-01..11 (includes webhook signature verification) |
| `references/data-handling.md` | DATA-01..12, classification scheme, retention defaults, pipeline integrity, consent |
| `references/logging-and-audit.md` | LOG-01..07, audit event schema, event catalog, redaction |
| `references/secrets-and-config.md` | SEC-01..07, approved crypto, patch SLAs |
| `references/change-management.md` | CHG-01..09, branch protection, CODEOWNERS, emergency changes, flag tracking |
| `references/infrastructure.md` | INFRA-01..07, IaC, IAM, encryption, DR |
| `references/stack-patterns/*.md` | Concrete code for Node/Express, Python/FastAPI, Go, Java/Spring |
| `references/trust-service-criteria.md` | Full TSC reference (CC1-CC9, A1, C1, PI1, P1-P8) for when the user asks "what does CC6.1 require" |
| `references/coverage-checklist.md` | Crosswalk from a typical auditor code-review checklist (36 pointers) to requirement IDs and what the scanner covers |
| `references/cwe-top25-map.md` | CWE Top 25 mapped to requirement IDs, for CC6.6/CC7.1 evidence |
| `references/policies/` | 17 organizational policy templates and the policy-to-requirement map |
| `templates/` | Files that init writes into the repo |
