# Change Management

This domain covers how code gets from a developer's branch into production: who reviews it, what automated gates it must pass, how emergencies are handled without bypassing accountability, how releases are identified and rolled back, and who (or what) is allowed to deploy. It serves CC8.1 (change management: authorization, design, testing, approval, and implementation of changes), CC3.4 (identifying changes that affect controls), CC6.1 (restricting production write access to a deploy identity), and A1.2 (recovery via tested rollback). Auditors sample merged PRs from the audit period and check each one for an approver who is not the author, passing required checks, a linked ticket, and a deployment record. One unreviewed merge to the default branch is a finding.

## When Claude must load this file

- Creating or editing anything under `.github/` (workflows, `CODEOWNERS`, `PULL_REQUEST_TEMPLATE.md`, `dependabot.yml`, rulesets)
- Editing `.gitlab-ci.yml`, `Jenkinsfile`, `bitbucket-pipelines.yml`, `.circleci/`, or other CI/CD pipeline definitions
- Changing branch protection, repository settings, merge strategy, or required status checks (via UI, `gh api`, or Terraform `github_*` resources)
- Adding a deploy step, deploy script, release workflow, or version-tagging logic
- Writing or changing a rollback, hotfix, or emergency procedure
- Adding or modifying deploy credentials, OIDC trust policies, or the identity a pipeline assumes
- Configuring commit signing, Sigstore/cosign, SLSA provenance, or artifact attestation
- Opening a PR that touches auth, crypto, infra, CI, or migration paths (CODEOWNERS applies)
- Responding to a production incident that requires shipping code outside the normal review window

## Requirements

### CHG-01 — Protected default branch

**Rule:** The default branch requires a pull request with at least one approving review from someone other than the author. Force pushes and direct pushes are disabled for everyone, including admins.

**TSC:** CC8.1

**How to implement:**
- Use GitHub repository rulesets (preferred over legacy branch protection because they apply to admins and can be enforced org-wide). Target `~DEFAULT_BRANCH` and any `release/*` pattern.
- Enable: `pull_request` rule with `required_approving_review_count: 1`, `dismiss_stale_reviews_on_push: true`, `require_last_push_approval: true` (blocks approving your own late commit); `non_fast_forward` (no force push); `deletion`; `required_linear_history` optionally.
- Do not add bypass actors except a break-glass team that is empty by default (see CHG-05). Never grant the deploy bot bypass.
- Manage rulesets as code with Terraform `github_repository_ruleset` or `github_organization_ruleset` so changes are themselves reviewed.
- For GitLab: protected branches with "Maintainers" allowed to merge, "No one" allowed to push, and merge request approvals with "Prevent approval by author".
- Audit quarterly with `gh api repos/{owner}/{repo}/rulesets` across all repos; alert on any repo whose default branch has no ruleset.

**Code example:**

```bash
# SOC2:CHG-01 apply the default-branch ruleset via gh CLI
gh api -X POST repos/acme/api/rulesets --input - <<'EOF'
{
  "name": "default-branch-protection",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "bypass_actors": [],
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    { "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": true,
        "require_last_push_approval": true,
        "required_review_thread_resolution": true } },
    { "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "required_status_checks": [
          { "context": "test" }, { "context": "sast" },
          { "context": "sca" },  { "context": "secret-scan" } ] } }
  ]
}
EOF
```

**Common violations:**
- Legacy branch protection with "Include administrators" unchecked; admins merge their own PRs during crunch.
- Approval count is 1 but the author's own approval counts because `require_last_push_approval` is off and they pushed after a teammate approved.
- A `release/*` branch that deploys to production is unprotected.
- Rulesets exist but `enforcement` is `evaluate` (dry run) rather than `active`.

**Evidence to produce:**
- `gh api repos/{owner}/{repo}/rulesets/{id}` JSON export or Terraform file path for the ruleset.
- Screenshot of the ruleset page showing `active` enforcement and zero bypass actors.
- Sample of 10 merged PRs from the period with approver ≠ author.

### CHG-02 — Required, blocking CI checks

**Rule:** Tests, SAST, SCA, and secret scanning must pass before merge. They are configured as required status checks in branch protection, not advisory.

**TSC:** CC8.1

**How to implement:**
- Standardize check names across repos (`test`, `sast`, `sca`, `secret-scan`, `image-scan`, `iac-scan`) so the ruleset can reference them by exact context. Job `name:` in the workflow must match.
- Set `strict_required_status_checks_policy: true` so the PR must be up to date with the base branch; otherwise a green check on a stale branch can mask a conflict-introduced failure.
- Never use `continue-on-error: true` on a security job. If a scanner is flaky, fix or replace it; do not demote it.
- Make workflows run on `pull_request` (not only `push`) and cover PRs from forks with `pull_request_target` only where safe (no secrets exposed to fork code).
- Do not allow "skip CI" strings (`[skip ci]`) to bypass required checks; GitHub still requires the check context, so a skipped workflow results in a pending (blocking) status.
- Pin every action to a commit SHA (SEC-03) and set `permissions:` to least privilege at the workflow level.

**Code example:**

```yaml
# .github/workflows/ci.yml
name: ci
on: { pull_request: {}, push: { branches: [main] } }
permissions: { contents: read }

jobs:
  test:                                   # SOC2:CHG-02 job name == required check context
    name: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
      - uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8 # v4.0.2
        with: { node-version: 20, cache: npm }
      - run: npm ci
      - run: npm test -- --coverage
  # sast, sca, secret-scan live in security.yml with identical name: values;
  # all four are listed under required_status_checks in the ruleset (CHG-01).
```

**Common violations:**
- Security workflows run on a schedule only, so the PR merges before the scan happens.
- Required check list is empty; checks "run" but a red X does not block the merge button.
- The check context in branch protection is `Semgrep / semgrep` but the job was renamed to `sast`, so the required check never reports and someone removes it "to unblock".
- Tests are required but the test job only runs `echo "todo"`.

**Evidence to produce:**
- Ruleset export showing `required_status_checks` contexts; workflow file paths with matching job names.
- A PR link where a failing `sast` or `sca` check blocked merge until fixed.

### CHG-03 — PR template with security checklist and ticket link

**Rule:** Every PR uses a template containing a security and data-impact checklist and links to a ticket or issue that authorizes the change.

**TSC:** CC8.1, CC3.4

**How to implement:**
- Add `.github/PULL_REQUEST_TEMPLATE.md` with sections: Summary, Ticket (required link), Change type, Security impact checklist (auth, data classification, secrets, logging, crypto, infra, migration), Rollback plan, Evidence updated (`.soc2/CONTROL_MAP.md` if a control moved).
- Enforce the ticket link with a lightweight check: a GitHub Action or Danger rule that fails if the body lacks `(JIRA-|#)\d+` or a URL matching the tracker. Name it `pr-metadata` and add it to required checks.
- Require the author to tick "N/A" explicitly rather than leaving boxes blank; reviewers reject PRs with an untouched checklist.
- Use PR labels to drive review routing: `security-impact`, `data-model`, `infra`, `emergency-change`. A label-based rule can require an additional reviewer team.
- Keep the template short enough that people fill it in honestly; a 40-item checklist gets rubber-stamped.
- For multi-repo orgs, place the template in the `.github` org repo so it is the default everywhere.

**Code example:**

```markdown
<!-- .github/PULL_REQUEST_TEMPLATE.md  SOC2:CHG-03 -->
## Summary

## Ticket
<!-- required: link to the issue that authorizes this change -->
Closes: 

## Security and data impact (tick all; use N/A explicitly)
- [ ] Auth/authz paths changed? If yes, AUTH-* reviewed and `SOC2:` annotations added
- [ ] New or changed persisted fields carry a classification (DATA-01)
- [ ] No secrets in diff; secret-scan green (SEC-01)
- [ ] New security-relevant events emit audit entries (LOG-01)
- [ ] Crypto uses approved algorithms only (SEC-07)
- [ ] Infra/CI/migration files touched? CODEOWNERS review requested (CHG-04)
- [ ] `.soc2/CONTROL_MAP.md` updated if a control's location changed (EVD-01)

## Rollback plan
<!-- how to revert safely; note any irreversible migration -->
```

**Common violations:**
- Template exists but PRs are created via CLI/bot without it, and no check enforces the ticket link.
- "Ticket: none, quick fix" accepted routinely; auditors cannot trace authorization.
- Checklist boxes all ticked in under a minute on a 2,000-line diff.
- Data-model changes shipped with no mention of classification or retention.

**Evidence to produce:**
- Template file path; CI job name `pr-metadata` and its run on a sampled PR.
- Sample of merged PRs from the period showing populated checklist and ticket link.

### CHG-04 — CODEOWNERS for sensitive paths

**Rule:** A `CODEOWNERS` file requires review from the security or platform owner team for authentication, cryptography, infrastructure, CI, and data-model or migration paths.

**TSC:** CC8.1

**How to implement:**
- Place `CODEOWNERS` at `.github/CODEOWNERS` (or repo root). Owners must be GitHub teams with write access, not individuals, so coverage survives vacations and departures.
- Enable `require_code_owner_review: true` in the ruleset (CHG-01); otherwise CODEOWNERS only auto-requests reviewers and does not block.
- Cover: auth and session code, crypto helpers, secrets loading, IaC directories, `.github/`, Dockerfiles, database migrations and schema files, the audit logger, and `.soc2/`.
- Keep a default owner (`*`) for the application team so every file has at least one owner, then add narrower rules below (last match wins).
- Validate syntax in CI (`gh api repos/{owner}/{repo}/codeowners/errors`) and fail if any rule references a non-existent team.
- Review CODEOWNERS quarterly alongside access reviews; membership of `@acme/security` and `@acme/platform` is itself evidence.

**Code example:**

```text
# .github/CODEOWNERS   SOC2:CHG-04 security/platform review on sensitive paths
*                                   @acme/app-team

# Authentication, authorization, sessions
/src/auth/**                        @acme/security
/src/middleware/authz*              @acme/security
/src/services/session*              @acme/security

# Cryptography and secrets handling
/src/crypto/**                      @acme/security
/src/config/secrets*                @acme/security

# Infrastructure as code and containers
/infra/**                           @acme/platform @acme/security
/terraform/**                       @acme/platform @acme/security
/k8s/**                             @acme/platform
/Dockerfile*                        @acme/platform

# CI/CD and repo governance
/.github/**                         @acme/platform @acme/security
/.github/CODEOWNERS                 @acme/security

# Data model and migrations
/db/migrations/**                   @acme/data-owners @acme/security
/src/models/**                      @acme/data-owners

# Audit logging and compliance evidence
/src/audit/**                       @acme/security
/.soc2/**                           @acme/security
```

**Common violations:**
- CODEOWNERS lists individual usernames; one person leaves and the rule silently stops requesting anyone.
- `require_code_owner_review` is off, so the owner is requested but the author merges after a teammate's approval.
- Migrations directory is not covered; a column drop ships with only a peer review.
- `.github/workflows/` is not covered, so anyone can change which checks are required or how deploy credentials are used.

**Evidence to produce:**
- `CODEOWNERS` file path; ruleset export showing `require_code_owner_review: true`.
- Team membership export for the owner teams at the audit date.

### CHG-05 — Emergency change path with post-hoc review

**Rule:** An emergency change path exists for production incidents. Every emergency change is labeled, deployed with a recorded justification, and receives a full post-hoc review within 2 business days. Emergency changes are reported to management.

**TSC:** CC8.1

**How to implement:**
- Define the path in `docs/runbooks/emergency-change.md` and link it from the PR template. The path never removes review entirely; it reduces the pre-merge bar (one approver from an on-call rotation, checks may be bypassed only by a break-glass team) and adds a post-merge obligation.
- Create a `break-glass` GitHub team that is empty by default. During an incident, an incident commander adds the responder for the duration; membership changes emit audit log events in GitHub's org audit log.
- Require the `emergency-change` label. A scheduled workflow lists open or recently merged PRs with the label that lack a linked post-incident review within 2 business days and posts to the security channel.
- Post-hoc review means: a second reviewer from CODEOWNERS reviews the merged diff, all skipped checks are re-run on `main`, and findings are either fixed in a follow-up PR or recorded in `.soc2/EXCEPTIONS.md`.
- Report monthly: count of emergency changes, whether each got its review on time, and whether any bypassed checks. This report is the auditor's sample source.

**Emergency change procedure:**

1. Declare the incident in the incident tool and record the incident ID; the incident commander confirms a code change is required and that no config-only mitigation (feature flag, rollback, scale-up) is sufficient.
2. Open the PR from a `hotfix/<incident-id>-*` branch, apply the `emergency-change` label, and put the incident ID and justification in the PR body using the template.
3. Obtain one approval from the on-call engineer or CODEOWNERS member who is not the author. If required checks cannot complete in time, the incident commander temporarily adds the responder to the `break-glass` bypass team and records the time in the incident timeline.
4. Merge and deploy through the normal pipeline (CHG-07); do not deploy from a laptop. Tag the release with `-hotfix` suffix.
5. Immediately after deploy, remove the responder from `break-glass`, and confirm the deployment record and audit log show who, what, when, and version (CHG-06).
6. Within 2 business days, a CODEOWNERS reviewer completes a full review of the merged diff, re-runs any bypassed checks, and links the review comment or follow-up PR from the incident record.
7. Include the change in the monthly emergency-change report with review-completion status; unresolved items become `.soc2/EXCEPTIONS.md` entries with an expiry.

**Code example:**

```yaml
# .github/workflows/emergency-audit.yml
name: emergency-change-audit
on:
  schedule: [{ cron: "0 9 * * 1-5" }]
permissions: { pull-requests: read, issues: write }
jobs:
  overdue:
    runs-on: ubuntu-latest
    steps:
      - name: List emergency PRs merged > 2 business days ago without review label
        env: { GH_TOKEN: "${{ secrets.GITHUB_TOKEN }}" }
        run: |
          # SOC2:CHG-05 flags emergency changes missing post-hoc review
          since=$(date -u -d '4 days ago' +%F)   # 2 business days incl. weekend margin
          gh pr list --state merged --label emergency-change \
            --search "merged:<${since} -label:post-review-complete" \
            --json number,title,mergedAt,author \
            --jq '.[] | "OVERDUE #\(.number) \(.title) merged \(.mergedAt) by \(.author.login)"' \
            | tee overdue.txt
          test ! -s overdue.txt || exit 1
```

**Common violations:**
- No defined path, so responders push directly to `main` with admin rights and nothing is labeled or reviewed afterward.
- The `break-glass` team has permanent members.
- Emergency PRs get a post-hoc "LGTM" with no re-run of skipped checks.
- No report; auditors discover emergency merges by sampling and find no justification.

**Evidence to produce:**
- Runbook path; list of PRs with `emergency-change` label for the period, each with the post-review link and completion date.
- GitHub org audit log entries for `break-glass` team membership changes.
- Monthly emergency-change report.

### CHG-06 — Tagged releases, deployment log, tested rollback

**Rule:** Every production release is tagged with an immutable version. Each deployment records who triggered it, what was deployed (version and commit), when, and to where. A rollback procedure is documented and exercised.

**TSC:** CC8.1, A1.2

**How to implement:**
- Tag releases with semver (`v1.42.0`) from the pipeline, using annotated tags. Build the image or artifact once, label it with the tag and commit SHA (`org.opencontainers.image.revision`), and promote the same artifact through environments; never rebuild for production.
- Record deployments in a durable place the auditor can query: GitHub Deployments API (`environment: production`), a `deployments` table, or the deploy tool's history (Argo CD, Spinnaker, Octopus). Include actor, version, commit, environment, start/end time, and outcome. Emit a `config.changed`-style audit event or Datadog deployment marker as well.
- Write `docs/runbooks/rollback.md`: how to redeploy the previous tag, how to handle irreversible migrations (expand/contract pattern, never drop columns in the same release), and who is authorized.
- Make rollback a one-command or one-click pipeline action (`gh workflow run deploy.yml -f version=v1.41.3`) rather than a manual sequence.
- Test rollback at least quarterly in staging, and after any change to the deploy pipeline; record the date, version pair, and duration.
- Require migrations to be backward compatible with the previous release for at least one version so rollback never needs a down-migration under pressure.

**Code example:**

```yaml
# .github/workflows/deploy.yml
name: deploy
on:
  push: { tags: ["v*.*.*"] }
  workflow_dispatch:
    inputs: { version: { description: "tag to (re)deploy, e.g. v1.41.3 for rollback", required: true } }
permissions: { contents: read, id-token: write, deployments: write }
jobs:
  production:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
        with: { ref: "${{ inputs.version || github.ref_name }}" }
      - uses: chrnorm/deployment-action@v2       # SOC2:CHG-06 durable who/what/when record
        id: dep
        with: { token: "${{ github.token }}", environment: production, ref: "${{ inputs.version || github.ref_name }}" }
      - run: ./scripts/deploy.sh "${{ inputs.version || github.ref_name }}"
      - uses: chrnorm/deployment-status@v2
        if: always()
        with: { token: "${{ github.token }}", deployment-id: "${{ steps.dep.outputs.deployment_id }}", state: "${{ job.status }}" }
```

**Common violations:**
- Production runs `main` at whatever commit was last pushed; no tag identifies what is live.
- Deploy history lives only in a Slack bot channel with 90-day retention.
- The rollback doc says "redeploy previous version" but the previous image was overwritten because tags are mutable (`latest`).
- Rollback has never been tried; the first attempt during an incident fails on a migration.

**Evidence to produce:**
- Git tag list for the period; GitHub Deployments export or deploy-table query showing actor, version, timestamp.
- `docs/runbooks/rollback.md` and the log of the most recent rollback test (date, versions, result).

### CHG-07 — Pipeline-only deploys with a deploy identity

**Rule:** Production deployments run only through the CI/CD pipeline using a dedicated deploy identity. Humans do not hold standing write access to production compute, configuration, or data.

**TSC:** CC8.1, CC6.1

**How to implement:**
- Create a deploy role per environment (e.g. `arn:aws:iam::123:role/github-deploy-prod`) trusted via OIDC federation from the CI provider, with the trust policy scoped to the repo and the `production` environment or tag ref. No stored cloud keys in CI.
- Grant the deploy role only what deploying needs (push image, update ECS service or Helm release, run migrations) and nothing interactive (`ssm:StartSession`, `rds:Connect` for humans, console access).
- Use GitHub `environment: production` with required reviewers if a human approval gate is desired; the approval is recorded in the deployment log.
- Give engineers read-only production access by default. Write or shell access is obtained via just-in-time elevation (AWS IAM Identity Center permission sets with time limits, Teleport, Vault SSH, GCP PAM) that is logged and expires in hours.
- Deny console and CLI writes from human roles with an SCP or IAM condition on `aws:PrincipalTag/role != deploy` for mutating actions on production resources.
- Alert (LOG-05) on any production mutation whose principal is not the deploy role.

**Code example:**

```hcl
# iam/deploy-role.tf
# SOC2:CHG-07 only GitHub Actions on this repo's production env can assume the deploy role
data "aws_iam_policy_document" "gh_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:acme/api:environment:production"]
    }
  }
}

resource "aws_iam_role" "github_deploy_prod" {
  name                 = "github-deploy-prod"
  assume_role_policy   = data.aws_iam_policy_document.gh_trust.json
  max_session_duration = 3600
}
```

**Common violations:**
- Engineers run `kubectl apply` or `terraform apply` against production from laptops with long-lived admin credentials.
- The CI deploy identity is an IAM user with an access key stored as a GitHub secret and never rotated.
- OIDC trust policy uses `sub: repo:acme/*` so any branch in any repo can deploy to production.
- "Temporary" production admin access granted during an incident is never revoked.

**Evidence to produce:**
- Deploy role trust policy and permissions policy export; SCP denying human writes.
- IAM Identity Center / Teleport access log showing time-bound elevations for the period.
- CloudTrail query showing production mutating API calls grouped by principal (all should be the deploy role).

### CHG-08 — Signed commits or artifacts and build provenance

**Rule:** Commits or build artifacts are cryptographically signed, and build provenance (what source, what builder, what inputs produced the artifact) is recorded and verifiable.

**TSC:** CC8.1

**How to implement:**
- Enable the `required_signatures` rule in the ruleset so every commit on the default branch is signed (GPG, SSH, or S/MIME). Developers configure `git config commit.gpgsign true`; GitHub web edits and merge commits are signed automatically.
- Sign container images and release artifacts with Sigstore cosign keyless (OIDC identity of the CI job), and verify at deploy time with a Kubernetes admission policy (Kyverno `verifyImages`, Sigstore policy-controller) or in the deploy script (`cosign verify --certificate-identity-regexp`).
- Generate SLSA provenance with `actions/attest-build-provenance` or `slsa-framework/slsa-github-generator`, attach it to the image or release, and verify with `gh attestation verify` or `slsa-verifier` before promoting.
- Produce an SBOM alongside provenance (SEC-05) and attest it too (`actions/attest-sbom`).
- Restrict which workflows may sign: use a reusable, pinned build workflow and check the certificate `Issuer` and `SubjectAlternativeName` match `https://github.com/acme/api/.github/workflows/release.yml@refs/tags/v*`.
- Store attestations in the registry (OCI referrers) or GitHub's attestation store, retained with the artifact.

**Code example:**

```yaml
# .github/workflows/release.yml (excerpt)
permissions: { contents: read, packages: write, id-token: write, attestations: write }
steps:
  - uses: docker/build-push-action@v6
    id: build
    with: { push: true, tags: "ghcr.io/acme/api:${{ github.ref_name }}", sbom: true }
  - uses: sigstore/cosign-installer@v3
  - name: Sign image (keyless, CI identity)
    run: cosign sign --yes ghcr.io/acme/api@${{ steps.build.outputs.digest }}   # SOC2:CHG-08
  - uses: actions/attest-build-provenance@v1                                     # SOC2:CHG-08 SLSA provenance
    with:
      subject-name: ghcr.io/acme/api
      subject-digest: ${{ steps.build.outputs.digest }}
      push-to-registry: true

# deploy-time verification (deploy.yml)
  - run: |
      gh attestation verify oci://ghcr.io/acme/api:${VERSION} --owner acme
      cosign verify ghcr.io/acme/api:${VERSION} \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        --certificate-identity-regexp '^https://github.com/acme/api/.github/workflows/release.yml@refs/tags/v'
```

**Common violations:**
- Images are signed but nothing verifies the signature before deploy, so signing is decorative.
- A long-lived cosign private key is stored as a CI secret and shared across repos.
- Provenance is generated for the image but the deploy pulls a mutable tag that could point elsewhere.
- Signed-commit rule is enabled but the merge queue bot's commits are unsigned, so the rule is disabled "to unblock".

**Evidence to produce:**
- Ruleset export showing `required_signatures`; `cosign verify` and `gh attestation verify` output from a production deploy log.
- Attestation stored in the registry or `gh attestation list` for the release.

### CHG-09 — Feature flags and runtime config changes are tracked

**Rule:** Every feature flag or runtime configuration change records who changed it, when, the old and new value, and a reason. Flags live in a flag service with an audit log or in config-as-code that goes through the PR process. Hardcoded toggles that are flipped by editing a constant and deploying are not acceptable for security-relevant behavior.

**TSC:** CC8.1, CC7.2

**How to implement:**
- Use a flag service with audit history (LaunchDarkly, Unleash, Flagsmith, ConfigCat, AWS AppConfig) or a versioned config file (`config/flags.yml`) changed only through PRs.
- Emit a `config.changed` audit event (LOG-01) when the application observes a flag or config change at runtime, including flag key, old value, new value, and actor if known.
- Restrict who can change production flags to the same roles that can deploy (CHG-07); require a reason field.
- Security-relevant flags (auth bypasses, rate-limit overrides, debug modes) must default to the safe value and expire: record an owner and removal date in the flag description.
- For SOC 1 relevance (financial logic), treat pricing, billing, and ledger toggles as changes requiring the same approval as code.

**Code example:**

```yaml
# config/flags.yml — reviewed through PR; CODEOWNERS covers this path (CHG-04)
# SOC2:CHG-09 flags are config-as-code with history in git and a mandatory reason
flags:
  new_invoice_pipeline:
    enabled: false
    owner: "@billing-team"
    reason: "Gradual rollout, ticket BILL-412"
    remove_by: "2026-12-31"
  auth_legacy_session_compat:
    enabled: false          # security-relevant: safe default off
    owner: "@security-team"
    reason: "Only for migration window; see EX-003 in .soc2/EXCEPTIONS.md"
    remove_by: "2026-10-15"
```

**Common violations:**
- `const ENABLE_MFA = false` flipped in a hotfix with no record of why.
- Flag service admin UI open to all engineers with no audit export.
- Rate-limit or auth-bypass flags left on after an incident.

**Evidence to produce:**
- Flag service audit log export for the period, or `git log -- config/flags.yml`.
- Audit log query for `config.changed` events.

## Review checklist

- [ ] CHG-01 — Is the target branch covered by an active ruleset requiring a PR, one non-author approval with last-push approval, no force push, and no bypass actors?
- [ ] CHG-02 — Are `test`, `sast`, `sca`, and `secret-scan` all green on this PR and still listed as required (not advisory) checks, with no `continue-on-error` on security jobs?
- [ ] CHG-03 — Does the PR body use the template, link a ticket, and have every security/data checklist item explicitly ticked or marked N/A?
- [ ] CHG-04 — If the diff touches auth, crypto, infra, CI, migrations, audit, or `.soc2/`, has the CODEOWNERS team approved (not just been requested)?
- [ ] CHG-05 — If this is an emergency change, is it labeled `emergency-change`, linked to an incident ID, and scheduled for a full review within 2 business days with any bypassed checks re-run?
- [ ] CHG-06 — Will this change ship under an immutable version tag with a deployment record, is the migration backward compatible with the previous release, and is the rollback runbook still accurate?
- [ ] CHG-07 — Does any deploy or infra change keep production writes limited to the OIDC-trusted deploy role, with no new long-lived keys or human standing access?
- [ ] CHG-08 — Are commits signed as required, and do release artifacts get signed and attested with verification enforced at deploy time?
- [ ] CHG-09 — Is every new or changed feature flag or runtime setting defined in the flag service or config-as-code with owner and reason, and does a security-relevant flag default to the safe value?
