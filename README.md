# soc2-dev — a Claude Code skill for SOC 2 compliant engineering

Drop one folder into any repository and Claude writes, reviews, and audits code
against SOC 2 Trust Service Criteria from the first commit: authenticated-by-default
endpoints, validated inputs, parameterized queries, audit logging with redaction,
approved cryptography, secrets handling, CI gates, and infrastructure hygiene, each
annotated with a requirement ID and mapped to evidence an auditor can inspect.

```
skills/soc2-dev/
├── SKILL.md                      instructions Claude follows (modes, workflow, rules)
├── references/
│   ├── requirements.md           the registry: 66 engineering requirements → TSC criteria
│   ├── auth-and-access.md        AUTH-01..10
│   ├── api-endpoint-checklist.md API-01..10
│   ├── data-handling.md          DATA-01..10, classification, retention defaults
│   ├── logging-and-audit.md      LOG-01..07, audit event schema, redaction
│   ├── secrets-and-config.md     SEC-01..07, approved crypto, patch SLAs
│   ├── change-management.md      CHG-01..08, branch protection, CODEOWNERS
│   ├── infrastructure.md         INFRA-01..07, IaC, IAM, encryption, DR
│   ├── coverage-checklist.md     auditor code-review checklist → requirement IDs
│   ├── cwe-top25-map.md          CWE Top 25 → requirement IDs
│   ├── stack-patterns/           concrete code: Node/Express, Python/FastAPI, Go, Java/Spring
│   ├── trust-service-criteria.md full TSC reference (CC1-CC9, A1, C1, PI1, P1-P8)
│   └── policies/                 17 organizational policy templates + policy→requirement map
├── scripts/
│   ├── soc2_init.py              scaffold .soc2/, PR template, CODEOWNERS, CI gates, SECURITY.md
│   ├── soc2_scan.py              heuristic scanner → findings with requirement IDs (CI-gateable)
│   └── control_map.py            reconcile SOC2:<ID> annotations with .soc2/CONTROL_MAP.md
└── templates/                    files init writes into a repo
```

## Install

Per repository (recommended, so the skill travels with the code and CI can run the scanner):

```bash
git clone https://github.com/aggtushar123/soc2-skills.git /tmp/soc2-skills
mkdir -p .claude/skills
cp -r /tmp/soc2-skills/skills/soc2-dev .claude/skills/soc2-dev
python3 .claude/skills/soc2-dev/scripts/soc2_init.py . --company "Acme Corp" --owner "@security-team"
```

Or globally for every project on your machine:

```bash
cp -r skills/soc2-dev ~/.claude/skills/soc2-dev
```

Claude Code picks the skill up automatically. It triggers when a repo has a `.soc2/`
directory, when you mention SOC 2 or compliance, or when you write endpoints, auth,
data models, loggers, secrets, CI, or infrastructure in a repo where it is installed.

## How it works

1. **Registry.** `references/requirements.md` turns each Trust Service Criterion into
   concrete engineering rules with IDs (`AUTH-01`, `API-03`, `LOG-03` ...), a severity
   (must / should / may), and a TSC mapping. Everything else keys off these IDs.
2. **Write mode (default).** When you ask Claude for a new endpoint, model, job, or
   pipeline, it classifies the change, loads only the relevant domain checklist and the
   matching stack pattern, implements the requirements alongside the feature, annotates
   each enforcement point with `// SOC2:<ID>`, updates `.soc2/CONTROL_MAP.md`, and ends
   with a compliance summary you can paste into the PR.
3. **Audit mode.** `soc2_scan.py` finds obvious violations (secrets, unauthenticated
   routes, string-built SQL, PII in logs, wildcard CORS, weak crypto, open security
   groups, root containers, missing CI gates). Claude then reviews entry points manually
   and writes a prioritized gap report.
4. **Evidence mode.** Regenerates the control map, a routes manifest, and an evidence
   index so an auditor can go from requirement to code to proof.
5. **Policy mode.** Drafts organizational policies from 17 templates and appends a
   "Technical enforcement" section listing the requirement IDs that implement each one.

Config lives in `.soc2/config.yml`: company, TSC categories in scope, data classes,
MFA scope, password minimums, token TTLs, retention periods, patch SLAs, public routes,
and scan ignores. Config overrides the registry defaults.

## Try it

```bash
# Ask Claude, in a repo with the skill installed:
#   "Add a POST /invoices endpoint that creates an invoice for the current tenant"
#   "Audit this repo for SOC 2"
#   "Prepare evidence for CC6 and CC7"
#   "Draft our access control policy"

# Or run the scripts directly:
python3 .claude/skills/soc2-dev/scripts/soc2_scan.py . --format md
python3 .claude/skills/soc2-dev/scripts/soc2_scan.py . --format json --fail-on high   # CI gate
python3 .claude/skills/soc2-dev/scripts/soc2_scan.py . --staged --fail-on high        # pre-commit gate
python3 .claude/skills/soc2-dev/scripts/control_map.py . --strict
```

A wrong or accepted finding can be silenced on that line with a `soc2:ignore` comment
(or `soc2:ignore-next-line`). A suppression is a review decision, not an exception; a
**must** requirement that cannot be met goes in `.soc2/EXCEPTIONS.md`.

The scripts need Python 3.9 or newer and nothing else. PyYAML is used for the config
if installed; otherwise a built-in parser handles the config template's subset.

## Development

```bash
python3 -m unittest discover -s tests -v
```

The suite has true-positive fixtures (every planted violation must be reported with the
right ID), false-positive fixtures (ordinary code must produce nothing at medium or
above), staged-mode and suppression tests, and consistency checks that every requirement
ID used anywhere exists in the registry. CI runs it on Python 3.9, 3.12, and 3.13, then
dogfoods the scanner on this repo and runs gitleaks. Scanner changes need a true-positive
and a false-positive test.

## Status

Public beta (v0.1.0). The Claude-facing half, meaning SKILL.md and the references, is
stable. The scanner is heuristic and its patterns will keep being tuned; see CHANGELOG.md.

## What this skill does not do

- It does not make you SOC 2 compliant by itself. SOC 2 is an attestation over
  organizational controls and evidence collected over an observation period. This skill
  covers the engineering half and points at the policies for the rest.
- The scanner is heuristic. Findings are leads for review, not proof.
- Branch protection, IdP configuration, vendor reviews, and access reviews happen
  outside the repo. Init prints the manual steps.

## Credits

- Policy templates converted from [kurianoff/claude-skills-soc2-policies](https://github.com/kurianoff/claude-skills-soc2-policies) (MIT).
- Trust Service Criteria reference from [alirezarezvani/claude-skills](https://github.com/alirezarezvani/claude-skills) `ra-qm-team/skills/soc2-compliance` (MIT).

## License

MIT
