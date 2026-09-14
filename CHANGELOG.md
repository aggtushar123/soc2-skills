# Changelog

## v0.1.0 — 2026-09-14 (public beta)

First tagged release.

- `soc2-dev` skill: SKILL.md with init, write, audit, evidence, and policy modes.
- Requirement registry: 66 engineering requirements mapped to Trust Service Criteria.
- Domain references for auth, API, data, logging, secrets, change management, infrastructure.
- Stack patterns for Node/Express, Python/FastAPI, Go, Java/Spring.
- 17 organizational policy templates and a policy-to-requirement map.
- Auditor checklist crosswalk (36 pointers) and CWE Top 25 map.
- Scripts: `soc2_init.py`, `soc2_scan.py` (with `--staged` pre-commit mode and inline
  suppressions), `control_map.py`.
- Regression test suite and CI (Python 3.9, 3.12, 3.13), self-scan, gitleaks.

Known limitations: the scanner is heuristic and cannot see object-level authorization,
tenant scoping, field-level encryption, CSRF, or session timeouts. Those need the
manual review in audit mode.
