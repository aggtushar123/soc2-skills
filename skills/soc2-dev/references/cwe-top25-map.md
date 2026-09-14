# CWE Top 25 to requirement map

The MITRE CWE Top 25 Most Dangerous Software Weaknesses (2024 list) mapped to the
requirement IDs that prevent each. Auditors sometimes ask for this as evidence for
CC6.6 and CC7.1. SAST rulesets (Semgrep `p/cwe-top-25`, CodeQL security-extended)
cover most of these automatically (SEC-04); the rest are design controls.

| Rank | CWE | Weakness | Requirement IDs | Detected by |
|------|-----|----------|-----------------|-------------|
| 1 | CWE-79 | Cross-site scripting | API-02, API-06 (CSP) | SAST, template auto-escaping |
| 2 | CWE-787 | Out-of-bounds write | SEC-03 (memory-safe runtime or patched native deps) | SCA; N/A for managed languages |
| 3 | CWE-89 | SQL injection | API-03 | scanner, SAST |
| 4 | CWE-352 | Cross-site request forgery | API-06 | manual review, SAST |
| 5 | CWE-22 | Path traversal | API-01 (path input validation), API-10 (server-generated keys) | SAST |
| 6 | CWE-125 | Out-of-bounds read | SEC-03 | SCA; N/A for managed languages |
| 7 | CWE-78 | OS command injection | API-03 | scanner, SAST |
| 8 | CWE-416 | Use after free | SEC-03 | N/A for managed languages |
| 9 | CWE-862 | Missing authorization | AUTH-02 | manual review |
| 10 | CWE-434 | Unrestricted upload of dangerous file type | API-10 | manual review |
| 11 | CWE-94 | Code injection | API-03 (eval, dynamic code) | scanner, SAST |
| 12 | CWE-20 | Improper input validation | API-01, DATA-11 | scanner (validation lib presence), SAST |
| 13 | CWE-77 | Command injection | API-03 | scanner, SAST |
| 14 | CWE-287 | Improper authentication | AUTH-01, AUTH-05, API-11 | scanner (route auth, webhook verifier), manual review |
| 15 | CWE-269 | Improper privilege management | AUTH-09, INFRA-03 | manual review, IaC scan |
| 16 | CWE-502 | Deserialization of untrusted data | API-01 (schema-bound parsing; no pickle/ObjectInputStream/yaml.load on input) | SAST |
| 17 | CWE-200 | Exposure of sensitive information | API-05, LOG-03, DATA-06 | scanner (log PII, debug), manual review |
| 18 | CWE-863 | Incorrect authorization | AUTH-02, DATA-08 | manual review |
| 19 | CWE-918 | Server-side request forgery | API-01 (URL allow-list for outbound fetches), INFRA-02 (metadata endpoint blocked) | SAST |
| 20 | CWE-119 | Buffer overflow | SEC-03 | N/A for managed languages |
| 21 | CWE-476 | NULL pointer dereference | CHG-02 (tests), SEC-04 | SAST |
| 22 | CWE-798 | Hardcoded credentials | SEC-01 | scanner, secret scan |
| 23 | CWE-190 | Integer overflow | API-01 (bounded numeric inputs), DATA-11 | SAST |
| 24 | CWE-400 | Uncontrolled resource consumption | API-04 (rate and size limits), INFRA-06 | scanner (rate-limit presence) |
| 25 | CWE-306 | Missing authentication for critical function | AUTH-01, AUTH-03 (MFA on admin) | scanner, manual review |

Weaknesses that are frequent in web services but outside the Top 25 and still
covered: CWE-327 broken crypto (SEC-07), CWE-330 weak randomness (SEC-07), CWE-295
improper certificate validation (DATA-03), CWE-532 sensitive data in logs (LOG-03),
CWE-613 insufficient session expiration (AUTH-05), CWE-770 missing throttling
(API-04), CWE-345 insufficient verification of data authenticity (API-11).

## Evidence

- SAST job name and ruleset (SEC-04) showing CWE coverage, plus the last run's report.
- This table, cross-referenced with `.soc2/CONTROL_MAP.md` status for each ID.
