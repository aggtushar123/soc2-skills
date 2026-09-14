# Baseline policy templates

Seventeen SOC 2 policy templates, converted to markdown from
[kurianoff/claude-skills-soc2-policies](https://github.com/kurianoff/claude-skills-soc2-policies) (MIT).
All use the `[COMPANY NAME]` placeholder.

These are the **organizational policies** the engineering requirements in
`../requirements.md` implement. When a repo has its own policies (see
`policies_dir` in `.soc2/config.yml`), those take precedence over these
templates. The `policy` mode of the skill drafts or updates them.

## Policy → engineering requirements

| Policy | File | Requirements it drives |
|--------|------|------------------------|
| Access Control Policy | `access_control_policy.md` | AUTH-01..10, DATA-08, INFRA-03 |
| Cryptography Policy | `cryptography_policy.md` | SEC-07, DATA-02, DATA-03, INFRA-04 |
| Data Management Policy | `data_management_policy.md` | DATA-01, DATA-04..07, DATA-09, DATA-10, LOG-03 |
| Secure Development Policy | `secure_development_policy.md` | API-01..10, SEC-01, SEC-03..06, CHG-01..04, CHG-07 |
| Operations Security Policy | `operations_security_policy.md` | LOG-01..07, SEC-03, SEC-05, INFRA-05, CHG-05, CHG-06 |
| Incident Response Plan | `incident_response_plan.md` | LOG-01, LOG-02, LOG-05 |
| Business Continuity and DR Plan | `business_continuity_and_disaster_recovery_plan.md` | DATA-07, INFRA-06, CHG-06 |
| Information Security Policy | `information_security_policy.md` | Umbrella for all; EVD-01, EVD-03 |
| Information Security Roles and Responsibilities | `information_security_roles_and_responsibilities.md` | EVD-01 owners, CHG-04 |
| Third-Party Management Policy | `third_party_management_policy.md` | SEC-03, INFRA-01 (vendor and dependency risk) |
| Risk Management Policy | `risk_management_policy.md` | EVD-03, CHG-03 |
| Asset Management Policy | `asset_management_policy.md` | DATA-01, INFRA-01 |
| Physical Security Policy | `physical_security_policy.md` | Not code-enforced; INFRA-02 by analogy |
| Human Resources Security Policy | `human_resources_security_policy.md` | AUTH-07, AUTH-10 |
| Acceptable Use Policy | `acceptable_use_policy.md` | Not code-enforced |
| Removable Media Policy | `removable_media_policy.md` | DATA-10 |
| Code of Conduct | `code_of_conduct.md` | Not code-enforced |
