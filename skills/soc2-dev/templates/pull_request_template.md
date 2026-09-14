## Summary

<!-- What and why. Link the ticket. (CHG-03) -->

Ticket: 

## Change type

- [ ] Feature
- [ ] Bug fix
- [ ] Refactor
- [ ] Infrastructure / CI
- [ ] Emergency change (label `emergency-change`; post-hoc review within 2 business days, CHG-05)

## SOC 2 impact

<!-- Tick everything this PR touches. Each ticked item must be addressed below or in CONTROL_MAP.md. -->

- [ ] Adds or changes an endpoint (AUTH-01, AUTH-02, API-01..06, LOG-01)
- [ ] Touches authentication, sessions, tokens, MFA, or roles (AUTH-*)
- [ ] Adds or changes stored data with PII, PHI, payment, or restricted fields (DATA-01, DATA-02, DATA-04..06)
- [ ] Changes logging, alerting, or monitoring (LOG-*)
- [ ] Touches secrets, config, crypto, or dependencies (SEC-*)
- [ ] Changes CI, branch settings, or deployment (CHG-*)
- [ ] Changes infrastructure, IAM, or networking (INFRA-*)
- [ ] None of the above

## Controls

<!-- Paste the compliance summary produced by the soc2-dev skill, or fill in manually. -->

- Implemented:
- Reused existing:
- Skipped (with reason):
- Exceptions applied:
- `CONTROL_MAP.md` updated: yes / no / not needed

## Checklist

- [ ] New routes are authenticated unless listed in `public_routes` (AUTH-01)
- [ ] No secrets, tokens, or credentials in the diff (SEC-01)
- [ ] No PII or secrets written to logs (LOG-03)
- [ ] Inputs validated with a schema (API-01)
- [ ] Queries parameterized (API-03)
- [ ] Tests added or updated for security-relevant behavior
- [ ] Security-sensitive paths reviewed by a CODEOWNER (CHG-04)
