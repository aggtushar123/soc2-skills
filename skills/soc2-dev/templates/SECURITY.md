# Security Policy

## Reporting a vulnerability

Email **[security@example.com]**. Include steps to reproduce, affected versions, and
impact. You will receive an acknowledgment within 2 business days and a status update
at least every 7 days until resolution. Do not open public issues for security reports.

## Supported versions

| Version | Supported |
|---------|-----------|
| main / latest release | yes |
| older releases | security fixes only for [N] months after the next release |

## Remediation targets (SEC-03)

| Severity | Fix deployed within |
|----------|---------------------|
| Critical | 7 days |
| High | 30 days |
| Medium | 90 days |
| Low | 180 days |

## Engineering controls

This repository follows SOC 2 engineering requirements enforced through the
`soc2-dev` skill. The control map is in `.soc2/CONTROL_MAP.md`; exceptions in
`.soc2/EXCEPTIONS.md`.
