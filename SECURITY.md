# Security Policy

## Reporting a vulnerability

Open a private security advisory on GitHub (Security tab, "Report a vulnerability")
or email the maintainer listed in `.github/CODEOWNERS`. Do not open a public issue.
You will get an acknowledgment within 2 business days.

## Scope

This repository ships documentation and three standard-library Python scripts. The
scripts read files in the target repository and run `git` read-only commands. They do
not make network calls. A reported issue is in scope if the scanner can be made to
crash, hang, or silently skip files on crafted input, or if a template introduces an
insecure default into a downstream repository.

## Remediation targets

| Severity | Fix within |
|----------|------------|
| Critical | 7 days |
| High | 30 days |
| Medium | 90 days |
