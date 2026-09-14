# SOC 2 Control Exceptions

A requirement that cannot be met as written is recorded here rather than ignored.
Every exception needs a compensating control, an approver, and an expiry. Expired
exceptions are findings. Review this file quarterly.

| ID | Requirement | Scope (paths/services) | Rationale | Compensating control | Approver | Opened | Expires | Status |
|----|-------------|------------------------|-----------|----------------------|----------|--------|---------|--------|
| EX-001 | (example) AUTH-03 | `legacy-admin/` | Legacy admin console has no MFA support; migration scheduled Q1 | VPN plus IP allow-list; access limited to 3 named admins; quarterly access review | [name] | 2026-09-14 | 2027-03-31 | open |
