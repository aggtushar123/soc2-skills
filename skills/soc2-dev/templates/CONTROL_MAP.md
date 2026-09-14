# SOC 2 Control Map

Maps engineering requirements (see the soc2-dev skill's `references/requirements.md`)
to where they are implemented in this repository and the evidence an auditor can inspect.
Update this file in the same pull request as the code it describes.

Status: **met** | **partial** | **missing** | **excepted** (see `EXCEPTIONS.md`) | **n/a** (category out of scope)

| Requirement | Status | Implementation (file:symbol) | Evidence | Owner | Last verified |
|-------------|--------|------------------------------|----------|-------|---------------|
| AUTH-01 | missing | | | | |
| AUTH-02 | missing | | | | |
| AUTH-03 | missing | | | | |
| AUTH-04 | missing | | | | |
| AUTH-05 | missing | | | | |
| AUTH-06 | missing | | | | |
| AUTH-07 | missing | | | | |
| AUTH-08 | missing | | | | |
| AUTH-09 | missing | | | | |
| AUTH-10 | missing | | | | |
| API-01 | missing | | | | |
| API-02 | missing | | | | |
| API-03 | missing | | | | |
| API-04 | missing | | | | |
| API-05 | missing | | | | |
| API-06 | missing | | | | |
| API-07 | missing | | | | |
| API-08 | missing | | | | |
| API-09 | missing | | | | |
| API-10 | missing | | | | |
| API-11 | missing | | | | |
| DATA-01 | missing | | | | |
| DATA-02 | missing | | | | |
| DATA-03 | missing | | | | |
| DATA-04 | missing | | | | |
| DATA-05 | missing | | | | |
| DATA-06 | missing | | | | |
| DATA-07 | missing | | | | |
| DATA-08 | missing | | | | |
| DATA-09 | missing | | | | |
| DATA-10 | missing | | | | |
| DATA-11 | n/a | | | | |
| DATA-12 | n/a | | | | |
| LOG-01 | missing | | | | |
| LOG-02 | missing | | | | |
| LOG-03 | missing | | | | |
| LOG-04 | missing | | | | |
| LOG-05 | missing | | | | |
| LOG-06 | missing | | | | |
| LOG-07 | missing | | | | |
| SEC-01 | missing | | | | |
| SEC-02 | missing | | | | |
| SEC-03 | missing | | | | |
| SEC-04 | missing | | | | |
| SEC-05 | missing | | | | |
| SEC-06 | missing | | | | |
| SEC-07 | missing | | | | |
| CHG-01 | missing | | | | |
| CHG-02 | missing | | | | |
| CHG-03 | missing | | | | |
| CHG-04 | missing | | | | |
| CHG-05 | missing | | | | |
| CHG-06 | missing | | | | |
| CHG-07 | missing | | | | |
| CHG-08 | missing | | | | |
| CHG-09 | missing | | | | |
| INFRA-01 | missing | | | | |
| INFRA-02 | missing | | | | |
| INFRA-03 | missing | | | | |
| INFRA-04 | missing | | | | |
| INFRA-05 | missing | | | | |
| INFRA-06 | missing | | | | |
| INFRA-07 | missing | | | | |
| EVD-01 | partial | `.soc2/CONTROL_MAP.md` | this file | | |
| EVD-02 | missing | | `grep -rn "SOC2:" src/` | | |
| EVD-03 | met | `.soc2/EXCEPTIONS.md` | that file | | |

## Example row

| Requirement | Status | Implementation (file:symbol) | Evidence | Owner | Last verified |
|-------------|--------|------------------------------|----------|-------|---------------|
| AUTH-01 | met | `src/middleware/auth.ts:requireAuth`, applied in `src/app.ts` before all routers | Route manifest `.soc2/routes.md`; test `test/auth.test.ts` proves 401 on missing token | @platform-team | 2026-09-14 |
