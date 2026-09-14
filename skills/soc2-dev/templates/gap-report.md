# SOC 2 Gap Report — [DATE]

**System:** [SYSTEM NAME]  **Scope:** Security, Confidentiality [adjust]  **Prepared by:** soc2-dev skill plus [reviewer]

## Readiness

| Category | Must requirements | Met | Partial | Missing | Excepted | Score |
|----------|-------------------|-----|---------|---------|----------|-------|
| AUTH | 8 | | | | | |
| API | 8 | | | | | |
| DATA | 9 | | | | | |
| LOG | 5 | | | | | |
| SEC | 5 | | | | | |
| CHG | 5 | | | | | |
| INFRA | 4 | | | | | |
| EVD | 2 | | | | | |
| **Total** | **46** | | | | | **__%** |

Conditional must requirements (DATA-11 if Processing Integrity, DATA-12 if Privacy) are added to the denominator only when that category is in scope in `.soc2/config.yml`.

Score = met / (must requirements in scope). Under 75% means do not schedule an audit window yet.

## Findings

Ordered by priority. Critical = missing **must** in CC6/CC7 with no compensating control.

| # | Priority | Requirement | Status | Where | Gap | Fix | Effort | Owner |
|---|----------|-------------|--------|-------|-----|-----|--------|-------|
| 1 | critical | | | | | | | |

## Scanner output

Attach or link `.soc2/reports/scan-[DATE].md`. Scanner findings are leads, not proof.

## Control map drift

Rows in `CONTROL_MAP.md` that point at code that no longer exists, or annotated controls
absent from the map (from `scripts/control_map.py`).

## Also noticed

Items outside the requirement registry worth fixing.

## Next steps

1. 
2. 
3. 
