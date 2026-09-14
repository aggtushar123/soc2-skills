## Summary

<!-- What changed and why. -->

## Checklist

- [ ] `python3 -m unittest discover -s tests` passes locally
- [ ] Scanner changes include a true-positive and a false-positive test in `tests/test_soc2_scan.py`
- [ ] New requirement IDs are added to `references/requirements.md` first, then to the domain reference, `templates/CONTROL_MAP.md`, and `coverage-checklist.md`
- [ ] No real secrets in fixtures (use obviously fake values that still match the patterns)
