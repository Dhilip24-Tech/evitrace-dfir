## Summary

What problem does this change solve, and why this approach?

## What changed

- <!-- describe -->
- <!-- describe -->

## Verification

- [ ] `python -m pytest -q`
- [ ] `python -m ruff check src tests scripts`
- [ ] `python -m ruff format --check src tests scripts`
- [ ] `python -m mypy src`

## Impact

- Behavior change: <!-- none / describe -->
- Certificate or schema change: <!-- none / describe -->
- New dependency: <!-- none / name and reason -->
- Documentation updated: <!-- yes / not needed -->

## Checklist

- [ ] The change is focused and does not include unrelated refactoring.
- [ ] Tests cover the new or changed behavior.
- [ ] No real evidence, case databases, `key.bin` files, certificates from a live
      investigation, or credentials are included.
- [ ] Untrusted event text still has no instruction authority.
- [ ] If demo artifacts or screenshots were regenerated, the reason is explained
      and the affected documentation is updated.
