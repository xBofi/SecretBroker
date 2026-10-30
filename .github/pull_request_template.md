## What and why

<!-- What does this change give the user? Link the issue: Fixes #123 -->

## How

<!-- Short notes on the approach, anything reviewers should look at first. -->

## Tests

- [ ] `tests\test_e2e.py`
- [ ] `tests\test_personal.py` / `tests\test_teams.py` (if touched)
- [ ] `tests\test_gui.py` (if the interface changed)
- [ ] `server/tests/test_server.py` (if the server changed)
- [ ] Other:

## Checklist

- [ ] No secret values are printed, logged or committed (tests use fake values)
- [ ] No new password prompts; approvals stay one click
- [ ] Anything that widens where a key can go still needs the user's approval
- [ ] UI text in Spanish; code comments in English; matches the surrounding code
- [ ] README / docs updated if behaviour or design changed
- [ ] No version bump
