# Contributing to SecretBroker

Thanks for helping. Bug reports, ideas, docs and code are all welcome. For anything bigger than a small fix, please open
an issue first so we can agree on the approach; [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) is the design everyone
builds against, and changes to it are discussed before code.

**Security issues are never reported in public.** See [SECURITY.md](SECURITY.md).

## Development setup

Desktop (Windows 10/11, Python 3.12):

```powershell
git clone https://github.com/xBofi/SecretBroker.git
cd SecretBroker
python -m venv .venv
.venv\Scripts\python.exe -m pip install -e .[dev]
.venv\Scripts\secretbroker.exe      # the app in development mode (same app, without account isolation)
```

Development mode keeps its data in your own profile and does not touch an installed SecretBroker. To try your code
inside the installed, isolated service, run `.\tools\update_installed.ps1` (asks for UAC; add `-Full` when
dependencies or `installer\` change).

Team server (any OS, Python 3.12):

```bash
python -m venv .venv-server
.venv-server/bin/python -m pip install -e server httpx    # Windows: .venv-server\Scripts\python.exe
```

See [server/README.md](server/README.md) for running it locally and with Docker.

## Tests

Every test file is a plain script: run it with the venv's Python. It prints what it checks and exits non-zero on the
first failure. All tests use temporary vaults and **fake** credentials.

| Command | What it covers |
|---|---|
| `.venv\Scripts\python.exe tests\test_e2e.py` | Service, identity proofs, approvals, actions, MCP (no GUI). Takes a few minutes. **Must pass for every PR.** |
| `.venv\Scripts\python.exe tests\test_personal.py` | Personal-use features, when present |
| `.venv\Scripts\python.exe tests\test_teams.py` | Desktop side of team sharing against a local server, when present |
| `.venv\Scripts\python.exe tests\test_gui.py` | The real app window, tray, approvals and MCP over HTTP, with a separate test vault. Saves screenshots. Needs a desktop session. |
| `.venv\Scripts\python.exe tests\test_browser.py` | The browser extension in a real Microsoft Edge (or Chrome for Testing), with its native host and the app, against local test sites. Saves screenshots. Skips without a supported browser. |
| `.venv\Scripts\python.exe tests\test_ssh.py` | SSH against a local test server |
| `.venv\Scripts\python.exe tests\test_exposure.py` | Exposure scanning against a fake user profile (needs `git`) |
| `python server/tests/test_server.py` | Team server API (any OS) |

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs the end-to-end, personal and team tests on Windows and
the server tests on Linux. Please run `test_gui.py` too when you change the app's interface, and `test_browser.py` when you change the
extension or its native host.

## Code style

- **Match the surrounding code**: its comment density, naming, idioms and small functions. Read the module before
  changing it. No new dependencies without discussing them first.
- **User-facing text is Spanish** (UI, error messages, notifications): plain, short, like the existing app. English and
  other languages will come through i18n (see [docs/ROADMAP.md](docs/ROADMAP.md)); until then do not mix languages in
  the UI.
- **Code comments, docs and commit messages are English.**
- The UI follows the design system described at the top of `secretbroker/web/styles.css`.
- **Never print or log secret values**, not even in tests or debug output. Use obviously fake values in tests.
- **No new password prompts.** The user types a password once (to unlock, or to link a team account); after that,
  approvals are one click with a presence check. Proposals that add friction need a strong security reason.
- Anything that decides where a key can go (hosts, programs, environment variables) must stay behind a user approval
  and out of the AI's reach. New AI-facing operations must never return a secret value.

## Commits and pull requests

- One logical change per commit. The subject says what the user gets, in the imperative and in plain words, for
  example `Choose how often keys are tested, in general and per credential`. Maintainers add the version in
  parentheses when releasing.
- Update `README.md` / `README.es.md` when behaviour visible to users changes, and `docs/ARCHITECTURE.md` when a design
  decision changes.
- Fill in the pull request template; say which tests you ran.
- Do not bump version numbers or edit `.github/workflows/release.yml` in a feature PR.

## Releases (maintainers only)

Releases are built, **signed** and published by `.github/workflows/release.yml` when a maintainer pushes a `v<version>`
tag. The Ed25519 release signing key is a repository secret available only to maintainers; contributors never need it
and must not try to produce signed builds. Installed apps refuse any update that is not signed with that key.

## License

By contributing you agree that your contributions are licensed under the [MIT License](LICENSE).
