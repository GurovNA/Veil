# Contributing to Veil

Thanks for interest in improving the panel. This document covers the small
amount of process that makes contributions easy to review.

## Before you start

- Read [SECURITY.md](SECURITY.md) — report vulnerabilities privately, not here.
- Pick or open an issue first for anything larger than a typo. If you plan to
  work on something, say so in the issue so we do not duplicate effort.
- The target branch is `main`. Development happens against the release line
  shown in the changelog.

## Development environment

Veil installs as a systemd service on a clean Ubuntu box, so the cheapest
honest environment is a throwaway VM or container:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/GurovNA/Veil/main/install.sh)
```

The panel runs as `vpnpanel.service`; the web UI listens on `8443`. Never
develop against a production node with real subscribers.

Layout of the repository:

| Path | Role |
|------|------|
| `panel.py` | single-file Flask application: all routes, config writers, schedulers |
| `index.html` | admin UI (vanilla JS, no build step) |
| `install.sh` | bootstrapper: dependencies, systemd units, initial credentials |
| `decoy/`, `appicons/`, `docs/` | static assets and public documentation |

`panel.py` is large on purpose: it is delivered as one file so that install,
update and rollback stay a single copy operation. Please keep it that way.

## Running checks

There is no heavyweight CI. Before opening a pull request:

```bash
python3 -c "import ast; ast.parse(open('panel.py').read())"   # syntax
node --check index.html 2>/dev/null || true                    # if node present
bash -n install.sh                                             # shell syntax
```

Then install the branch on a test box and click through the area you touched:
subscriber create/update/revoke, the UI tab you changed, and the Telegram
subscription link. A change that cannot be shown working on a test box is not
ready.

## Code style

- Python: follow the surrounding code, 4 spaces, type-free but documented by
  docstrings in Russian or English (match the neighbouring function).
- Comments explain *why*, not *what*; remove any that describe the task.
- No new runtime dependencies unless the pull request explains why the
  standard library or an already-installed tool is not enough.
- Do not introduce build tooling, linter configs or formatters into the tree;
  they change thousands of lines and are reviewed as their own discussion.

## Data and privacy rules (strict)

These are the parts of review that reject patches fastest:

- Personal data of subscribers — emails, tokens, UUIDs, seeds, client IPs,
  keys — must never appear in source, comments, commit messages, logs or
  issue text. Use obvious placeholders (`user@example.com`, `deadbeef…`).
- Anything secret must never be hard-coded; read it from the panel's settings
  store or environment.
- Traffic accounting, bans and telemetry must not add identifying information
  to on-disk journals beyond what the panel already stores.

## Pull request checklist

- [ ] Short reason *why* in the description, not only what changed
- [ ] One logical change per pull request
- [ ] Tested on a fresh install of the branch, results mentioned
- [ ] No secrets or real subscriber data anywhere in the diff
- [ ] Docs/changelog updated if user-visible behaviour changed

Keep pull requests small; a 30-line diff gets reviewed the same day, a
900-line diff waits.

## License

By submitting a pull request you agree that your contribution is licensed
under the project's MIT license.
