## Why

One or two sentences on the problem this fixes. Link the issue.

## What changed

Bullet the user-visible effects, not the line-by-line diff.

## How it was tested

- [ ] Fresh `install.sh` run of this branch on a throwaway VM/container
- [ ] Clicked through the affected UI area (create/update/revoke subscription, tab touched)
- [ ] `python3 -c "import ast; ast.parse(open('panel.py').read())"` passes
- [ ] `bash -n install.sh` passes (if install changed)

## Data and privacy

- [ ] No real keys, tokens, UUIDs, seeds, emails, client IPs or passwords
      anywhere in the diff, including tests and fixtures (placeholders only)
- [ ] No new secrets, identifiers or traffic data written to on-disk journals

## Notes for the reviewer

Anything surprising in the diff — dead code removed, behaviour that looks
regressive but is not, migration steps for existing installs.
