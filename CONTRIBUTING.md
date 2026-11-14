# Contributing to cGRASP

Thanks for your interest. This is a research prototype; contributions that
improve correctness, clarity, tests and documentation are welcome.

## Before you start

- Read [README.md](./README.md) and [SECURITY.md](./SECURITY.md).
- For non-trivial changes, open an issue first so we can agree on scope.
- cGRASP is a **prototype**: please do not present it as production-ready.

## Development environment

Requirements: Python 3.10 or newer, Git, and (for the namespace tests) Linux
with root, `iproute2`, `tcpdump` and `tshark`.

```bash
git clone <your-fork-url> cGRASP
cd cGRASP
python3 -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -U pip
python -m pip install -e ".[test]"
```

Do not use the historical `c/bin/python` path; it was a machine-local virtual
environment and is no longer part of the workflow.

## Running tests

```bash
pytest -q                              # unit + loopback tests
pytest -q -m "not relay"               # skip privileged relay tests
sudo -E PYTHON_BIN="$PWD/.venv/bin/python" \
    scripts/test_relay_multi_namespaces.sh relay
```

Guidelines:

- Every bug fix must come with a regression test that fails without the fix.
- Tests must not depend on fixed UDP ports; use ephemeral ports.
- Tests that need IPv6, `tshark`, root or network namespaces must be marked
  `network`, `multicast` or `relay` and skip cleanly when unavailable.
- Do not commit packet captures, logs or generated artifacts.

## Code style

- Python: follow PEP 8, 4-space indentation, `from __future__ import
  annotations` where useful. `ruff check` must pass.
- Use `logging`, not `print()`, in library code.
- Prefer explicit exceptions over bare `except:`.
- Keep the public ASA-facing API (`discover`, `req_negotiate`,
  `negotiate_step`, `end_negotiate`, `synchronize`, `flood`, `register_obj`,
  ...) source-compatible unless a change is explicitly agreed.
- Shell: `set -euo pipefail`, quote variables, and pass `shellcheck`.

Formatting/linting (when available):

```bash
ruff check .
shellcheck scripts/*.sh ASA-examples/cgrasp_relay_e2e/*.sh
```

## Commit messages

Use a short imperative subject, optionally prefixed by the area:

```
coap: reject multicast FETCH without content-format 60
relay: bound the discovery response window
docs: add install instructions for Windows
```

Reference the relevant issue or finding ID in the body (e.g. `Refs: D4-02`).
Keep unrelated changes in separate commits.

## Developer Certificate of Origin

By contributing you certify that you have the right to submit the work under
this project's license and agree to the
[Developer Certificate of Origin 1.1](https://developercertificate.org/).
Add a sign-off line to every commit:

```
Signed-off-by: Your Name <your.email@example.com>
```

Use `git commit -s` to add it automatically.

## Pull requests

Please make sure that:

- [ ] the change is focused and described in the PR text,
- [ ] new behaviour is covered by tests,
- [ ] `pytest -q` passes locally,
- [ ] `ruff check .` passes (if available),
- [ ] no generated artifacts, captures, credentials or personal paths are added,
- [ ] documentation is updated when behaviour or CLI options change,
- [ ] commits are signed off (DCO).

Maintainers may ask for changes or close PRs that are out of scope for a
research prototype.

## Reporting security issues

Do **not** open a public issue. See [SECURITY.md](./SECURITY.md).

## License

By contributing you agree that your contributions are licensed under the
BSD 3-Clause License (see [LICENSE](./LICENSE)).
