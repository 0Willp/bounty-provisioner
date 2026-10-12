# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`bounty-provisioner` is a **single-file installer** (`provisioner.py`) that turns a clean Debian/
Ubuntu/Kali box into a bug-bounty recon workstation: it creates `~/bounty/{tools,targets,wordlists}`
and installs ~85 Go tools + pipx (Python) tools + a few git/compiled tools + wordlists, for
**authorized** security research.

This directory is **its own git repo** (published as `0Willp/bounty-provisioner`) but is also one
subproject of a larger workspace — see the parent `../CLAUDE.md`, which describes how the ops scripts
cooperate through the shared `~/bounty/` layout. The provisioner is the **installer** that the sibling
recon/workflow repos depend on.

The script targets a **Linux VPS** and shells out to `apt`, `sudo`, `go`, `git`, `curl`, `cargo`, etc.;
it will not run end-to-end on the Windows dev machine. The **pytest suite is pure Python and runs
anywhere** — it is the automated gate here.

## Commands

```bash
# Tests — Linux
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements-dev.txt && pytest -q

# Tests — Windows dev box (the `python`/`python3` alias is often absent; use the `py` launcher)
py -m venv .venv && .venv/Scripts/python -m pip install -r requirements-dev.txt && .venv/Scripts/python -m pytest -q

# A single test
pytest tests/test_provisioner.py::test_sudo_wrap_as_root

# Inspect the tool catalog without installing anything (safe on any OS)
python3 provisioner.py --list

# Run the installer (Linux VPS). No stage flag = full run. Stages are composable:
python3 provisioner.py                      # everything
python3 provisioner.py --go --jobs 16       # only Go tools, 16 parallel installs
python3 provisioner.py --system --structure # OS deps + ~/bounty + PATH exports
python3 provisioner.py --go --force         # reinstall even what already exists
```

Stage flags: `--system --structure --go --python --external --wordlists` (and `--all`). Also `--force`
(reinstall/update), `--jobs N`, `--no-banner`. **Exit code is `1` if any item failed** — useful for CI
or `cloud-init`.

## Architecture (the non-obvious parts)

- **Data-driven catalogs, not install code.** Tools live in `GO_TOOLS`, `PYTHON_TOOLS`, `APT_PACKAGES`.
  `GoTool` entries are built by `_go(category, *entries)`, which accepts three forms: a bare module
  string (binary name inferred from the path), `(module, binary)`, or `(module, binary, env)` for tools
  needing build env (e.g. katana with `CGO_ENABLED=1`). **Add a tool by adding a catalog entry** — never
  by writing a new install branch.
- **Idempotent by default.** Each stage skips what already exists (`have()` checks `$PATH` *and*
  `~/go/bin`); `--force` overrides. Re-running the full provisioner is safe.
- **Stage pipeline in `main()`:** `preflight()` → system → structure (+`ensure_path_exports`) → go
  (+`link_go_bins`) → python → external → wordlists → `REPORT.render()`. `preflight()` **aborts** the
  whole run if the platform isn't Linux, there's no root/sudo, or (for `--go`) a usable Go toolchain
  can't be ensured.
- **`~/bounty/` is a cross-repo contract.** `tools/`, `targets/`, `wordlists/` (overridable via
  `BOUNTY_DIR`) are read/written by the sibling recon/workflow scripts. Changing a path here can
  silently break them.
- **Go binaries are symlinked** into `/usr/local/bin` (via `link_go_bins`), never moved — moving would
  empty `~/go/bin` (breaking `go install` idempotency) and could clobber dpkg-managed files.
- **Supply-chain verification is deliberate and asymmetric.** `ensure_go()` downloads the official Go
  tarball to a temp dir, verifies its SHA256 against `go.dev/dl/?mode=json`, and **hard-aborts if the
  checksum can't be obtained or doesn't match** (a security posture, not a bug). Findomain verification
  is currently *best-effort* (warns and proceeds if the `.sha256` asset is unreachable).
- **Python tool isolation.** pipx tools install in isolated envs. LinkFinder/SecretFinder git-clones get
  their requirements installed into a **dedicated venv at `~/bounty/tools/.venv`** (invoke those scripts
  with that venv's python) — not the system interpreter.
- **Core helpers:** `run(cmd, …)` — list → no shell (preferred), string → shell; returns
  `(success, stdout, stderr)`; logs everything to `~/bounty/provisioner.log` with per-call `timeout` and
  no exception escaping. `sudo_wrap()` prefixes `sudo` unless running as root. Prefer list-form `run()`;
  there is intentionally no `shell=True` in the code.
- **Config via env / top-of-module constants:** `BOUNTY_DIR`, `GOPATH`/`GOBIN`, plus `MIN_GO` and the
  timeouts at the top of the file.

## Conventions

- **Language:** identifiers are English; the README is Portuguese; comments and user-facing strings are
  Portuguese written in **ASCII (no diacritics)** — match that when editing (e.g. `instalacao`, not
  `instalação`). Commit messages are in Portuguese.
- **Tests never invoke external binaries.** They assert on constructed argv / parsed values only, and
  monkeypatch every subprocess/network boundary (`provisioner.run`, `shutil.which`, `GO_BIN`). Keep new
  tests to pure logic — mirror the existing cases in `tests/test_provisioner.py`.
