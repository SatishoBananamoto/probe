# DOSSIER — probe

> MCP server security scanner. Finds what others miss.
> Updated before every commit. Single source of truth.

**Current version**: v0.2.0 (on PyPI as `mcp-probe`)
**Last session**: 2026-07-03 — public CI, license, and source-secret recursion repair
**Repo**: Public-readiness repaired. 102 tests passing locally.

---

## NEXT SESSION — START HERE

### What just happened (2026-07-03 — Codex public-readiness pass)

Codex reviewed `probe` as a public repo and found real code worth keeping
public: a Python MCP security scanner with CLI mode, MCP server mode, config
discovery, grading models, five scanner categories, and focused tests.

Public-readiness gaps were repaired. GitHub Actions used the invalid command
`pip install pytest pip install -e .`, so public runs failed before pytest.
The workflow now upgrades pip and installs pytest plus editable probe in
separate valid steps. README claimed MIT license, but GitHub detected no
license; an MIT `LICENSE` file and package `readme`/`license` metadata are now
present. README install instructions now point normal users to
`pip install mcp-probe` instead of editable local install.

One scanner gap was also closed: hardcoded-secret source scanning now recurses
through Python/JavaScript/TypeScript source directories, matching the directory
behavior already present in the injection scanner. Verification:
`python3 -B -m pytest -q -p no:cacheprovider` passed with 102 tests,
`python3 -B -m compileall -q src tests` passed, `git diff --check` passed,
the installed CLI entry point worked in a throwaway venv, and editable package
metadata/install succeeded with `pip install -e . --no-deps --no-build-isolation`.

Previous session (2026-05-12):

Codex audited the source-scanning path and found the tracker was partly stale: directory scanning already used recursive `rglob`, but `ServerConfig.resolve_server_path()` only resolved relative args from the process cwd, not from the MCP config directory. Python injection detection was also regex-only, so multiline calls and import aliases could be missed.

This session added config-relative path resolution, local `python -m package.module` resolution, Python AST detection for `subprocess(..., shell=True)`, `os.system`, `os.popen`, `eval`, `exec`, f-string command construction, and `.format()` command construction. Added tests for nested source directories, multiline subprocess calls, and import aliases. Verification: `python3 -B -m pytest -q -p no:cacheprovider` passed with 101 tests, `python3 -B -m compileall src tests` passed, and `git diff --check` passed.

Previous session (2026-05-11): Codex verified the repo state before adopting this tracker: `python3 -B -m pytest -q -p no:cacheprovider` passed with 95 tests, `python3 -m compileall src tests` passed, and `git diff --check` passed. No code changes were needed for that slice.

Previous session (2026-03-27): Shipped v0.2.0 to PyPI with MCP server mode (probe can audit other MCP servers programmatically). Added README (was REVIEW.md's #1 priority). Added integration tests with real-world MCP config patterns. Added --markdown flag. CI green.


### #1 Priority: Source-level scanning depth

REVIEW.md (grade B+) identified: secret detection and injection scanning work well on config files, but source-level analysis is shallow. Current state: Python source scanning is now recursive for directories and AST-backed for common dangerous calls. Remaining depth gap: Node.js source analysis is still regex-only, and deeper data-flow analysis is not implemented.

### What NOT to do

- Don't add new scanner categories before deepening existing ones
- Don't build a web UI — CLI + MCP server mode is the right interface
- Don't add runtime analysis yet — static analysis has more ground to cover first

---

## Work

### Source-level scanning depth (REVIEW Priority #2)

_Python source scanning now handles config-relative nested directories and AST-visible dangerous calls. Node.js remains regex-only._

- [x] Audit current resolve_server_path() — found cwd-relative-only path resolution gap
- [x] Extend to recursive directory scanning when server source is a directory — already present; added integration coverage for config-relative directories
- [x] Add AST-based analysis for Python (detect subprocess, exec, eval patterns in nested modules)
- [x] Recursively scan source directories for hardcoded secrets
- [ ] Add AST-based analysis for Node.js (detect child_process, eval in nested modules)
- [x] Add tests with realistic nested vulnerability patterns
- [ ] Continue

### Config discovery improvements (REVIEW Priority #3)

_Hardcoded paths, no XDG convention._

- [ ] Add XDG_CONFIG_HOME support for config discovery
- [ ] Add environment variable override for custom config locations
- [ ] Test cross-platform discovery (Linux, macOS)
- [ ] Continue

### Scanner modularity (REVIEW Priority #4)

- [ ] Add `__init__.py` exports for scanners
- [ ] Consider plugin system for custom scanners (v0.3+)
- [ ] Continue

### Done

<details>
<summary>v0.1.0 → v0.2.0 — completed 2026-03-27</summary>

- [x] v0.1.0: core scanner — secrets, injection, filesystem, validation, transport — `commit:c265a58`
- [x] REVIEW.md: B+ grade, 5 priorities — `commit:8518a14`
- [x] README: user-facing docs — `commit:d05a6e4` · REVIEW Priority #1
- [x] v0.2.0: MCP server mode — `commit:620a435`
- [x] PyPI: shipped as mcp-probe — `commit:9a93579`
- [x] CLAUDE.md: scroll-extracted knowledge — `commit:2d1ac34`
- [x] --markdown flag — `commit:b236e42`
- [x] 6 integration tests — `commit:dc3e207`
- [x] CI: tests on push/PR — `commit:c862e26`
- [x] DOSSIER/.graft tracking baseline verified — 2026-05-11 · 95 tests passing
- [x] Public CI/license repair and recursive source-secret scan — 2026-07-03 · 102 tests passing

</details>

---

## Decision Log

| ID | Date | Decision | Why |
|----|------|----------|-----|
| D-001 | 2026-03-24 | Published as mcp-probe (not probe) | Name taken on PyPI. |
| D-002 | 2026-03-27 | Added MCP server mode | Enables programmatic auditing from other MCP servers/agents. |

---

## Session Log

### 2026-03-24 — Initial build (Session 1)

- **Worked on:** Core scanner, all 5 categories, grading system
- **Completed:** v0.1.0 — 16 source files, ~1,600 LOC, 76 tests
- **State:** Working scanner, not yet published

### 2026-03-27 — Ship + extend (Session 2)

- **Worked on:** MCP server mode, README, PyPI, integration tests, CI
- **Completed:** v0.2.0 on PyPI, 95 tests, CI green
- **State:** Shipped. Next: source-level scanning depth.

### 2026-05-12 — Source scanning hardening (Session 3)

- **Worked on:** Config-relative source resolution, local `python -m` module resolution, recursive Python AST injection detection.
- **Completed:** 6 new tests; 101-test suite passing.
- **State:** Python source scanning depth improved. Next: Node.js AST-equivalent scan or config discovery improvements.

### 2026-07-03 — Public-readiness pass

- **Worked on:** Keep `probe` public-worthy after repo review.
- **Completed:** Fixed GitHub Actions install command, added MIT LICENSE, added package readme/license metadata, corrected README install instructions, and added recursive source-directory hardcoded-secret scanning.
- **State:** 102 tests passing locally; editable install metadata and installed CLI verified in `/tmp` venv. Next: commit/push and confirm GitHub Actions.

---

### Key reference files

| File | What it contains |
|------|-----------------|
| DOSSIER.md | This file. |
| REVIEW.md | Structured assessment (grade B+). 5 priorities. |
| CLAUDE.md | scroll-extracted knowledge (decisions, learnings). |
