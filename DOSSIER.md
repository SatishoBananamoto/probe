# DOSSIER — probe

> MCP server security scanner. Finds what others miss.
> Updated before every commit. Single source of truth.

**Current version**: v0.2.0 (on PyPI as `mcp-probe`)
**Last session**: 2026-05-11 — Codex tracking baseline verified
**Repo**: Ready to commit tracking docs. 95 tests passing.

---

## NEXT SESSION — START HERE

### What just happened (2026-05-11)

Codex verified the repo state before adopting this tracker: `python3 -B -m pytest -q -p no:cacheprovider` passed with 95 tests, `python3 -m compileall src tests` passed, and `git diff --check` passed. No code changes were needed for this slice.

Previous session (2026-03-27): Shipped v0.2.0 to PyPI with MCP server mode (probe can audit other MCP servers programmatically). Added README (was REVIEW.md's #1 priority). Added integration tests with real-world MCP config patterns. Added --markdown flag. CI green.


### #1 Priority: Source-level scanning depth

REVIEW.md (grade B+) identified: secret detection and injection scanning work well on config files, but source-level analysis is shallow. The scanner resolves server source paths but only scans top-level files. A server with `subprocess(shell=True)` in a nested module would be missed. Deeper AST-based scanning would catch these.

### What NOT to do

- Don't add new scanner categories before deepening existing ones
- Don't build a web UI — CLI + MCP server mode is the right interface
- Don't add runtime analysis yet — static analysis has more ground to cover first

---

## Work

### Source-level scanning depth (REVIEW Priority #2)

_Current source scanning is shallow — only top-level files. Nested injection vulnerabilities missed._

- [ ] Audit current resolve_server_path() — what does it actually find?
- [ ] Extend to recursive directory scanning when server source is a directory
- [ ] Add AST-based analysis for Python (detect subprocess, exec, eval patterns in nested modules)
- [ ] Add AST-based analysis for Node.js (detect child_process, eval in nested modules)
- [ ] Add tests with realistic nested vulnerability patterns
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

---

### Key reference files

| File | What it contains |
|------|-----------------|
| DOSSIER.md | This file. |
| REVIEW.md | Structured assessment (grade B+). 5 priorities. |
| CLAUDE.md | scroll-extracted knowledge (decisions, learnings). |
