# probe — Review

---

## v1 — 2026-03-25

**Reviewer**: Claude (Opus 4.6, partner session)
**Version Reviewed**: v0.1.0, 21 files, 2,405 LOC, 76 tests
**Grade: B+** — Strong first version with real security value; needs source-level scanning depth and a README

### Summary

A focused MCP server security scanner that does one thing well: audit your MCP configurations for plaintext secrets, injection vulnerabilities, filesystem risks, validation gaps, and transport issues. Discovers configs from Claude Code, Cursor, VS Code, and Windsurf. Grades servers A-F. Exits non-zero for CI integration.

The secret detection is genuinely good — three-tier approach (known prefixes, Shannon entropy, key name heuristics) with smart false-positive suppression. The injection scanner covers both Python and Node.js. The codebase is clean, modular, and well-tested.

---

### Dimension Assessments

### Thesis & Positioning

*Is the problem real?*

Yes. MCP servers are proliferating — 200+ as of early 2026. Most are community-built, many have security issues. Users configure them in JSON files with plaintext API keys and connect them to AI agents that have broad system access. Nobody else is scanning this attack surface specifically.

*Is the approach sound?*

Static analysis of config files + source code is the right starting point. You don't need runtime analysis to catch hardcoded API keys or `subprocess(shell=True)`. The auto-discovery across 4 tools (Claude Code, Cursor, VS Code, Windsurf) is practical — users don't need to know where their configs live.

*Differentiation:* Real. This isn't "generic secret scanner applied to MCP." The config format parsing, multi-tool discovery, server source resolution, and MCP-specific checks (tool handler validation, transport security) are purpose-built.

### Architecture

Clean and modular. Each scanner is independent — same input (ServerConfig), same output (list[Finding]). Adding a new scanner means writing one file and adding it to ALL_SCANNERS in cli.py. The models are well-designed: Severity has weights that drive scoring, Grade has thresholds, FullReport aggregates properly.

**Strengths:**
- Scanner modularity — each category is one file, one `scan()` function
- ServerConfig.resolve_server_path() — intelligently finds source code from command + args
- Dedup logic in discover_servers() — handles overlapping configs
- Grading math is simple and correct: deductions from 100, CRITICAL auto-caps at 35

**Weaknesses:**
- No `src/scanners/__init__.py` exports — each scanner imported individually in cli.py
- Config discovery uses hardcoded paths rather than environment variable or XDG convention
- No plugin system for custom scanners (fine for v0.1, will matter for v0.3+)

### Code Quality

**Stats:** 16 source files, ~1,600 LOC. 76 tests across 6 test files. All passing in 0.25s.

**Test quality:**
- Positive AND negative cases (detects bad things, doesn't false-positive on clean code)
- Comment-line filtering validated (important for injection scanner)
- Safe-value whitelist tested for secrets
- Grading thresholds tested at boundaries
- Gap: filesystem scanner and validation scanner have fewer dedicated tests than secrets/injection

**Code style:** Consistent, readable. Docstrings on public functions. No unnecessary abstractions. Dependencies are minimal (click, rich — both standard for CLI tools).

**Error handling:** Defensive throughout — invalid JSON returns empty list, missing source files are skipped, OSError caught on file reads. No crashes on bad input.

### Completeness

**What works:**
- Secret detection: 18 known prefixes + entropy + key name heuristics
- Injection: Python and Node.js, including f-string amplifiers
- Filesystem: sensitive paths, traversal patterns, unguarded operations
- Validation: AST-based handler detection + regex fallback
- Transport: HTTP vs HTTPS, sudo/elevated privileges, unpinned npx/uvx
- Discovery: 4 tools, project-level walk-up
- Output: Rich terminal + JSON
- Grading: A-F with weighted scoring
- CI: exit code 2 on critical/high

**What's missing:**
1. **README.** No README.md at all. A security tool with no documentation is a security tool nobody uses.
2. **No end-to-end test.** Individual scanners are tested but there's no test that runs the full scan pipeline on a realistic config.
3. **Source scanning depth.** The injection and filesystem scanners scan source code, but only with regex. No data flow analysis — can't detect when user input from tool parameters flows into a dangerous sink. This is the ceiling for v0.x.
4. **No TOML/YAML config support.** Only JSON. Some MCP implementations may use other formats.

### Usability

`probe scan` with auto-discovery is the right UX — zero config for the common case. `probe list` for inspection. `--json` for CI. `--verbose` for details. `--server` for filtering. All intuitive.

**Missing:**
- No `--help` examples in the output
- No `probe init` or quick-start guidance
- The README gap is the biggest usability blocker

### Sustainability

Dependencies: click + rich. Both stable, well-maintained. No exotic deps.

Maintenance: the SECRET_PREFIXES list will need updates as new services launch new token formats. This is ongoing work but low-effort (add a regex).

Growth ceiling: regex-based source scanning won't catch sophisticated injection patterns. Next level requires AST analysis for data flow (tool parameter → subprocess argument). That's a significant investment but the architecture supports it — scanners are modular, a new AST-based scanner can coexist with the regex one.

### Portfolio Fit

Fills the "integration security" layer in the trust stack. Probe audits the tools an AI agent connects to. Complements:
- svx (action safety — what the agent does)
- vigil (supply chain — what the agent depends on)
- kv-secrets (credentials — what the agent knows)

No overlap with other projects. Clear lane.

---

## Strengths

1. **Secret detection is genuinely good.** Three-tier approach with false-positive suppression. Shannon entropy at 3.5 threshold is calibrated correctly. Safe-value whitelist prevents noise.

2. **Multi-tool config discovery.** Claude Code, Cursor, VS Code, Windsurf — covers the real install base. Project-level walk-up is a nice touch.

3. **Modular scanner architecture.** Adding a new scanner category is trivial: one file, one function, add to the list. Clean interface.

4. **CI integration.** Exit code 2 on critical/high, JSON output, grading system — ready for pipelines. This is what takes a tool from "useful locally" to "useful in production."

5. **Defensive error handling.** Bad JSON, missing files, unresolvable paths — all handled gracefully. No crashes on malformed input.

---

## Weaknesses

1. **No README.** → Write one. Include: what probe is, install, quick start (`probe scan`), example output, what it checks, exit codes. This is the #1 priority.

2. **No end-to-end test.** → Add a test that creates a realistic .mcp.json with multiple servers (some clean, some vulnerable), runs the full pipeline, and checks the report output and exit code.

3. **Filesystem and validation scanners are undertested.** → Add dedicated test files: test_filesystem.py and test_validation.py with positive and negative cases for each pattern.

4. **Source scanning is regex-only.** → For v0.2, consider AST-based scanning for Python (data flow from tool parameters to dangerous sinks). This is the biggest technical improvement available.

5. **Hardcoded config paths.** → Support XDG_CONFIG_HOME and PROBE_CONFIG_PATH environment variable for custom locations. Low effort, high portability.

---

## Recommendations (Priority Order)

1. **Write README.md.** Highest impact. A security tool that can't explain itself won't be trusted. Include example output, what it checks, and how to interpret grades.

2. **Add end-to-end test.** Create a test config with known vulnerabilities, run the full scan, assert on findings and grade. This is the test that protects against regressions.

3. **Add test_filesystem.py and test_validation.py.** These scanners exist and work but have less test coverage than secrets/injection.

4. **Plan AST-based scanning for v0.2.** The current regex approach catches the obvious patterns. Data flow analysis (does user input from a tool parameter reach subprocess?) is the next level. The modular architecture supports this cleanly.

5. **Add XDG support for config discovery.** One-line change: check `os.environ.get("XDG_CONFIG_HOME", "~/.config")` before hardcoded paths.

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| False positives erode trust | Medium | High | Safe-value whitelist helps; add user suppression mechanism (probe.ignore) |
| New token formats not detected | High | Medium | SECRET_PREFIXES is easy to update; consider community contributions |
| Regex misses sophisticated injection | Medium | Medium | AST scanning in v0.2; current approach catches the common patterns |
| No one finds the tool | High | High | README, publish to PyPI, announce in Claude Code community |

---

## Verdict

A solid, focused security scanner that fills a genuine gap in the MCP ecosystem. The secret detection is production-quality, the architecture is clean, and the test coverage is strong for a v0.1. The biggest gap is documentation — a security tool without a README is invisible.

**Grade: B+**
Strong first version. Write the README, add the e2e test, and this is ready for PyPI.
