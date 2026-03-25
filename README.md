# probe

MCP server security scanner. Finds plaintext secrets, injection vulnerabilities, and missing auth in your MCP configurations.

## Why

You connect MCP servers to your AI agent. Those servers get tool access, environment variables, and filesystem paths. Are they safe?

probe scans your MCP configs and the server source code for security issues, grades each server A-F, and tells you what to fix.

## Install

```bash
pip install -e .
```

## Usage

```bash
# Scan all discovered MCP servers
probe scan

# Verbose output (descriptions + fix recommendations)
probe scan -v

# JSON output (for CI/CD)
probe scan --json

# Scan specific config file
probe scan -p ~/.mcp.json

# Only scan specific server(s)
probe scan -s my-server -s other-server

# List discovered servers without scanning
probe list
```

## What It Checks

| Category | What it finds | Severity |
|----------|--------------|----------|
| **Secrets** | Hardcoded API keys (OpenAI, Anthropic, GitHub, AWS, Slack, 18+ types), high-entropy credentials, secret-like env var names | Critical / High |
| **Injection** | `subprocess(shell=True)`, `os.system()`, `eval()`, `exec()`, f-strings in commands, Node.js `child_process.exec()` | Critical / High |
| **Filesystem** | Access to `/etc/passwd`, `~/.ssh`, `~/.aws`; path traversal patterns; unguarded delete/chmod | High / Medium |
| **Validation** | Missing input validation in tool handlers, direct dict access without error handling | Medium / Low |
| **Transport** | Unencrypted HTTP, elevated privileges (`sudo`), unpinned `npx`/`uvx` packages | Critical / High |

## Config Discovery

probe auto-discovers MCP configs from:

- **Claude Code**: `~/.mcp.json` + project-level `.mcp.json` (walks up from cwd)
- **Cursor**: `~/.cursor/mcp.json`
- **VS Code**: `~/.vscode/settings.json`
- **Windsurf**: `~/.windsurf/mcp.json`

Or specify paths directly with `probe scan -p /path/to/config.json`.

## Grading

Each server gets a score (0-100) and a grade:

| Grade | Score | Meaning |
|-------|-------|---------|
| A | 90-100 | Excellent — no significant issues |
| B | 75-89 | Good — minor issues only |
| C | 60-74 | Needs improvement |
| D | 40-59 | Poor — significant security gaps |
| F | 0-39 | Failing — critical vulnerabilities |

Any CRITICAL finding caps the score at 35 (automatic F).

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean — no critical or high findings |
| 2 | Security issues — critical or high findings detected |

Use in CI: `probe scan --json || echo "Security issues found"`.

## Secret Detection

Three-tier approach to minimize false positives:

1. **Known prefixes**: 18 patterns for API keys from OpenAI, Anthropic, GitHub, AWS, Slack, GitLab, Google, npm, PyPI, and more
2. **Entropy analysis**: Shannon entropy > 3.5 on values with secret-like key names
3. **Key name heuristics**: Flags env vars named `API_KEY`, `SECRET`, `TOKEN`, etc.

Values like `${ENV_VAR}`, `<placeholder>`, and `CHANGEME` are automatically whitelisted.

## License

MIT
