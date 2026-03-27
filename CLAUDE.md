<!-- scroll:start -->
## Project Knowledge (scroll)

*Extracted from `probe` git history.*

### Decisions

- **DEC-001**: Published as mcp-probe on PyPI instead of probe due to name conflict (high)
  - The name 'probe' was already taken on PyPI, requiring an alternative name for the package.
- **DEC-002**: Added MCP server mode to enable auditing other MCP servers (high)
  - MCP server mode allows other MCP servers to perform security audits programmatically, enabling integration into larger MCP ecosystems and automated workflows.

### Learnings

- **LRN-001**: Multi-tier approach provides comprehensive secret detection coverage
  - Layering multiple detection methods (pattern matching + entropy analysis + whitelisting) provides both high recall for known patterns and discovery of unknown secrets while reducing false positives.

<!-- scroll:end -->
