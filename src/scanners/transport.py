"""Check transport security of MCP server configurations."""

from ..models import Category, Finding, ServerConfig, Severity, Transport


def scan(server: ServerConfig) -> list[Finding]:
    """Check transport-level security of an MCP server."""
    findings = []

    # Check 1: Remote servers (SSE/HTTP) have higher risk than local (stdio)
    if server.transport in (Transport.SSE, Transport.STREAMABLE_HTTP):
        if server.url and server.url.startswith("http://"):
            findings.append(Finding(
                severity=Severity.HIGH,
                category=Category.TRANSPORT,
                title="Remote MCP server over unencrypted HTTP",
                description=(
                    f"Server '{server.name}' connects to {server.url} over "
                    f"plain HTTP. All communication — including tool parameters "
                    f"and results — is transmitted unencrypted and can be "
                    f"intercepted by network attackers."
                ),
                recommendation=(
                    "Switch to HTTPS. If the server is local, consider using "
                    "stdio transport instead."
                ),
                location=f"{server.source_file}:{server.name}.url",
                evidence=server.url,
            ))
        elif server.url and server.url.startswith("https://"):
            # HTTPS is good, but note it's remote
            findings.append(Finding(
                severity=Severity.INFO,
                category=Category.TRANSPORT,
                title="Remote MCP server (HTTPS)",
                description=(
                    f"Server '{server.name}' connects to a remote endpoint "
                    f"over HTTPS. While encrypted, remote servers have a "
                    f"larger attack surface than local stdio servers."
                ),
                recommendation=(
                    "Ensure the remote server is trusted and maintained. "
                    "Consider whether a local server could serve the same purpose."
                ),
                location=f"{server.source_file}:{server.name}.url",
            ))

    # Check 2: Command-based servers running as root or with elevated privileges
    if server.command in ("sudo", "doas"):
        findings.append(Finding(
            severity=Severity.CRITICAL,
            category=Category.TRANSPORT,
            title="MCP server running with elevated privileges",
            description=(
                f"Server '{server.name}' runs via '{server.command}', giving "
                f"it root/elevated privileges. Any vulnerability in this server "
                f"becomes a full system compromise."
            ),
            recommendation=(
                "Run MCP servers as a regular user. If elevated access is needed "
                "for specific operations, use capability-based access control "
                "instead of full root."
            ),
            location=f"{server.source_file}:{server.name}.command",
        ))

    # Check 3: npx/uvx executing remote packages without version pinning
    if server.command in ("npx", "uvx"):
        has_version = any("@" in arg or "==" in arg for arg in server.args)
        if not has_version:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                category=Category.TRANSPORT,
                title=f"Unpinned package via {server.command}",
                description=(
                    f"Server '{server.name}' uses {server.command} without "
                    f"pinning a specific package version. A supply chain attack "
                    f"could publish a malicious version that gets auto-installed."
                ),
                recommendation=(
                    f"Pin the package version. For npx: package@1.2.3. "
                    f"For uvx: package==1.2.3."
                ),
                location=f"{server.source_file}:{server.name}",
                evidence=f"{server.command} {' '.join(server.args)}",
            ))

    # Check 4: Server with no env vars at all (not necessarily bad, but note it)
    # Skipped — no env vars is actually fine for local tools

    return findings
