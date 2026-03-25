"""Tests for the transport scanner."""

import pytest
from pathlib import Path

from src.models import Category, ServerConfig, Severity, Transport
from src.scanners.transport import scan


class TestTransportScanner:
    def test_http_url_flagged(self):
        server = ServerConfig(
            name="remote",
            command="",
            args=[],
            transport=Transport.SSE,
            url="http://example.com:8080/sse",
            source_file=Path("/tmp/test.json"),
        )
        findings = scan(server)
        assert any(f.severity == Severity.HIGH for f in findings)
        assert any("unencrypted HTTP" in f.title for f in findings)

    def test_https_url_info_only(self):
        server = ServerConfig(
            name="remote",
            command="",
            args=[],
            transport=Transport.SSE,
            url="https://example.com/sse",
            source_file=Path("/tmp/test.json"),
        )
        findings = scan(server)
        assert all(f.severity == Severity.INFO for f in findings)

    def test_stdio_no_transport_findings(self):
        server = ServerConfig(
            name="local",
            command="python3",
            args=["server.py"],
            transport=Transport.STDIO,
            source_file=Path("/tmp/test.json"),
        )
        findings = scan(server)
        assert len(findings) == 0

    def test_sudo_flagged_critical(self):
        server = ServerConfig(
            name="dangerous",
            command="sudo",
            args=["python3", "server.py"],
            source_file=Path("/tmp/test.json"),
        )
        findings = scan(server)
        assert any(f.severity == Severity.CRITICAL for f in findings)
        assert any("elevated privileges" in f.title for f in findings)

    def test_npx_unpinned(self):
        server = ServerConfig(
            name="tool",
            command="npx",
            args=["some-mcp-tool"],
            source_file=Path("/tmp/test.json"),
        )
        findings = scan(server)
        assert any("Unpinned" in f.title for f in findings)

    def test_npx_pinned_ok(self):
        server = ServerConfig(
            name="tool",
            command="npx",
            args=["some-mcp-tool@1.2.3"],
            source_file=Path("/tmp/test.json"),
        )
        findings = scan(server)
        assert not any("Unpinned" in f.title for f in findings)

    def test_uvx_unpinned(self):
        server = ServerConfig(
            name="tool",
            command="uvx",
            args=["my-tool"],
            source_file=Path("/tmp/test.json"),
        )
        findings = scan(server)
        assert any("Unpinned" in f.title for f in findings)

    def test_uvx_pinned_ok(self):
        server = ServerConfig(
            name="tool",
            command="uvx",
            args=["my-tool==1.0.0"],
            source_file=Path("/tmp/test.json"),
        )
        findings = scan(server)
        assert not any("Unpinned" in f.title for f in findings)
