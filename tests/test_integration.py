"""Integration tests — scan real-world MCP config patterns."""

import json
import tempfile
from pathlib import Path

from click.testing import CliRunner

from src.cli import main


def _write_config(path: Path, servers: dict) -> Path:
    """Write an MCP config file."""
    config = {"mcpServers": servers}
    config_path = path / ".mcp.json"
    config_path.write_text(json.dumps(config, indent=2))
    return config_path


class TestRealWorldPatterns:
    """Test probe against common real-world MCP config patterns."""

    def test_clean_stdio_server(self, tmp_path):
        """A clean stdio MCP server should grade A."""
        config = _write_config(tmp_path, {
            "my-tool": {
                "command": "python3",
                "args": ["server.py"],
            }
        })
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "-p", str(config), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["results"][0]["grade"] == "A"

    def test_plaintext_api_key(self, tmp_path):
        """A config with a plaintext API key should be flagged."""
        config = _write_config(tmp_path, {
            "my-tool": {
                "command": "python3",
                "args": ["server.py"],
                "env": {
                    "API_KEY": "sk-1234567890abcdefghijklmnopqrstuvwxyz"
                }
            }
        })
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "-p", str(config), "--json"])
        data = json.loads(result.output)
        assert data["total_findings"] > 0
        assert any("secret" in f["title"].lower() or "key" in f["title"].lower()
                    for r in data["results"] for f in r["findings"])

    def test_unpinned_npx(self, tmp_path):
        """npx without version pinning should be flagged."""
        config = _write_config(tmp_path, {
            "my-tool": {
                "command": "npx",
                "args": ["some-mcp-server"],
            }
        })
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "-p", str(config), "--json"])
        data = json.loads(result.output)
        assert any("unpin" in f["title"].lower()
                    for r in data["results"] for f in r["findings"])

    def test_markdown_output(self, tmp_path):
        """Markdown output should be valid markdown."""
        config = _write_config(tmp_path, {
            "test-server": {
                "command": "python3",
                "args": ["server.py"],
            }
        })
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "-p", str(config), "--markdown"])
        assert result.exit_code == 0
        assert "# MCP Server Security Report" in result.output
        assert "| Server |" in result.output

    def test_multiple_servers(self, tmp_path):
        """Scanning multiple servers reports all of them."""
        config = _write_config(tmp_path, {
            "server-a": {"command": "python3", "args": ["a.py"]},
            "server-b": {"command": "node", "args": ["b.js"]},
            "server-c": {"command": "python3", "args": ["c.py"]},
        })
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "-p", str(config), "--json"])
        data = json.loads(result.output)
        assert data["servers_scanned"] == 3

    def test_json_output_structure(self, tmp_path):
        """JSON output has expected top-level fields."""
        config = _write_config(tmp_path, {
            "test": {"command": "python3", "args": ["s.py"]},
        })
        runner = CliRunner()
        result = runner.invoke(main, ["scan", "-p", str(config), "--json"])
        data = json.loads(result.output)
        assert "probe_version" in data
        assert "overall_grade" in data
        assert "servers_scanned" in data
        assert "total_findings" in data
        assert "results" in data
