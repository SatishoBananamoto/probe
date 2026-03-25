"""Tests for probe MCP server tools."""

import json
import pytest
from pathlib import Path
from unittest.mock import patch

from src.server import probe_scan, probe_scan_server, probe_list, probe_check_config
from src.models import ServerConfig, Transport


@pytest.fixture
def mock_servers():
    """Mock discover_servers to return controlled test data."""
    servers = [
        ServerConfig(
            name="clean-server",
            command="python3",
            args=["server.py"],
            transport=Transport.STDIO,
            source_file=Path("/tmp/test.json"),
            source_app="claude-code",
        ),
        ServerConfig(
            name="risky-server",
            command="sudo",
            args=["python3", "server.py"],
            transport=Transport.STDIO,
            source_file=Path("/tmp/test.json"),
            source_app="claude-code",
        ),
    ]
    with patch("src.server.discover_servers", return_value=servers):
        yield servers


@pytest.fixture
def empty_servers():
    """Mock discover_servers to return nothing."""
    with patch("src.server.discover_servers", return_value=[]):
        yield


class TestProbeScan:
    def test_returns_valid_json(self, mock_servers):
        result = probe_scan()
        data = json.loads(result)
        assert "overall_grade" in data
        assert "results" in data

    def test_finds_sudo_issue(self, mock_servers):
        result = probe_scan()
        data = json.loads(result)
        assert data["total_findings"] >= 1
        # The sudo server should be graded F
        risky = [r for r in data["results"] if r["server"]["name"] == "risky-server"]
        assert risky[0]["grade"] == "F"

    def test_clean_server_grade_a(self, mock_servers):
        result = probe_scan()
        data = json.loads(result)
        clean = [r for r in data["results"] if r["server"]["name"] == "clean-server"]
        assert clean[0]["grade"] == "A"

    def test_empty_returns_message(self, empty_servers):
        result = probe_scan()
        data = json.loads(result)
        assert "No MCP servers found" in data["message"]


class TestProbeScanServer:
    def test_scan_specific_server(self, mock_servers):
        result = probe_scan_server("clean-server")
        data = json.loads(result)
        assert data["servers_scanned"] == 1
        assert data["results"][0]["server"]["name"] == "clean-server"

    def test_server_not_found(self, mock_servers):
        result = probe_scan_server("nonexistent")
        data = json.loads(result)
        assert "error" in data
        assert "nonexistent" in data["error"]
        assert "available_servers" in data

    def test_available_servers_listed(self, mock_servers):
        result = probe_scan_server("nonexistent")
        data = json.loads(result)
        assert "clean-server" in data["available_servers"]
        assert "risky-server" in data["available_servers"]


class TestProbeList:
    def test_lists_all_servers(self, mock_servers):
        result = probe_list()
        data = json.loads(result)
        assert data["count"] == 2
        names = {s["name"] for s in data["servers"]}
        assert names == {"clean-server", "risky-server"}

    def test_server_details(self, mock_servers):
        result = probe_list()
        data = json.loads(result)
        clean = [s for s in data["servers"] if s["name"] == "clean-server"][0]
        assert clean["transport"] == "stdio"
        assert clean["command"] == "python3"
        assert clean["config_app"] == "claude-code"

    def test_empty_returns_message(self, empty_servers):
        result = probe_list()
        data = json.loads(result)
        assert data["servers"] == []


class TestProbeCheckConfig:
    def test_scan_specific_config(self, tmp_path):
        config = tmp_path / "test-mcp.json"
        config.write_text(json.dumps({
            "mcpServers": {
                "test": {
                    "command": "npx",
                    "args": ["some-tool"],
                }
            }
        }))
        result = probe_check_config(str(config))
        data = json.loads(result)
        assert data["servers_scanned"] == 1
        # npx unpinned should be flagged
        assert data["total_findings"] >= 1

    def test_nonexistent_config(self):
        result = probe_check_config("/nonexistent/path.json")
        data = json.loads(result)
        assert "error" in data

    def test_config_with_secrets(self, tmp_path):
        config = tmp_path / "test-mcp.json"
        config.write_text(json.dumps({
            "mcpServers": {
                "leaky": {
                    "command": "node",
                    "args": ["index.js"],
                    "env": {
                        "SLACK_TOKEN": "xoxb-" + "0" * 10 + "-" + "1" * 13 + "-" + "a" * 24,
                    }
                }
            }
        }))
        result = probe_check_config(str(config))
        data = json.loads(result)
        assert data["overall_grade"] == "F"
        assert any(
            "Slack" in f["title"]
            for r in data["results"]
            for f in r["findings"]
        )
