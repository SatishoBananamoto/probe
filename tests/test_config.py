"""Tests for MCP config discovery and parsing."""

import json
import pytest
from pathlib import Path

from src.config import parse_config, _guess_app
from src.models import Transport


@pytest.fixture
def tmp_config(tmp_path):
    """Create a temporary MCP config file."""
    def _create(data: dict, filename: str = ".mcp.json") -> Path:
        config_path = tmp_path / filename
        config_path.write_text(json.dumps(data))
        return config_path
    return _create


class TestParseConfig:
    def test_basic_stdio_server(self, tmp_config):
        config = tmp_config({
            "mcpServers": {
                "my-server": {
                    "command": "python3",
                    "args": ["server.py"],
                }
            }
        })
        servers = parse_config("claude-code", config)
        assert len(servers) == 1
        assert servers[0].name == "my-server"
        assert servers[0].command == "python3"
        assert servers[0].transport == Transport.STDIO

    def test_server_with_env(self, tmp_config):
        config = tmp_config({
            "mcpServers": {
                "api-server": {
                    "command": "node",
                    "args": ["index.js"],
                    "env": {
                        "API_KEY": "sk-abc123",
                        "PORT": "3000",
                    }
                }
            }
        })
        servers = parse_config("claude-code", config)
        assert servers[0].env["API_KEY"] == "sk-abc123"
        assert servers[0].env["PORT"] == "3000"

    def test_sse_server_with_url(self, tmp_config):
        config = tmp_config({
            "mcpServers": {
                "remote": {
                    "command": "",
                    "args": [],
                    "url": "http://localhost:8080/sse",
                }
            }
        })
        servers = parse_config("claude-code", config)
        assert servers[0].transport == Transport.SSE
        assert servers[0].url == "http://localhost:8080/sse"

    def test_multiple_servers(self, tmp_config):
        config = tmp_config({
            "mcpServers": {
                "server-a": {"command": "python3", "args": ["a.py"]},
                "server-b": {"command": "node", "args": ["b.js"]},
                "server-c": {"command": "uvx", "args": ["some-tool"]},
            }
        })
        servers = parse_config("claude-code", config)
        assert len(servers) == 3
        names = {s.name for s in servers}
        assert names == {"server-a", "server-b", "server-c"}

    def test_empty_config(self, tmp_config):
        config = tmp_config({})
        servers = parse_config("claude-code", config)
        assert servers == []

    def test_invalid_json(self, tmp_path):
        config = tmp_path / "bad.json"
        config.write_text("not json {{{")
        servers = parse_config("claude-code", config)
        assert servers == []

    def test_source_file_recorded(self, tmp_config):
        config = tmp_config({"mcpServers": {"s": {"command": "echo", "args": []}}})
        servers = parse_config("test-app", config)
        assert servers[0].source_file == config
        assert servers[0].source_app == "test-app"


class TestGuessApp:
    def test_cursor(self):
        assert _guess_app(Path("/home/user/.cursor/mcp.json")) == "cursor"

    def test_vscode(self):
        assert _guess_app(Path("/home/user/.vscode/settings.json")) == "vscode"

    def test_windsurf(self):
        assert _guess_app(Path("/home/user/.windsurf/mcp.json")) == "windsurf"

    def test_default_claude(self):
        assert _guess_app(Path("/home/user/.mcp.json")) == "claude-code"
