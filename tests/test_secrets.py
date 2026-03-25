"""Tests for the secrets scanner."""

import pytest
from pathlib import Path

from src.models import Category, ServerConfig, Severity
from src.scanners.secrets import (
    scan, scan_config_secrets, shannon_entropy, _is_safe_value, _mask_secret,
)


class TestShannonEntropy:
    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_single_char(self):
        assert shannon_entropy("aaaa") == 0.0

    def test_high_entropy(self):
        # Random-looking string should have high entropy
        e = shannon_entropy("aB3$xY9!mK2@pQ7&")
        assert e > 3.5

    def test_low_entropy(self):
        # Repetitive string should have low entropy
        e = shannon_entropy("aaabbbccc")
        assert e < 2.0


class TestIsSafeValue:
    def test_env_var_reference(self):
        assert _is_safe_value("${MY_API_KEY}")

    def test_env_var_dollar(self):
        assert _is_safe_value("$MY_API_KEY")

    def test_placeholder(self):
        assert _is_safe_value("<your-api-key>")

    def test_your_prefix(self):
        assert _is_safe_value("your_api_key_here")

    def test_xxx(self):
        assert _is_safe_value("xxxxxxxx")

    def test_todo(self):
        assert _is_safe_value("TODO")

    def test_none(self):
        assert _is_safe_value("none")

    def test_number(self):
        assert _is_safe_value("3000")

    def test_real_key_not_safe(self):
        assert not _is_safe_value("sk-ant-abc123def456ghi789")

    def test_changeme(self):
        assert _is_safe_value("CHANGE_ME")


class TestMaskSecret:
    def test_normal_length(self):
        masked = _mask_secret("sk-ant-abc123def456")
        assert masked.startswith("sk-a")
        assert masked.endswith("56")
        assert "***" in masked

    def test_short_value(self):
        assert _mask_secret("abc") == "***"


class TestScanConfigSecrets:
    def test_detects_anthropic_key(self):
        server = ServerConfig(
            name="test",
            command="python3",
            args=["server.py"],
            env={"ANTHROPIC_API_KEY": "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"},
            source_file=Path("/tmp/test.json"),
        )
        findings = scan_config_secrets(server)
        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].category == Category.SECRETS

    def test_detects_github_token(self):
        server = ServerConfig(
            name="test",
            command="node",
            args=["index.js"],
            env={"GITHUB_TOKEN": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"},
            source_file=Path("/tmp/test.json"),
        )
        findings = scan_config_secrets(server)
        assert len(findings) >= 1
        assert any("GitHub" in f.title for f in findings)

    def test_detects_aws_key(self):
        server = ServerConfig(
            name="test",
            command="node",
            args=["index.js"],
            env={"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"},
            source_file=Path("/tmp/test.json"),
        )
        findings = scan_config_secrets(server)
        assert len(findings) >= 1
        assert any("AWS" in f.title for f in findings)

    def test_ignores_safe_values(self):
        server = ServerConfig(
            name="test",
            command="python3",
            args=["server.py"],
            env={
                "API_KEY": "${MY_API_KEY}",
                "PORT": "3000",
                "DEBUG": "true",
            },
            source_file=Path("/tmp/test.json"),
        )
        findings = scan_config_secrets(server)
        assert len(findings) == 0

    def test_detects_high_entropy_secret_key(self):
        server = ServerConfig(
            name="test",
            command="python3",
            args=["server.py"],
            env={"API_SECRET": "aB3xY9mK2pQ7wE5tR8uI0oP4sD6fG1hJ"},
            source_file=Path("/tmp/test.json"),
        )
        findings = scan_config_secrets(server)
        assert len(findings) >= 1
        # Should be HIGH (entropy-based) not CRITICAL (prefix-based)
        assert any(f.severity in (Severity.HIGH, Severity.MEDIUM) for f in findings)

    def test_no_env_no_findings(self):
        server = ServerConfig(
            name="test",
            command="python3",
            args=["server.py"],
            source_file=Path("/tmp/test.json"),
        )
        findings = scan_config_secrets(server)
        assert len(findings) == 0

    def test_detects_slack_token(self):
        server = ServerConfig(
            name="slack-mcp",
            command="node",
            args=["index.js"],
            env={"SLACK_TOKEN": "xoxb-" + "0" * 10 + "-" + "1" * 13 + "-" + "a" * 24},
            source_file=Path("/tmp/test.json"),
        )
        findings = scan_config_secrets(server)
        assert len(findings) >= 1
        assert any("Slack" in f.title for f in findings)


class TestScanSourceSecrets:
    def test_detects_hardcoded_key_in_source(self, tmp_path):
        source = tmp_path / "server.py"
        source.write_text(
            'API_KEY = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"\n'
            'client = Client(api_key=API_KEY)\n'
        )
        server = ServerConfig(
            name="test",
            command="python3",
            args=[str(source)],
            source_file=Path("/tmp/test.json"),
        )
        findings = scan(server)
        assert any(f.category == Category.SECRETS and "source" in f.title.lower() for f in findings)

    def test_ignores_comments(self, tmp_path):
        source = tmp_path / "server.py"
        source.write_text(
            '# Example: sk-ant-api03-abcdefghijklmnopqrstuvwxyz\n'
            'key = os.environ["API_KEY"]\n'
        )
        server = ServerConfig(
            name="test",
            command="python3",
            args=[str(source)],
            source_file=Path("/tmp/test.json"),
        )
        findings = scan(server)
        source_findings = [f for f in findings if "source" in f.title.lower()]
        assert len(source_findings) == 0
