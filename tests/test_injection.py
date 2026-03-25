"""Tests for the injection scanner."""

import pytest
from pathlib import Path

from src.models import Category, ServerConfig, Severity
from src.scanners.injection import scan


@pytest.fixture
def server_with_source(tmp_path):
    """Create a server config pointing to a temp source file."""
    def _create(code: str) -> ServerConfig:
        source = tmp_path / "server.py"
        source.write_text(code)
        return ServerConfig(
            name="test",
            command="python3",
            args=[str(source)],
            source_file=Path("/tmp/test.json"),
        )
    return _create


class TestInjectionScanner:
    def test_detects_subprocess_shell_true(self, server_with_source):
        server = server_with_source(
            'import subprocess\n'
            'def handle_tool(args):\n'
            '    subprocess.run(args["cmd"], shell=True)\n'
        )
        findings = scan(server)
        assert len(findings) >= 1
        assert findings[0].category == Category.INJECTION
        assert findings[0].severity == Severity.HIGH

    def test_detects_os_system(self, server_with_source):
        server = server_with_source(
            'import os\n'
            'def run_command(cmd):\n'
            '    os.system(cmd)\n'
        )
        findings = scan(server)
        assert len(findings) >= 1
        assert any("os.system" in f.title for f in findings)

    def test_detects_eval(self, server_with_source):
        server = server_with_source(
            'def handle_tool(args):\n'
            '    result = eval(args["expression"])\n'
        )
        findings = scan(server)
        assert len(findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_detects_exec(self, server_with_source):
        server = server_with_source(
            'def handle_tool(args):\n'
            '    exec(args["code"])\n'
        )
        findings = scan(server)
        assert len(findings) >= 1
        assert any("exec" in f.title for f in findings)

    def test_detects_fstring_in_subprocess(self, server_with_source):
        server = server_with_source(
            'import subprocess\n'
            'def run(cmd):\n'
            '    subprocess.run(f"echo {cmd}", shell=True)\n'
        )
        findings = scan(server)
        assert len(findings) >= 1
        assert any("f-string" in f.title for f in findings)

    def test_detects_os_popen(self, server_with_source):
        server = server_with_source(
            'import os\n'
            'output = os.popen("ls -la").read()\n'
        )
        findings = scan(server)
        assert any("os.popen" in f.title for f in findings)

    def test_clean_code_no_findings(self, server_with_source):
        server = server_with_source(
            'import subprocess\n'
            'def safe_run(args):\n'
            '    subprocess.run(["echo", args["msg"]])\n'
        )
        findings = scan(server)
        assert len(findings) == 0

    def test_ignores_comments(self, server_with_source):
        server = server_with_source(
            '# os.system("dangerous")\n'
            '# subprocess.run(cmd, shell=True)\n'
            'print("safe")\n'
        )
        findings = scan(server)
        assert len(findings) == 0

    def test_no_source_no_findings(self):
        server = ServerConfig(
            name="test",
            command="python3",
            args=["/nonexistent/server.py"],
            source_file=Path("/tmp/test.json"),
        )
        findings = scan(server)
        assert len(findings) == 0

    def test_detects_format_in_os_system(self, server_with_source):
        server = server_with_source(
            'import os\n'
            'def run(cmd):\n'
            '    os.system(f"ls {cmd}")\n'
        )
        findings = scan(server)
        assert any("f-string in os.system" in f.title for f in findings)


class TestNodeInjection:
    def test_detects_child_process_exec(self, tmp_path):
        source = tmp_path / "server.js"
        source.write_text(
            'const { exec } = require("child_process");\n'
            'function handle(args) {\n'
            '  child_process.exec(args.cmd);\n'
            '}\n'
        )
        server = ServerConfig(
            name="test",
            command="node",
            args=[str(source)],
            source_file=Path("/tmp/test.json"),
        )
        findings = scan(server)
        assert any("child_process" in f.title for f in findings)

    def test_detects_new_function(self, tmp_path):
        source = tmp_path / "server.js"
        source.write_text(
            'function handle(args) {\n'
            '  const fn = new Function(args.code);\n'
            '  fn();\n'
            '}\n'
        )
        server = ServerConfig(
            name="test",
            command="node",
            args=[str(source)],
            source_file=Path("/tmp/test.json"),
        )
        findings = scan(server)
        assert any("Function" in f.title for f in findings)
