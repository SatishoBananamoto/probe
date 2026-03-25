"""Tests for probe data models."""

import pytest
from src.models import (
    Category, Finding, FullReport, Grade, ScanResult,
    ServerConfig, Severity, Transport,
)


class TestSeverity:
    def test_weights(self):
        assert Severity.CRITICAL.weight == 40
        assert Severity.HIGH.weight == 20
        assert Severity.MEDIUM.weight == 10
        assert Severity.LOW.weight == 3
        assert Severity.INFO.weight == 0

    def test_ordering_by_weight(self):
        severities = sorted(Severity, key=lambda s: s.weight, reverse=True)
        assert severities[0] == Severity.CRITICAL
        assert severities[-1] == Severity.INFO


class TestGrade:
    def test_labels(self):
        assert Grade.A.label == "Excellent"
        assert Grade.F.label == "Failing"


class TestServerConfig:
    def test_basic_creation(self):
        s = ServerConfig(name="test", command="python3", args=["server.py"])
        assert s.name == "test"
        assert s.transport == Transport.STDIO

    def test_resolve_nonexistent_path(self):
        s = ServerConfig(name="test", command="python3", args=["/nonexistent.py"])
        assert s.resolve_server_path() is None


class TestFinding:
    def test_sort_key(self):
        critical = Finding(
            severity=Severity.CRITICAL,
            category=Category.SECRETS,
            title="test",
            description="test",
            recommendation="test",
        )
        low = Finding(
            severity=Severity.LOW,
            category=Category.SECRETS,
            title="test",
            description="test",
            recommendation="test",
        )
        assert critical.sort_key > low.sort_key


class TestScanResult:
    def test_counts(self):
        result = ScanResult(
            server=ServerConfig(name="test", command="python3"),
            findings=[
                Finding(Severity.CRITICAL, Category.SECRETS, "a", "b", "c"),
                Finding(Severity.CRITICAL, Category.SECRETS, "a", "b", "c"),
                Finding(Severity.HIGH, Category.INJECTION, "a", "b", "c"),
                Finding(Severity.MEDIUM, Category.FILESYSTEM, "a", "b", "c"),
                Finding(Severity.LOW, Category.VALIDATION, "a", "b", "c"),
                Finding(Severity.INFO, Category.TRANSPORT, "a", "b", "c"),
            ],
        )
        assert result.critical_count == 2
        assert result.high_count == 1
        assert result.medium_count == 1
        assert result.low_count == 1
        assert result.info_count == 1

    def test_findings_by_severity(self):
        result = ScanResult(
            server=ServerConfig(name="test", command="python3"),
            findings=[
                Finding(Severity.LOW, Category.SECRETS, "low", "b", "c"),
                Finding(Severity.CRITICAL, Category.SECRETS, "crit", "b", "c"),
            ],
        )
        ordered = result.findings_by_severity()
        assert ordered[0].title == "crit"
        assert ordered[1].title == "low"


class TestFullReport:
    def test_overall_grade_worst_wins(self):
        report = FullReport(results=[
            ScanResult(
                server=ServerConfig(name="good", command="python3"),
                grade=Grade.A,
            ),
            ScanResult(
                server=ServerConfig(name="bad", command="python3"),
                grade=Grade.D,
            ),
        ])
        assert report.overall_grade == Grade.D

    def test_empty_report(self):
        report = FullReport()
        assert report.overall_grade == Grade.A
        assert report.total_findings == 0
        assert report.servers_scanned == 0

    def test_totals(self):
        report = FullReport(results=[
            ScanResult(
                server=ServerConfig(name="s1", command="python3"),
                findings=[
                    Finding(Severity.CRITICAL, Category.SECRETS, "a", "b", "c"),
                ],
            ),
            ScanResult(
                server=ServerConfig(name="s2", command="python3"),
                findings=[
                    Finding(Severity.HIGH, Category.INJECTION, "a", "b", "c"),
                    Finding(Severity.CRITICAL, Category.SECRETS, "a", "b", "c"),
                ],
            ),
        ])
        assert report.total_findings == 3
        assert report.total_critical == 2
        assert report.total_high == 1
