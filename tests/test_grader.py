"""Tests for the grading system."""

import pytest

from src.models import (
    Category, Finding, Grade, ScanResult, ServerConfig, Severity,
)
from src.grader import grade_server


def _make_result(*severities: Severity) -> ScanResult:
    """Helper to create a ScanResult with findings of given severities."""
    return ScanResult(
        server=ServerConfig(name="test", command="python3"),
        findings=[
            Finding(sev, Category.SECRETS, "test", "desc", "rec")
            for sev in severities
        ],
    )


class TestGrader:
    def test_clean_server_grade_a(self):
        result = _make_result()
        graded = grade_server(result)
        assert graded.grade == Grade.A
        assert graded.score == 100

    def test_info_only_still_a(self):
        result = _make_result(Severity.INFO, Severity.INFO)
        graded = grade_server(result)
        assert graded.grade == Grade.A
        assert graded.score == 100

    def test_one_low_still_a(self):
        result = _make_result(Severity.LOW)
        graded = grade_server(result)
        assert graded.grade == Grade.A  # 100 - 3 = 97

    def test_one_medium_grade_a(self):
        result = _make_result(Severity.MEDIUM)
        graded = grade_server(result)
        assert graded.grade == Grade.A  # 100 - 10 = 90

    def test_one_high_grade_b(self):
        result = _make_result(Severity.HIGH)
        graded = grade_server(result)
        assert graded.grade == Grade.B  # 100 - 20 = 80

    def test_critical_auto_fail(self):
        result = _make_result(Severity.CRITICAL)
        graded = grade_server(result)
        assert graded.grade == Grade.F
        assert graded.score <= 35

    def test_multiple_highs_grade_c(self):
        result = _make_result(Severity.HIGH, Severity.HIGH)
        graded = grade_server(result)
        assert graded.grade == Grade.C  # 100 - 40 = 60

    def test_many_mediums_degrade(self):
        result = _make_result(
            Severity.MEDIUM, Severity.MEDIUM, Severity.MEDIUM,
            Severity.MEDIUM, Severity.MEDIUM,
        )
        graded = grade_server(result)
        assert graded.score == 50  # 100 - 50
        assert graded.grade == Grade.D

    def test_score_floors_at_zero(self):
        result = _make_result(
            Severity.CRITICAL, Severity.CRITICAL, Severity.CRITICAL,
        )
        graded = grade_server(result)
        assert graded.score >= 0
