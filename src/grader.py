"""Grade MCP servers based on scan findings."""

from .models import Finding, Grade, ScanResult, Severity


def grade_server(result: ScanResult) -> ScanResult:
    """Calculate grade and score for a scan result.

    Scoring: Start at 100, deduct based on findings.
    Grade thresholds: A>=90, B>=75, C>=60, D>=40, F<40.
    Any CRITICAL finding = automatic F.
    """
    score = 100

    for finding in result.findings:
        score -= finding.severity.weight

    # Floor at 0
    score = max(0, score)

    # Any critical finding = automatic cap at F
    if result.critical_count > 0:
        score = min(score, 35)

    # Assign grade
    if score >= 90:
        grade = Grade.A
    elif score >= 75:
        grade = Grade.B
    elif score >= 60:
        grade = Grade.C
    elif score >= 40:
        grade = Grade.D
    else:
        grade = Grade.F

    result.score = score
    result.grade = grade
    return result
