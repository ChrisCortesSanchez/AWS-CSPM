"""
Severity levels, Finding data structure, and risk scoring.
Every scanner returns a list of Finding objects.
"""
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# Maps severity to a numeric weight for scoring
SEVERITY_SCORE = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 2,
    Severity.INFO: 0,
}

# Grade thresholds
GRADE_THRESHOLDS = [
    (90, "A"),
    (75, "B"),
    (60, "C"),
    (40, "D"),
    (0,  "F"),
]


@dataclass
class Finding:
    """Represents a single misconfiguration finding."""
    scanner: str
    check_id: str
    title: str
    description: str
    recommendation: str
    severity: Severity
    resource: str
    region: str
    cis_control: Optional[str] = None
    passed: bool = False

    def to_dict(self) -> dict:
        return {
            "scanner": self.scanner,
            "check_id": self.check_id,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "severity": self.severity.value,
            "resource": self.resource,
            "region": self.region,
            "cis_control": self.cis_control,
            "passed": self.passed,
        }


def calculate_risk_score(findings: List[Finding]) -> dict:
    """
    Calculate a 0-100 security score from a list of findings.

    Scoring logic:
      - Start at 100
      - Deduct weighted points per failing finding based on severity
      - Normalized against a worst-case all-CRITICAL scenario
      - Score floors at 0

    Returns a dict with score, grade, and breakdown.
    """
    if not findings:
        return {"score": 100, "grade": "A", "breakdown": {}}

    failures = [f for f in findings if not f.passed]

    if not failures:
        return {"score": 100, "grade": "A", "breakdown": {}}

    # Count failures by severity
    counts = {s.value: 0 for s in Severity}
    for f in failures:
        counts[f.severity.value] += 1

    # Total penalty vs worst-case (all checks are CRITICAL failures)
    total_penalty = sum(SEVERITY_SCORE[f.severity] for f in failures)
    max_possible_penalty = SEVERITY_SCORE[Severity.CRITICAL] * len(findings)

    score = max(0, round(100 - (total_penalty / max_possible_penalty * 100)))

    # Assign grade
    grade = "F"
    for threshold, letter in GRADE_THRESHOLDS:
        if score >= threshold:
            grade = letter
            break

    return {
        "score": score,
        "grade": grade,
        "breakdown": {
            "total_checks": len(findings),
            "total_findings": len(failures),
            "critical": counts["CRITICAL"],
            "high": counts["HIGH"],
            "medium": counts["MEDIUM"],
            "low": counts["LOW"],
        }
    }