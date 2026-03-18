"""
Severity levels and Finding data structure.
Every scanner returns a list of Finding objects.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# Maps severity to a numeric score for sorting/scoring
SEVERITY_SCORE = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 2,
    Severity.INFO: 0,
}


@dataclass
class Finding:
    """Represents a single misconfiguration finding."""
    scanner: str                    # e.g. "s3", "iam"
    check_id: str                   # e.g. "S3-001"
    title: str                      # Short human-readable title
    description: str                # What's wrong
    recommendation: str             # How to fix it
    severity: Severity
    resource: str                   # ARN or resource identifier
    region: str
    cis_control: Optional[str] = None   # e.g. "2.1.1"
    passed: bool = False            # True = check passed, False = finding

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