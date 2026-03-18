"""
Base scanner class. Every scanner inherits from this.
"""
from abc import ABC, abstractmethod
from typing import List
from utils.severity import Finding


class BaseScanner(ABC):
    """
    Abstract base class for all CSPM scanners.

    Each subclass implements `run()` and returns a list of Finding objects.
    """

    def __init__(self, region: str = "us-east-1"):
        self.region = region
        self.findings: List[Finding] = []

    @abstractmethod
    def run(self) -> List[Finding]:
        """Execute all checks and return findings."""
        pass

    def _add_finding(self, finding: Finding):
        self.findings.append(finding)

    def summary(self) -> dict:
        """Return a count of findings by severity."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            if not f.passed:
                counts[f.severity.value] += 1
        return counts