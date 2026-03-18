"""
CloudTrail Scanner - checks for logging and monitoring gaps.

Checks implemented:
  CT-001 [HIGH]   CloudTrail not enabled in region              CIS 3.1
  CT-002 [HIGH]   CloudTrail log file validation not enabled    CIS 3.2
  CT-003 [MEDIUM] CloudTrail logs not encrypted with KMS        CIS 3.7
  CT-004 [HIGH]   Multi-region trail not configured             CIS 3.1
"""
from typing import List
from scanners.base import BaseScanner
from utils.aws_client import get_client
from utils.severity import Finding, Severity


class CloudTrailScanner(BaseScanner):
    def __init__(self, region: str = "us-east-1"):
        super().__init__(region)
        self.client = get_client("cloudtrail", region)

    def run(self) -> List[Finding]:
        trails = self._get_trails()
        self._check_trail_enabled(trails)
        self._check_log_validation(trails)
        self._check_kms_encryption(trails)
        self._check_multi_region(trails)
        return self.findings

    def _get_trails(self) -> list:
        """Return all trails visible in this region, filtered to home region only."""
        try:
            resp = self.client.describe_trails(includeShadowTrails=False)
            return resp.get("trailList", [])
        except Exception:
            return []

    def _check_trail_enabled(self, trails: list):
        """CIS 3.1 - At least one CloudTrail trail must be active in the region."""
        if not trails:
            self._add_finding(Finding(
                scanner="cloudtrail",
                check_id="CT-001",
                title="CloudTrail not enabled in region",
                description=f"No CloudTrail trails are configured in region '{self.region}'. API activity is not being logged.",
                recommendation="Enable CloudTrail with at least one trail in this region. Enable multi-region trails for full coverage.",
                severity=Severity.HIGH,
                resource=f"arn:aws:cloudtrail:{self.region}::trail/none",
                region=self.region,
                cis_control="3.1",
                passed=False,
            ))
            return

        # Check if any trail is actually logging
        for trail in trails:
            trail_arn = trail.get("TrailARN", trail.get("Name", "unknown"))
            try:
                status = self.client.get_trail_status(Name=trail_arn)
                is_logging = status.get("IsLogging", False)
            except Exception:
                is_logging = False

            self._add_finding(Finding(
                scanner="cloudtrail",
                check_id="CT-001",
                title="CloudTrail trail is not actively logging",
                description=f"Trail '{trail.get('Name')}' exists but logging is {'enabled' if is_logging else 'disabled'}.",
                recommendation="Enable logging on all CloudTrail trails.",
                severity=Severity.HIGH,
                resource=trail_arn,
                region=self.region,
                cis_control="3.1",
                passed=is_logging,
            ))

    def _check_log_validation(self, trails: list):
        """CIS 3.2 - Log file validation ensures logs haven't been tampered with."""
        for trail in trails:
            trail_arn = trail.get("TrailARN", trail.get("Name", "unknown"))
            validated = trail.get("LogFileValidationEnabled", False)

            self._add_finding(Finding(
                scanner="cloudtrail",
                check_id="CT-002",
                title="CloudTrail log file validation not enabled",
                description=f"Trail '{trail.get('Name')}' does not have log file validation enabled. Logs could be modified without detection.",
                recommendation="Enable log file validation to detect tampering using SHA-256 hash digests.",
                severity=Severity.HIGH,
                resource=trail_arn,
                region=self.region,
                cis_control="3.2",
                passed=validated,
            ))

    def _check_kms_encryption(self, trails: list):
        """CIS 3.7 - CloudTrail logs should be encrypted with a KMS CMK."""
        for trail in trails:
            trail_arn = trail.get("TrailARN", trail.get("Name", "unknown"))
            has_kms = bool(trail.get("KMSKeyId"))

            self._add_finding(Finding(
                scanner="cloudtrail",
                check_id="CT-003",
                title="CloudTrail logs not encrypted with KMS",
                description=f"Trail '{trail.get('Name')}' is not encrypted with a KMS Customer Managed Key.",
                recommendation="Configure a KMS CMK for CloudTrail log encryption to add an extra layer of access control.",
                severity=Severity.MEDIUM,
                resource=trail_arn,
                region=self.region,
                cis_control="3.7",
                passed=has_kms,
            ))

    def _check_multi_region(self, trails: list):
        """CIS 3.1 - A multi-region trail ensures global API activity is captured."""
        has_multi_region = any(t.get("IsMultiRegionTrail", False) for t in trails)

        self._add_finding(Finding(
            scanner="cloudtrail",
            check_id="CT-004",
            title="No multi-region CloudTrail trail configured",
            description="No multi-region trail exists. API activity in other regions may go unlogged.",
            recommendation="Create a multi-region trail to capture API activity across all AWS regions.",
            severity=Severity.HIGH,
            resource=f"arn:aws:cloudtrail:{self.region}::trail/multi-region",
            region=self.region,
            cis_control="3.1",
            passed=has_multi_region,
        ))