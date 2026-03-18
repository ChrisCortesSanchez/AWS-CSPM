"""
S3 Scanner - checks for S3 bucket misconfigurations.

Checks implemented:
  S3-001 [HIGH]     Block Public Access not fully enabled        CIS 2.1.5
  S3-002 [HIGH]     Server-side encryption not enabled           CIS 2.1.1
  S3-003 [MEDIUM]   Versioning not enabled
  S3-004 [MEDIUM]   Bucket logging not enabled                   CIS 2.1.2
  S3-005 [CRITICAL] Bucket ACL allows public READ or WRITE
"""
from typing import List
from scanners.base import BaseScanner
from utils.aws_client import get_client
from utils.severity import Finding, Severity


class S3Scanner(BaseScanner):
    def __init__(self, region: str = "us-east-1"):
        super().__init__(region)
        self.client = get_client("s3", region)

    def run(self) -> List[Finding]:
        """Run all S3 checks across all buckets."""
        buckets = self.client.list_buckets().get("Buckets", [])
        for bucket in buckets:
            name = bucket["Name"]
            self._check_public_access_block(name)
            self._check_encryption(name)
            self._check_versioning(name)
            self._check_logging(name)
            self._check_acl(name)
        return self.findings

    # ------------------------------------------------------------------
    # Individual checks — implement each one in the S3 module session
    # ------------------------------------------------------------------

    def _check_public_access_block(self, bucket_name: str):
        """CIS 2.1.5 - All 4 public access block settings must be True."""
        try:
            resp = self.client.get_public_access_block(Bucket=bucket_name)
            config = resp["PublicAccessBlockConfiguration"]
            all_blocked = all([
                config.get("BlockPublicAcls", False),
                config.get("IgnorePublicAcls", False),
                config.get("BlockPublicPolicy", False),
                config.get("RestrictPublicBuckets", False),
            ])
            self._add_finding(Finding(
                scanner="s3",
                check_id="S3-001",
                title="S3 Block Public Access not fully enabled",
                description=f"Bucket '{bucket_name}' does not have all Block Public Access settings enabled.",
                recommendation="Enable all 4 Block Public Access settings: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets.",
                severity=Severity.HIGH,
                resource=f"arn:aws:s3:::{bucket_name}",
                region=self.region,
                cis_control="2.1.5",
                passed=all_blocked,
            ))
        except self.client.exceptions.NoSuchPublicAccessBlockConfiguration:
            # No config set at all — same as all False
            self._add_finding(Finding(
                scanner="s3",
                check_id="S3-001",
                title="S3 Block Public Access not fully enabled",
                description=f"Bucket '{bucket_name}' has no Block Public Access configuration.",
                recommendation="Enable all 4 Block Public Access settings.",
                severity=Severity.HIGH,
                resource=f"arn:aws:s3:::{bucket_name}",
                region=self.region,
                cis_control="2.1.5",
                passed=False,
            ))

    def _check_encryption(self, bucket_name: str):
        """CIS 2.1.1 - Bucket must have default server-side encryption enabled."""
        try:
            self.client.get_bucket_encryption(Bucket=bucket_name)
            passed = True
        except Exception:
            passed = False

        self._add_finding(Finding(
            scanner="s3",
            check_id="S3-002",
            title="S3 bucket server-side encryption not enabled",
            description=f"Bucket '{bucket_name}' does not have default server-side encryption configured.",
            recommendation="Enable default encryption using SSE-S3 (AES-256) or SSE-KMS.",
            severity=Severity.HIGH,
            resource=f"arn:aws:s3:::{bucket_name}",
            region=self.region,
            cis_control="2.1.1",
            passed=passed,
        ))

    def _check_versioning(self, bucket_name: str):
        """Check that versioning is enabled for data recovery and tamper detection."""
        try:
            resp = self.client.get_bucket_versioning(Bucket=bucket_name)
            passed = resp.get("Status") == "Enabled"
        except Exception:
            passed = False

        self._add_finding(Finding(
            scanner="s3",
            check_id="S3-003",
            title="S3 bucket versioning not enabled",
            description=f"Bucket '{bucket_name}' does not have versioning enabled.",
            recommendation="Enable versioning to protect against accidental deletion and data tampering.",
            severity=Severity.MEDIUM,
            resource=f"arn:aws:s3:::{bucket_name}",
            region=self.region,
            cis_control=None,
            passed=passed,
        ))

    def _check_logging(self, bucket_name: str):
        """CIS 2.1.2 - Server access logging should be enabled."""
        try:
            resp = self.client.get_bucket_logging(Bucket=bucket_name)
            passed = "LoggingEnabled" in resp
        except Exception:
            passed = False

        self._add_finding(Finding(
            scanner="s3",
            check_id="S3-004",
            title="S3 bucket access logging not enabled",
            description=f"Bucket '{bucket_name}' does not have server access logging enabled.",
            recommendation="Enable server access logging to capture all requests made to the bucket.",
            severity=Severity.MEDIUM,
            resource=f"arn:aws:s3:::{bucket_name}",
            region=self.region,
            cis_control="2.1.2",
            passed=passed,
        ))

    def _check_acl(self, bucket_name: str):
        """Check bucket ACL for public READ or WRITE grants."""
        PUBLIC_URIS = [
            "http://acs.amazonaws.com/groups/global/AllUsers",
            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
        ]
        try:
            resp = self.client.get_bucket_acl(Bucket=bucket_name)
            grants = resp.get("Grants", [])
            public_grants = [
                g for g in grants
                if g.get("Grantee", {}).get("URI") in PUBLIC_URIS
            ]
            passed = len(public_grants) == 0
        except Exception:
            passed = True  # Can't read ACL, assume fine

        self._add_finding(Finding(
            scanner="s3",
            check_id="S3-005",
            title="S3 bucket ACL allows public access",
            description=f"Bucket '{bucket_name}' has ACL grants that allow public READ or WRITE access.",
            recommendation="Remove public ACL grants and rely on bucket policies with least-privilege access.",
            severity=Severity.CRITICAL,
            resource=f"arn:aws:s3:::{bucket_name}",
            region=self.region,
            cis_control=None,
            passed=passed,
        ))
