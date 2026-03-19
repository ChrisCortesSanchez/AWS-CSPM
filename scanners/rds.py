"""
RDS Scanner - checks for RDS database misconfigurations.

Checks implemented:
  RDS-001 [HIGH]     Database instance not encrypted at rest
  RDS-002 [MEDIUM]   Automated backups disabled
  RDS-003 [CRITICAL] Database instance publicly accessible
  RDS-004 [LOW]      Minor version auto-upgrade disabled
  RDS-005 [MEDIUM]   Multi-AZ not enabled (single point of failure)
  RDS-006 [HIGH]     Deletion protection not enabled
"""
from typing import List
from scanners.base import BaseScanner
from utils.aws_client import get_client
from utils.severity import Finding, Severity


class RDSScanner(BaseScanner):
    def __init__(self, region: str = "us-east-1"):
        super().__init__(region)
        self.client = get_client("rds", region)

    def run(self) -> List[Finding]:
        instances = self._get_instances()
        for instance in instances:
            self._check_encryption(instance)
            self._check_automated_backups(instance)
            self._check_public_access(instance)
            self._check_minor_version_upgrade(instance)
            self._check_multi_az(instance)
            self._check_deletion_protection(instance)
        return self.findings

    def _get_instances(self) -> list:
        """Return all RDS DB instances in the region."""
        instances = []
        paginator = self.client.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            instances.extend(page.get("DBInstances", []))
        return instances

    def _check_encryption(self, instance: dict):
        """RDS-001 - RDS instances should be encrypted at rest."""
        db_id = instance["DBInstanceIdentifier"]
        encrypted = instance.get("StorageEncrypted", False)

        self._add_finding(Finding(
            scanner="rds",
            check_id="RDS-001",
            title="RDS instance not encrypted at rest",
            description=f"RDS instance '{db_id}' does not have storage encryption enabled.",
            recommendation="Enable encryption at rest. Note: encryption must be set at creation time. Encrypt a snapshot and restore to a new instance.",
            severity=Severity.HIGH,
            resource=instance.get("DBInstanceArn", db_id),
            region=self.region,
            cis_control=None,
            passed=encrypted,
        ))

    def _check_automated_backups(self, instance: dict):
        """RDS-002 - Automated backups should be enabled with a retention period > 0."""
        db_id = instance["DBInstanceIdentifier"]
        retention = instance.get("BackupRetentionPeriod", 0)
        passed = retention > 0

        self._add_finding(Finding(
            scanner="rds",
            check_id="RDS-002",
            title="RDS automated backups disabled",
            description=f"RDS instance '{db_id}' has a backup retention period of {retention} days. Automated backups are disabled.",
            recommendation="Set a backup retention period of at least 7 days to enable point-in-time recovery.",
            severity=Severity.MEDIUM,
            resource=instance.get("DBInstanceArn", db_id),
            region=self.region,
            cis_control=None,
            passed=passed,
        ))

    def _check_public_access(self, instance: dict):
        """RDS-003 - RDS instances should not be publicly accessible."""
        db_id = instance["DBInstanceIdentifier"]
        publicly_accessible = instance.get("PubliclyAccessible", False)

        self._add_finding(Finding(
            scanner="rds",
            check_id="RDS-003",
            title="RDS instance is publicly accessible",
            description=f"RDS instance '{db_id}' is configured to be publicly accessible from the internet.",
            recommendation="Disable public accessibility and place the instance in a private subnet. Use a bastion host or VPN for access.",
            severity=Severity.CRITICAL,
            resource=instance.get("DBInstanceArn", db_id),
            region=self.region,
            cis_control=None,
            passed=not publicly_accessible,
        ))

    def _check_minor_version_upgrade(self, instance: dict):
        """RDS-004 - Auto minor version upgrade keeps instances patched."""
        db_id = instance["DBInstanceIdentifier"]
        auto_upgrade = instance.get("AutoMinorVersionUpgrade", False)

        self._add_finding(Finding(
            scanner="rds",
            check_id="RDS-004",
            title="RDS minor version auto-upgrade disabled",
            description=f"RDS instance '{db_id}' does not have automatic minor version upgrades enabled.",
            recommendation="Enable auto minor version upgrade to ensure security patches are applied automatically.",
            severity=Severity.LOW,
            resource=instance.get("DBInstanceArn", db_id),
            region=self.region,
            cis_control=None,
            passed=auto_upgrade,
        ))

    def _check_multi_az(self, instance: dict):
        """RDS-005 - Multi-AZ deployments provide high availability."""
        db_id = instance["DBInstanceIdentifier"]
        multi_az = instance.get("MultiAZ", False)

        self._add_finding(Finding(
            scanner="rds",
            check_id="RDS-005",
            title="RDS instance not configured for Multi-AZ",
            description=f"RDS instance '{db_id}' is not deployed across multiple availability zones.",
            recommendation="Enable Multi-AZ deployment for automatic failover and high availability.",
            severity=Severity.MEDIUM,
            resource=instance.get("DBInstanceArn", db_id),
            region=self.region,
            cis_control=None,
            passed=multi_az,
        ))

    def _check_deletion_protection(self, instance: dict):
        """RDS-006 - Deletion protection prevents accidental database deletion."""
        db_id = instance["DBInstanceIdentifier"]
        deletion_protection = instance.get("DeletionProtection", False)

        self._add_finding(Finding(
            scanner="rds",
            check_id="RDS-006",
            title="RDS deletion protection not enabled",
            description=f"RDS instance '{db_id}' does not have deletion protection enabled.",
            recommendation="Enable deletion protection to prevent accidental or malicious deletion of the database.",
            severity=Severity.HIGH,
            resource=instance.get("DBInstanceArn", db_id),
            region=self.region,
            cis_control=None,
            passed=deletion_protection,
        ))