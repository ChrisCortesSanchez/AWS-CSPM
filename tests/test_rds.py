"""
Unit tests for the RDS scanner using moto to mock AWS API calls.
Run with: pytest tests/test_rds.py -v
"""
import boto3
from moto import mock_aws
from scanners.rds import RDSScanner


def _create_instance(rds_client, db_id="test-db", **kwargs):
    """Helper: create an RDS instance with given parameters."""
    defaults = {
        "DBInstanceIdentifier": db_id,
        "DBInstanceClass": "db.t3.micro",
        "Engine": "mysql",
        "MasterUsername": "admin",
        "MasterUserPassword": "password123!",
        "StorageEncrypted": False,
        "BackupRetentionPeriod": 0,
        "PubliclyAccessible": False,
        "AutoMinorVersionUpgrade": False,
        "MultiAZ": False,
        "DeletionProtection": False,
    }
    defaults.update(kwargs)
    rds_client.create_db_instance(**defaults)


@mock_aws
def test_no_findings_when_no_instances():
    """Scanner should return 0 findings when no RDS instances exist."""
    scanner = RDSScanner(region="us-east-1")
    findings = scanner.run()
    assert len(findings) == 0


@mock_aws
def test_rds_001_fails_when_not_encrypted():
    """Unencrypted RDS instance should fail RDS-001."""
    rds = boto3.client("rds", region_name="us-east-1")
    _create_instance(rds, StorageEncrypted=False)

    scanner = RDSScanner(region="us-east-1")
    findings = scanner.run()

    finding = next(f for f in findings if f.check_id == "RDS-001")
    assert finding.passed is False


@mock_aws
def test_rds_001_passes_when_encrypted():
    """Encrypted RDS instance should pass RDS-001."""
    rds = boto3.client("rds", region_name="us-east-1")
    _create_instance(rds, StorageEncrypted=True)

    scanner = RDSScanner(region="us-east-1")
    findings = scanner.run()

    finding = next(f for f in findings if f.check_id == "RDS-001")
    assert finding.passed is True


@mock_aws
def test_rds_002_fails_when_no_backups():
    """RDS instance with 0 day retention should fail RDS-002."""
    rds = boto3.client("rds", region_name="us-east-1")
    _create_instance(rds, BackupRetentionPeriod=0)

    scanner = RDSScanner(region="us-east-1")
    findings = scanner.run()

    finding = next(f for f in findings if f.check_id == "RDS-002")
    assert finding.passed is False


@mock_aws
def test_rds_002_passes_when_backups_enabled():
    """RDS instance with 7 day retention should pass RDS-002."""
    rds = boto3.client("rds", region_name="us-east-1")
    _create_instance(rds, BackupRetentionPeriod=7)

    scanner = RDSScanner(region="us-east-1")
    findings = scanner.run()

    finding = next(f for f in findings if f.check_id == "RDS-002")
    assert finding.passed is True


@mock_aws
def test_rds_003_fails_when_publicly_accessible():
    """Publicly accessible RDS instance should fail RDS-003."""
    rds = boto3.client("rds", region_name="us-east-1")
    _create_instance(rds, PubliclyAccessible=True)

    scanner = RDSScanner(region="us-east-1")
    findings = scanner.run()

    finding = next(f for f in findings if f.check_id == "RDS-003")
    assert finding.passed is False


@mock_aws
def test_rds_003_passes_when_not_publicly_accessible():
    """Private RDS instance should pass RDS-003."""
    rds = boto3.client("rds", region_name="us-east-1")
    _create_instance(rds, PubliclyAccessible=False)

    scanner = RDSScanner(region="us-east-1")
    findings = scanner.run()

    finding = next(f for f in findings if f.check_id == "RDS-003")
    assert finding.passed is True


@mock_aws
def test_rds_004_fails_when_auto_upgrade_disabled():
    """RDS instance with auto minor version upgrade disabled should fail RDS-004."""
    rds = boto3.client("rds", region_name="us-east-1")
    _create_instance(rds, AutoMinorVersionUpgrade=False)

    scanner = RDSScanner(region="us-east-1")
    findings = scanner.run()

    finding = next(f for f in findings if f.check_id == "RDS-004")
    assert finding.passed is False


@mock_aws
def test_rds_005_fails_when_single_az():
    """RDS instance without Multi-AZ should fail RDS-005."""
    rds = boto3.client("rds", region_name="us-east-1")
    _create_instance(rds, MultiAZ=False)

    scanner = RDSScanner(region="us-east-1")
    findings = scanner.run()

    finding = next(f for f in findings if f.check_id == "RDS-005")
    assert finding.passed is False


@mock_aws
def test_rds_006_fails_when_no_deletion_protection():
    """RDS instance without deletion protection should fail RDS-006."""
    rds = boto3.client("rds", region_name="us-east-1")
    _create_instance(rds, DeletionProtection=False)

    scanner = RDSScanner(region="us-east-1")
    findings = scanner.run()

    finding = next(f for f in findings if f.check_id == "RDS-006")
    assert finding.passed is False


@mock_aws
def test_rds_006_passes_when_deletion_protection_enabled():
    """RDS instance with deletion protection enabled should pass RDS-006."""
    rds = boto3.client("rds", region_name="us-east-1")
    _create_instance(rds, DeletionProtection=True)

    scanner = RDSScanner(region="us-east-1")
    findings = scanner.run()

    finding = next(f for f in findings if f.check_id == "RDS-006")
    assert finding.passed is True