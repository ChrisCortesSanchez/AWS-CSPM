"""
Unit tests for the S3 scanner using moto to mock AWS API calls.
Run with: pytest tests/test_s3.py -v
"""
import boto3
from moto import mock_aws
from scanners.s3 import S3Scanner


@mock_aws
def test_no_findings_when_no_buckets():
    """Scanner should return 0 findings when no buckets exist."""
    scanner = S3Scanner(region="us-east-1")
    findings = scanner.run()
    assert len(findings) == 0


@mock_aws
def test_s3_001_fails_when_no_public_access_block():
    """Bucket with no public access block config should fail S3-001."""
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket")

    scanner = S3Scanner(region="us-east-1")
    findings = scanner.run()

    finding = next(f for f in findings if f.check_id == "S3-001")
    assert finding.passed is False


@mock_aws
def test_s3_001_passes_when_public_access_fully_blocked():
    """Bucket with all 4 public access block settings enabled should pass S3-001."""
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket")
    s3.put_public_access_block(
        Bucket="test-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    )

    scanner = S3Scanner(region="us-east-1")
    findings = scanner.run()

    finding = next(f for f in findings if f.check_id == "S3-001")
    assert finding.passed is True


@mock_aws
def test_s3_002_fails_when_no_encryption():
    """Bucket without default encryption should fail S3-002."""
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket")

    scanner = S3Scanner(region="us-east-1")
    findings = scanner.run()

    finding = next(f for f in findings if f.check_id == "S3-002")
    assert finding.passed is False


@mock_aws
def test_s3_002_passes_when_encrypted():
    """Bucket with AES-256 default encryption should pass S3-002."""
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket")
    s3.put_bucket_encryption(
        Bucket="test-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        }
    )

    scanner = S3Scanner(region="us-east-1")
    findings = scanner.run()

    finding = next(f for f in findings if f.check_id == "S3-002")
    assert finding.passed is True


@mock_aws
def test_s3_003_fails_when_versioning_disabled():
    """Bucket without versioning should fail S3-003."""
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket")

    scanner = S3Scanner(region="us-east-1")
    findings = scanner.run()

    finding = next(f for f in findings if f.check_id == "S3-003")
    assert finding.passed is False


@mock_aws
def test_s3_003_passes_when_versioning_enabled():
    """Bucket with versioning enabled should pass S3-003."""
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket")
    s3.put_bucket_versioning(
        Bucket="test-bucket",
        VersioningConfiguration={"Status": "Enabled"}
    )

    scanner = S3Scanner(region="us-east-1")
    findings = scanner.run()

    finding = next(f for f in findings if f.check_id == "S3-003")
    assert finding.passed is True


@mock_aws
def test_s3_004_fails_when_logging_disabled():
    """Bucket without access logging should fail S3-004."""
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket")

    scanner = S3Scanner(region="us-east-1")
    findings = scanner.run()

    finding = next(f for f in findings if f.check_id == "S3-004")
    assert finding.passed is False