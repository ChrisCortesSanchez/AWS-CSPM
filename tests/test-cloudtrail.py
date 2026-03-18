"""
Unit tests for the CloudTrail scanner using moto to mock AWS API calls.
Run with: pytest tests/test_cloudtrail.py -v
"""
import boto3
from moto import mock_aws
from scanners.cloudtrail import CloudTrailScanner


def _create_trail(ct_client, s3_client, name="test-trail", multi_region=False, log_validation=False):
    """Helper: create an S3 bucket and a CloudTrail trail."""
    bucket = f"{name}-bucket"
    s3_client.create_bucket(Bucket=bucket)
    ct_client.create_trail(
        Name=name,
        S3BucketName=bucket,
        IsMultiRegionTrail=multi_region,
        EnableLogFileValidation=log_validation,
    )
    ct_client.start_logging(Name=name)


@mock_aws
def test_ct_001_fails_when_no_trails():
    """No trails configured in region should fail CT-001."""
    scanner = CloudTrailScanner(region="us-east-1")
    findings = scanner.run()

    finding = next(f for f in findings if f.check_id == "CT-001")
    assert finding.passed is False


@mock_aws
def test_ct_001_passes_when_trail_is_logging():
    """Active trail should pass CT-001."""
    ct = boto3.client("cloudtrail", region_name="us-east-1")
    s3 = boto3.client("s3", region_name="us-east-1")
    _create_trail(ct, s3)

    scanner = CloudTrailScanner(region="us-east-1")
    findings = scanner.run()

    finding = next(f for f in findings if f.check_id == "CT-001")
    assert finding.passed is True


@mock_aws
def test_ct_002_fails_when_log_validation_disabled():
    """Trail without log file validation should fail CT-002."""
    ct = boto3.client("cloudtrail", region_name="us-east-1")
    s3 = boto3.client("s3", region_name="us-east-1")
    _create_trail(ct, s3, log_validation=False)

    scanner = CloudTrailScanner(region="us-east-1")
    findings = scanner.run()

    finding = next(f for f in findings if f.check_id == "CT-002")
    assert finding.passed is False


@mock_aws
def test_ct_002_passes_when_log_validation_enabled():
    """Trail with log file validation enabled should pass CT-002."""
    ct = boto3.client("cloudtrail", region_name="us-east-1")
    s3 = boto3.client("s3", region_name="us-east-1")
    _create_trail(ct, s3, log_validation=True)

    scanner = CloudTrailScanner(region="us-east-1")
    findings = scanner.run()

    finding = next(f for f in findings if f.check_id == "CT-002")
    assert finding.passed is True


@mock_aws
def test_ct_003_fails_when_no_kms():
    """Trail without KMS encryption should fail CT-003."""
    ct = boto3.client("cloudtrail", region_name="us-east-1")
    s3 = boto3.client("s3", region_name="us-east-1")
    _create_trail(ct, s3)

    scanner = CloudTrailScanner(region="us-east-1")
    findings = scanner.run()

    finding = next(f for f in findings if f.check_id == "CT-003")
    assert finding.passed is False


@mock_aws
def test_ct_004_fails_when_single_region_trail():
    """Single-region trail should fail CT-004."""
    ct = boto3.client("cloudtrail", region_name="us-east-1")
    s3 = boto3.client("s3", region_name="us-east-1")
    _create_trail(ct, s3, multi_region=False)

    scanner = CloudTrailScanner(region="us-east-1")
    findings = scanner.run()

    finding = next(f for f in findings if f.check_id == "CT-004")
    assert finding.passed is False


@mock_aws
def test_ct_004_passes_when_multi_region_trail():
    """Multi-region trail should pass CT-004."""
    ct = boto3.client("cloudtrail", region_name="us-east-1")
    s3 = boto3.client("s3", region_name="us-east-1")
    _create_trail(ct, s3, multi_region=True)

    scanner = CloudTrailScanner(region="us-east-1")
    findings = scanner.run()

    finding = next(f for f in findings if f.check_id == "CT-004")
    assert finding.passed is True