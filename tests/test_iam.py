"""
Unit tests for the IAM scanner using moto to mock AWS API calls.
Run with: pytest tests/test_iam.py -v
"""
import boto3
from moto import mock_aws
from scanners.iam import IAMScanner


@mock_aws
def test_iam_001_passes_when_no_root_access_keys():
    """Root account with no access keys should pass IAM-001."""
    scanner = IAMScanner(region="us-east-1")
    findings = scanner.run()

    finding = next(f for f in findings if f.check_id == "IAM-001")
    assert finding.passed is True


@mock_aws
def test_iam_002_check_exists():
    """IAM-002 root MFA check should always produce a finding."""
    scanner = IAMScanner(region="us-east-1")
    findings = scanner.run()

    finding = next(f for f in findings if f.check_id == "IAM-002")
    assert finding is not None


@mock_aws
def test_iam_004_fails_when_no_password_policy():
    """Account with no password policy set should fail IAM-004."""
    scanner = IAMScanner(region="us-east-1")
    findings = scanner.run()

    finding = next(f for f in findings if f.check_id == "IAM-004")
    assert finding.passed is False


@mock_aws
def test_iam_004_passes_with_strong_password_policy():
    """Account with a CIS-compliant password policy should pass IAM-004."""
    iam = boto3.client("iam", region_name="us-east-1")
    iam.update_account_password_policy(
        MinimumPasswordLength=14,
        RequireSymbols=True,
        RequireNumbers=True,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
        MaxPasswordAge=90,
    )

    scanner = IAMScanner(region="us-east-1")
    findings = scanner.run()

    finding = next(f for f in findings if f.check_id == "IAM-004")
    assert finding.passed is True


@mock_aws
def test_iam_005_fails_when_user_has_inline_policy():
    """IAM user with an inline policy attached should fail IAM-005."""
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="test-user")
    iam.put_user_policy(
        UserName="test-user",
        PolicyName="InlinePolicy",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'
    )

    scanner = IAMScanner(region="us-east-1")
    findings = scanner.run()

    finding = next(
        (f for f in findings if f.check_id == "IAM-005" and "test-user" in f.description),
        None
    )
    assert finding is not None
    assert finding.passed is False


@mock_aws
def test_iam_005_passes_when_no_inline_policies():
    """IAM user with no inline policies should pass IAM-005."""
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="clean-user")

    scanner = IAMScanner(region="us-east-1")
    findings = scanner.run()

    finding = next(
        (f for f in findings if f.check_id == "IAM-005" and "clean-user" in f.description),
        None
    )
    assert finding is not None
    assert finding.passed is True