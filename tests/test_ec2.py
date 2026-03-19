"""
Unit tests for the EC2 scanner using moto to mock AWS API calls.
Run with: pytest tests/test_ec2.py -v
"""
import boto3
from moto import mock_aws
from scanners.ec2 import EC2Scanner


def _create_open_ssh_sg(ec2_client):
    """Helper: security group with SSH open to 0.0.0.0/0."""
    sg = ec2_client.create_security_group(
        GroupName="open-ssh-sg",
        Description="Test SG with open SSH"
    )
    ec2_client.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }]
    )
    return sg["GroupId"]


def _create_restricted_ssh_sg(ec2_client):
    """Helper: security group with SSH restricted to a single IP."""
    sg = ec2_client.create_security_group(
        GroupName="restricted-ssh-sg",
        Description="Test SG with restricted SSH"
    )
    ec2_client.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "10.0.0.1/32"}],
        }]
    )
    return sg["GroupId"]


@mock_aws
def test_ec2_001_fails_when_ssh_open_to_world():
    """Security group allowing SSH from 0.0.0.0/0 should produce EC2-001 finding."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    _create_open_ssh_sg(ec2)

    scanner = EC2Scanner(region="us-east-1")
    findings = scanner.run()

    ssh_findings = [f for f in findings if f.check_id == "EC2-001"]
    assert len(ssh_findings) > 0
    assert all(f.passed is False for f in ssh_findings)


@mock_aws
def test_ec2_001_no_finding_when_ssh_restricted():
    """Security group with SSH restricted to a specific IP should not produce EC2-001."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    _create_restricted_ssh_sg(ec2)

    scanner = EC2Scanner(region="us-east-1")
    findings = scanner.run()

    ssh_findings = [f for f in findings if f.check_id == "EC2-001"]
    assert len(ssh_findings) == 0


@mock_aws
def test_ec2_002_fails_when_rdp_open_to_world():
    """Security group allowing RDP from 0.0.0.0/0 should produce EC2-002 finding."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(GroupName="open-rdp-sg", Description="Open RDP")
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 3389,
            "ToPort": 3389,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }]
    )

    scanner = EC2Scanner(region="us-east-1")
    findings = scanner.run()

    rdp_findings = [f for f in findings if f.check_id == "EC2-002"]
    assert len(rdp_findings) > 0
    assert all(f.passed is False for f in rdp_findings)


@mock_aws
def test_ec2_004_fails_when_ebs_unencrypted():
    """Unencrypted EBS volume should fail EC2-004."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    ec2.create_volume(AvailabilityZone="us-east-1a", Size=8, Encrypted=False)

    scanner = EC2Scanner(region="us-east-1")
    findings = scanner.run()

    ebs_findings = [f for f in findings if f.check_id == "EC2-004" and not f.passed]
    assert len(ebs_findings) > 0


@mock_aws
def test_ec2_004_passes_when_ebs_encrypted():
    """Encrypted EBS volume should pass EC2-004."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    ec2.create_volume(AvailabilityZone="us-east-1a", Size=8, Encrypted=True)

    scanner = EC2Scanner(region="us-east-1")
    findings = scanner.run()

    ebs_findings = [f for f in findings if f.check_id == "EC2-004"]
    assert all(f.passed is True for f in ebs_findings)