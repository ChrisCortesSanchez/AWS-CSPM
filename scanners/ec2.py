"""
EC2 Scanner - checks for EC2 and Security Group misconfigurations.

Checks implemented:
  EC2-001 [CRITICAL] Security group allows SSH (22) from 0.0.0.0/0   CIS 5.2
  EC2-002 [CRITICAL] Security group allows RDP (3389) from 0.0.0.0/0 CIS 5.3
  EC2-003 [HIGH]     Security group allows all traffic (port -1)
  EC2-004 [MEDIUM]   EBS volumes not encrypted
  EC2-005 [MEDIUM]   IMDSv2 not enforced on instances
"""
from typing import List
from scanners.base import BaseScanner
from utils.aws_client import get_client
from utils.severity import Finding, Severity


class EC2Scanner(BaseScanner):
    def __init__(self, region: str = "us-east-1"):
        super().__init__(region)
        self.client = get_client("ec2", region)

    def run(self) -> List[Finding]:
        self._check_security_groups()
        self._check_ebs_encryption()
        self._check_imdsv2()
        return self.findings

    def _check_security_groups(self):
        """CIS 5.2 / 5.3 - No security group should allow unrestricted SSH or RDP."""
        OPEN_CIDRS = ["0.0.0.0/0", "::/0"]

        paginator = self.client.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                sg_id = sg["GroupId"]
                sg_name = sg["GroupName"]
                resource = f"{sg_id} ({sg_name})"

                for rule in sg.get("IpPermissions", []):
                    from_port = rule.get("FromPort", -1)
                    to_port = rule.get("ToPort", -1)
                    ip_protocol = rule.get("IpProtocol", "")

                    # Collect all open CIDRs in this rule
                    open_cidrs = [
                        r["CidrIp"] for r in rule.get("IpRanges", [])
                        if r["CidrIp"] in OPEN_CIDRS
                    ] + [
                        r["CidrIpv6"] for r in rule.get("Ipv6Ranges", [])
                        if r["CidrIpv6"] in OPEN_CIDRS
                    ]

                    if not open_cidrs:
                        continue

                    # Check for all traffic (-1 protocol)
                    if ip_protocol == "-1":
                        self._add_finding(Finding(
                            scanner="ec2",
                            check_id="EC2-003",
                            title="Security group allows all inbound traffic",
                            description=f"Security group '{resource}' allows all inbound traffic from {', '.join(open_cidrs)}.",
                            recommendation="Restrict inbound rules to only necessary ports and trusted IP ranges.",
                            severity=Severity.HIGH,
                            resource=f"arn:aws:ec2:{self.region}::security-group/{sg_id}",
                            region=self.region,
                            cis_control=None,
                            passed=False,
                        ))
                        continue

                    # Port range helper
                    def port_in_range(port):
                        return from_port <= port <= to_port

                    # SSH check (CIS 5.2)
                    if port_in_range(22):
                        self._add_finding(Finding(
                            scanner="ec2",
                            check_id="EC2-001",
                            title="Security group allows unrestricted SSH access",
                            description=f"Security group '{resource}' allows SSH (port 22) from {', '.join(open_cidrs)}.",
                            recommendation="Restrict SSH access to specific trusted IP ranges only.",
                            severity=Severity.CRITICAL,
                            resource=f"arn:aws:ec2:{self.region}::security-group/{sg_id}",
                            region=self.region,
                            cis_control="5.2",
                            passed=False,
                        ))

                    # RDP check (CIS 5.3)
                    if port_in_range(3389):
                        self._add_finding(Finding(
                            scanner="ec2",
                            check_id="EC2-002",
                            title="Security group allows unrestricted RDP access",
                            description=f"Security group '{resource}' allows RDP (port 3389) from {', '.join(open_cidrs)}.",
                            recommendation="Restrict RDP access to specific trusted IP ranges only.",
                            severity=Severity.CRITICAL,
                            resource=f"arn:aws:ec2:{self.region}::security-group/{sg_id}",
                            region=self.region,
                            cis_control="5.3",
                            passed=False,
                        ))

    def _check_ebs_encryption(self):
        """Check that all EBS volumes are encrypted at rest."""
        paginator = self.client.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for volume in page["Volumes"]:
                vol_id = volume["VolumeId"]
                encrypted = volume.get("Encrypted", False)

                self._add_finding(Finding(
                    scanner="ec2",
                    check_id="EC2-004",
                    title="EBS volume not encrypted",
                    description=f"EBS volume '{vol_id}' is not encrypted at rest.",
                    recommendation="Enable EBS encryption. Use AWS KMS to manage encryption keys.",
                    severity=Severity.MEDIUM,
                    resource=f"arn:aws:ec2:{self.region}::volume/{vol_id}",
                    region=self.region,
                    cis_control=None,
                    passed=encrypted,
                ))

    def _check_imdsv2(self):
        """Check that IMDSv2 is enforced on all EC2 instances (prevents SSRF attacks)."""
        paginator = self.client.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:
                    instance_id = instance["InstanceId"]

                    # Get instance name tag if available
                    name = instance_id
                    for tag in instance.get("Tags", []):
                        if tag["Key"] == "Name":
                            name = f"{tag['Value']} ({instance_id})"

                    metadata_options = instance.get("MetadataOptions", {})
                    imdsv2_required = metadata_options.get("HttpTokens") == "required"

                    self._add_finding(Finding(
                        scanner="ec2",
                        check_id="EC2-005",
                        title="IMDSv2 not enforced on EC2 instance",
                        description=f"Instance '{name}' does not require IMDSv2, leaving it vulnerable to SSRF-based metadata attacks.",
                        recommendation="Set HttpTokens to 'required' to enforce IMDSv2 on all instances.",
                        severity=Severity.MEDIUM,
                        resource=f"arn:aws:ec2:{self.region}:instance:{instance_id}",
                        region=self.region,
                        cis_control=None,
                        passed=imdsv2_required,
                    ))