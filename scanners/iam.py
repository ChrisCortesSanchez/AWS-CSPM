"""
IAM Scanner - checks for IAM misconfigurations.

Checks implemented:
  IAM-001 [CRITICAL] Root account has active access keys         CIS 1.4
  IAM-002 [HIGH]     Root account MFA not enabled                CIS 1.5
  IAM-003 [HIGH]     User MFA not enabled for console access      CIS 1.10
  IAM-004 [MEDIUM]   Password policy too weak                     CIS 1.8
  IAM-005 [HIGH]     Inline policies attached to users            CIS 1.15
  IAM-006 [MEDIUM]   Access keys not rotated in 90 days           CIS 1.14
"""
from typing import List
from datetime import datetime, timezone, timedelta
from scanners.base import BaseScanner
from utils.aws_client import get_client
from utils.severity import Finding, Severity


class IAMScanner(BaseScanner):
    def __init__(self, region: str = "us-east-1"):
        super().__init__(region)
        self.client = get_client("iam", region)

    def run(self) -> List[Finding]:
        self._check_root_access_keys()
        self._check_root_mfa()
        self._check_user_mfa()
        self._check_password_policy()
        self._check_inline_policies()
        self._check_key_rotation()
        return self.findings

    def _check_root_access_keys(self):
        """CIS 1.4 - Root account should not have active access keys."""
        summary = self.client.get_account_summary()["SummaryMap"]
        has_keys = summary.get("AccountAccessKeysPresent", 0) > 0

        self._add_finding(Finding(
            scanner="iam",
            check_id="IAM-001",
            title="Root account has active access keys",
            description="The root account has active access keys. Root keys are extremely high risk and should never be used.",
            recommendation="Delete all root account access keys immediately. Use IAM roles or IAM users instead.",
            severity=Severity.CRITICAL,
            resource="arn:aws:iam::root",
            region=self.region,
            cis_control="1.4",
            passed=not has_keys,
        ))

    def _check_root_mfa(self):
        """CIS 1.5 - Root account should have MFA enabled."""
        summary = self.client.get_account_summary()["SummaryMap"]
        mfa_enabled = summary.get("AccountMFAEnabled", 0) == 1

        self._add_finding(Finding(
            scanner="iam",
            check_id="IAM-002",
            title="Root account MFA not enabled",
            description="The root account does not have MFA enabled, making it vulnerable to credential compromise.",
            recommendation="Enable a hardware or virtual MFA device on the root account immediately.",
            severity=Severity.HIGH,
            resource="arn:aws:iam::root",
            region=self.region,
            cis_control="1.5",
            passed=mfa_enabled,
        ))

    def _check_user_mfa(self):
        """CIS 1.10 - All IAM users with console access should have MFA enabled."""
        paginator = self.client.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]

                # Check if user has console (password) access
                try:
                    self.client.get_login_profile(UserName=username)
                    has_console = True
                except self.client.exceptions.NoSuchEntityException:
                    has_console = False

                if not has_console:
                    continue

                # Check MFA devices
                mfa_devices = self.client.list_mfa_devices(UserName=username)["MFADevices"]
                has_mfa = len(mfa_devices) > 0

                self._add_finding(Finding(
                    scanner="iam",
                    check_id="IAM-003",
                    title="IAM user console access without MFA",
                    description=f"User '{username}' has console access but no MFA device configured.",
                    recommendation="Enable MFA for all IAM users with console access.",
                    severity=Severity.HIGH,
                    resource=f"arn:aws:iam::*:user/{username}",
                    region=self.region,
                    cis_control="1.10",
                    passed=has_mfa,
                ))

    def _check_password_policy(self):
        """CIS 1.8 - Account password policy should meet minimum requirements."""
        try:
            policy = self.client.get_account_password_policy()["PasswordPolicy"]
            passed = all([
                policy.get("MinimumPasswordLength", 0) >= 14,
                policy.get("RequireSymbols", False),
                policy.get("RequireNumbers", False),
                policy.get("RequireUppercaseCharacters", False),
                policy.get("RequireLowercaseCharacters", False),
                policy.get("MaxPasswordAge", 999) <= 90,
            ])
        except self.client.exceptions.NoSuchEntityException:
            passed = False  # No policy set at all

        self._add_finding(Finding(
            scanner="iam",
            check_id="IAM-004",
            title="IAM password policy does not meet CIS requirements",
            description="The account password policy is missing or does not meet minimum security requirements (14+ chars, complexity, 90-day expiry).",
            recommendation="Set a strong password policy: min 14 chars, require uppercase/lowercase/numbers/symbols, max age 90 days.",
            severity=Severity.MEDIUM,
            resource="arn:aws:iam::*:root",
            region=self.region,
            cis_control="1.8",
            passed=passed,
        ))

    def _check_inline_policies(self):
        """CIS 1.15 - IAM users should not have inline policies attached."""
        paginator = self.client.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                inline = self.client.list_user_policies(UserName=username)["PolicyNames"]
                has_inline = len(inline) > 0

                self._add_finding(Finding(
                    scanner="iam",
                    check_id="IAM-005",
                    title="IAM user has inline policies attached",
                    description=f"User '{username}' has {len(inline)} inline policy(s) attached: {', '.join(inline) if inline else 'none'}.",
                    recommendation="Replace inline policies with managed policies for easier auditing and reuse.",
                    severity=Severity.HIGH,
                    resource=f"arn:aws:iam::*:user/{username}",
                    region=self.region,
                    cis_control="1.15",
                    passed=not has_inline,
                ))

    def _check_key_rotation(self):
        """CIS 1.14 - Access keys should be rotated every 90 days."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=90)
        paginator = self.client.get_paginator("list_users")

        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                keys = self.client.list_access_keys(UserName=username)["AccessKeyMetadata"]

                for key in keys:
                    if key["Status"] != "Active":
                        continue
                    created = key["CreateDate"]
                    is_old = created < cutoff

                    self._add_finding(Finding(
                        scanner="iam",
                        check_id="IAM-006",
                        title="IAM access key not rotated in 90 days",
                        description=f"Access key '{key['AccessKeyId']}' for user '{username}' was created on {created.strftime('%Y-%m-%d')} and has not been rotated.",
                        recommendation="Rotate access keys every 90 days. Delete unused keys.",
                        severity=Severity.MEDIUM,
                        resource=f"arn:aws:iam::*:user/{username}",
                        region=self.region,
                        cis_control="1.14",
                        passed=not is_old,
                    ))