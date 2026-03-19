"""
AWS CSPM Tool - Main CLI Entrypoint
Usage: python main.py [OPTIONS]

Examples:
  python main.py
  python main.py --region us-west-2 --output both
  python main.py --scanners s3,iam --output json
  python main.py --profile my-profile --region eu-west-1
"""
import click
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))

import config
from utils.aws_client import init_session, get_account_id
from scanners.s3 import S3Scanner
from scanners.iam import IAMScanner
from scanners.ec2 import EC2Scanner
from scanners.cloudtrail import CloudTrailScanner
from reports.json_report import generate_json_report
from reports.html_report import generate_html_report


SCANNERS = {
    "s3": S3Scanner,
    "iam": IAMScanner,
    "ec2": EC2Scanner,
    "cloudtrail": CloudTrailScanner,
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def print_banner(account_id: str, region: str):
    print("\n" + "=" * 62)
    print("  AWS Cloud Security Posture Management (CSPM) Scanner")
    print("=" * 62)
    print(f"  Account : {account_id}")
    print(f"  Region  : {region}")
    print(f"  Time    : {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    print("=" * 62 + "\n")


def print_scanner_summary(name: str, summary: dict):
    parts = " | ".join(
        f"{sev}: {summary.get(sev, 0)}" for sev in SEVERITY_ORDER if sev != "INFO"
    )
    print(f"  [{name.upper()}]  {parts}")


def print_final_summary(all_findings: list, scanners_run: list, output_paths: list):
    failures = [f for f in all_findings if not f.passed]
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in failures:
        counts[f.severity.value] += 1

    print("\n" + "=" * 62)
    print(f"  Scan Complete: {len(failures)} findings across {len(scanners_run)} scanner(s)")
    print("=" * 62)
    print(f"  CRITICAL : {counts['CRITICAL']}")
    print(f"  HIGH     : {counts['HIGH']}")
    print(f"  MEDIUM   : {counts['MEDIUM']}")
    print(f"  LOW      : {counts['LOW']}")
    print("-" * 62)
    for path in output_paths:
        print(f"  Report   : {path}")
    print("=" * 62 + "\n")


@click.command()
@click.option(
    "--profile", default=None,
    help="AWS CLI profile name (uses default credentials if not set)"
)
@click.option(
    "--region", default="us-east-1", show_default=True,
    help="AWS region to scan"
)
@click.option(
    "--output", default="html",
    type=click.Choice(["json", "html", "both"], case_sensitive=False),
    show_default=True,
    help="Output report format"
)
@click.option(
    "--scanners", default="all",
    help="Comma-separated scanners to run: s3,iam,ec2,cloudtrail (default: all)"
)
def main(profile, region, output, scanners):
    """AWS Cloud Security Posture Management (CSPM) Scanner.

    Scans your AWS account for misconfigurations mapped to CIS Benchmark
    controls and generates a severity-scored report.
    """
    # Initialize AWS session
    init_session(profile=profile, region=region)

    try:
        account_id = get_account_id()
    except SystemExit as e:
        print(str(e))
        raise SystemExit(1)

    print_banner(account_id, region)

    # Resolve which scanners to run
    if scanners.lower() == "all":
        active = [k for k, v in config.ENABLED_SCANNERS.items() if v]
    else:
        active = [s.strip().lower() for s in scanners.split(",")]
        unknown = [s for s in active if s not in SCANNERS]
        if unknown:
            print(f"[!] Unknown scanner(s): {', '.join(unknown)}")
            print(f"    Valid options: {', '.join(SCANNERS.keys())}")
            raise SystemExit(1)

    # Run each scanner
    all_findings = []
    print("Running scanners...\n")

    for name in active:
        print(f"  Scanning {name.upper()}...")
        scanner = SCANNERS[name](region=region)

        try:
            findings = scanner.run()
        except Exception as e:
            print(f"  [!] {name.upper()} scanner error: {e}")
            continue

        all_findings.extend(findings)
        print_scanner_summary(name, scanner.summary())

    # Generate reports
    os.makedirs(config.OUTPUT_DIR, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    output_paths = []

    if output in ("json", "both"):
        path = os.path.join(config.OUTPUT_DIR, f"cspm_report_{timestamp}.json")
        generate_json_report(all_findings, account_id, region, path)
        output_paths.append(path)

    if output in ("html", "both"):
        path = os.path.join(config.OUTPUT_DIR, f"cspm_report_{timestamp}.html")
        generate_html_report(all_findings, account_id, region, path)
        output_paths.append(path)

    print_final_summary(all_findings, active, output_paths)


if __name__ == "__main__":
    main()