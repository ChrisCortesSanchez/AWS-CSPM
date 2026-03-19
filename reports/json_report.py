"""
JSON report generator.
Outputs a structured JSON file with scan metadata, risk score, and findings.
"""
import json
from typing import List
from datetime import datetime
from utils.severity import Finding


def generate_json_report(
    findings: List[Finding],
    account_id: str,
    region: str,
    output_path: str,
    risk: dict = None,
):
    """Write a JSON report to output_path."""
    failures = [f for f in findings if not f.passed]
    passed = [f for f in findings if f.passed]

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in failures:
        severity_counts[f.severity.value] += 1

    report = {
        "meta": {
            "tool": "AWS CSPM Scanner",
            "account_id": account_id,
            "region": region,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "total_checks": len(findings),
            "total_findings": len(failures),
            "total_passed": len(passed),
            "severity_counts": severity_counts,
            "risk_score": risk or {},
        },
        "findings": sorted(
            [f.to_dict() for f in failures],
            key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(x["severity"])
        ),
    }

    with open(output_path, "w") as fh:
        json.dump(report, fh, indent=2)