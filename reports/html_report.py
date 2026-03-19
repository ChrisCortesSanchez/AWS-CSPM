"""
HTML report generator.
Produces a self-contained, styled HTML dashboard from scanner findings.
"""
from typing import List
from datetime import datetime
from utils.severity import Finding

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SEVERITY_COLOR = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f97316",
    "MEDIUM":   "#eab308",
    "LOW":      "#22c55e",
    "INFO":     "#6b7280",
}

SEVERITY_BG = {
    "CRITICAL": "#fef2f2",
    "HIGH":     "#fff7ed",
    "MEDIUM":   "#fefce8",
    "LOW":      "#f0fdf4",
    "INFO":     "#f9fafb",
}

GRADE_COLOR = {
    "A": "#22c55e",
    "B": "#22c55e",
    "C": "#eab308",
    "D": "#f97316",
    "F": "#ef4444",
}


def generate_html_report(
    findings: List[Finding],
    account_id: str,
    region: str,
    output_path: str,
    risk: dict = None,
):
    risk = risk or {"score": 0, "grade": "F", "breakdown": {}}
    failures = sorted(
        [f for f in findings if not f.passed],
        key=lambda x: SEVERITY_ORDER.index(x.severity.value)
    )
    total_checks = len(findings)
    total_passed = len([f for f in findings if f.passed])

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in failures:
        counts[f.severity.value] += 1

    pass_pct = round((total_passed / total_checks * 100) if total_checks > 0 else 0)
    bar_color = "#22c55e" if pass_pct >= 80 else "#eab308" if pass_pct >= 50 else "#ef4444"

    grade = risk.get("grade", "F")
    score = risk.get("score", 0)
    grade_color = GRADE_COLOR.get(grade, "#ef4444")

    # Summary cards
    cards_html = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        color = SEVERITY_COLOR[sev]
        cards_html += f"""
        <div class="card">
            <div class="card-count" style="color:{color}">{counts[sev]}</div>
            <div class="card-label" style="color:{color}">{sev}</div>
        </div>"""

    # Findings table rows
    rows_html = ""
    if not failures:
        rows_html = """
        <tr>
            <td colspan="6" style="text-align:center;padding:2rem;color:#6b7280;">
                No findings — account looks clean!
            </td>
        </tr>"""
    else:
        for f in failures:
            color = SEVERITY_COLOR.get(f.severity.value, "#6b7280")
            bg = SEVERITY_BG.get(f.severity.value, "#ffffff")
            cis = f.cis_control or "—"
            rows_html += f"""
        <tr style="background:{bg}">
            <td><span class="badge" style="background:{color}">{f.severity.value}</span></td>
            <td><code>{f.check_id}</code></td>
            <td><strong>{f.title}</strong><br>
                <small style="color:#6b7280">{f.description}</small>
            </td>
            <td><code style="font-size:0.75rem">{f.resource}</code></td>
            <td style="text-align:center">{cis}</td>
            <td style="color:#374151;font-size:0.85rem">{f.recommendation}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AWS CSPM Report — {account_id}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #f1f5f9;
    color: #1e293b;
    padding: 2rem;
  }}
  .header {{
    background: #0f172a;
    color: white;
    border-radius: 12px;
    padding: 1.75rem 2rem;
    margin-bottom: 1.5rem;
  }}
  .header h1 {{ font-size: 1.4rem; font-weight: 700; margin-bottom: 0.5rem; }}
  .header .meta {{ display: flex; gap: 2rem; font-size: 0.85rem; color: #94a3b8; flex-wrap: wrap; }}
  .header .meta span strong {{ color: #e2e8f0; }}
  .top-row {{ display: grid; grid-template-columns: 1fr auto; gap: 1rem; margin-bottom: 1.5rem; align-items: start; }}
  .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; }}
  .score-card {{
    background: white;
    border-radius: 10px;
    padding: 1.25rem 2rem;
    box-shadow: 0 1px 3px rgba(0,0,0,.08);
    text-align: center;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-width: 130px;
  }}
  .score-number {{ font-size: 2.8rem; font-weight: 800; color: {grade_color}; line-height: 1; }}
  .score-grade {{ font-size: 1.1rem; font-weight: 700; color: {grade_color}; margin-top: 0.15rem; }}
  .score-label {{ font-size: 0.72rem; color: #94a3b8; margin-top: 0.25rem; text-transform: uppercase; letter-spacing: .05em; }}
  .card {{
    background: white;
    border-radius: 10px;
    padding: 1.25rem 1.5rem;
    box-shadow: 0 1px 3px rgba(0,0,0,.08);
    text-align: center;
  }}
  .card-count {{ font-size: 2.5rem; font-weight: 800; line-height: 1; }}
  .card-label {{ font-size: 0.75rem; font-weight: 600; letter-spacing: .05em; margin-top: 0.25rem; }}
  .progress-wrap {{
    background: white;
    border-radius: 10px;
    padding: 1.25rem 1.5rem;
    box-shadow: 0 1px 3px rgba(0,0,0,.08);
    margin-bottom: 1.5rem;
  }}
  .progress-label {{
    display: flex;
    justify-content: space-between;
    font-size: 0.85rem;
    color: #64748b;
    margin-bottom: 0.5rem;
  }}
  .progress-bar {{ background: #e2e8f0; border-radius: 9999px; height: 10px; overflow: hidden; }}
  .progress-fill {{
    height: 100%;
    border-radius: 9999px;
    background: {bar_color};
    width: {pass_pct}%;
  }}
  .table-wrap {{
    background: white;
    border-radius: 10px;
    box-shadow: 0 1px 3px rgba(0,0,0,.08);
    overflow: hidden;
  }}
  .table-title {{
    padding: 1rem 1.5rem;
    font-weight: 600;
    font-size: 0.95rem;
    border-bottom: 1px solid #e2e8f0;
    background: #f8fafc;
  }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{
    background: #0f172a;
    color: #94a3b8;
    padding: 0.75rem 1rem;
    text-align: left;
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: .05em;
    text-transform: uppercase;
  }}
  td {{ padding: 0.85rem 1rem; border-bottom: 1px solid #f1f5f9; font-size: 0.875rem; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  .badge {{
    display: inline-block;
    color: white;
    font-size: 0.7rem;
    font-weight: 700;
    padding: 0.2rem 0.55rem;
    border-radius: 9999px;
    letter-spacing: .04em;
  }}
  code {{
    background: #f1f5f9;
    padding: 0.1rem 0.35rem;
    border-radius: 4px;
    font-size: 0.8rem;
    color: #334155;
  }}
  .footer {{ text-align: center; color: #94a3b8; font-size: 0.8rem; margin-top: 1.5rem; }}
</style>
</head>
<body>

<div class="header">
  <h1>AWS Cloud Security Posture Management Report</h1>
  <div class="meta">
    <span>Account: <strong>{account_id}</strong></span>
    <span>Region: <strong>{region}</strong></span>
    <span>Generated: <strong>{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</strong></span>
    <span>Checks Run: <strong>{total_checks}</strong></span>
  </div>
</div>

<div class="top-row">
  <div class="summary">
    {cards_html}
  </div>
  <div class="score-card">
    <div class="score-number">{score}</div>
    <div class="score-grade">Grade: {grade}</div>
    <div class="score-label">Security Score</div>
  </div>
</div>

<div class="progress-wrap">
  <div class="progress-label">
    <span>Checks Passed</span>
    <span><strong>{total_passed}</strong> / {total_checks} ({pass_pct}%)</span>
  </div>
  <div class="progress-bar">
    <div class="progress-fill"></div>
  </div>
</div>

<div class="table-wrap">
  <div class="table-title">Findings ({len(failures)} total)</div>
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Check ID</th>
        <th>Title & Description</th>
        <th>Resource</th>
        <th>CIS Control</th>
        <th>Recommendation</th>
      </tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>
</div>

<div class="footer">
  Generated by AWS CSPM Scanner &nbsp;|&nbsp; CIS AWS Benchmark v1.5.0
</div>

</body>
</html>"""

    with open(output_path, "w") as fh:
        fh.write(html)