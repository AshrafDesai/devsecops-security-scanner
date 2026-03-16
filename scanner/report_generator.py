import json
import os
from datetime import datetime
from jinja2 import Template

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Scan Report — {{ target }}</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --c-bg: #0f1117; --c-surface: #1a1d27; --c-border: #2a2d3a;
    --c-text: #e2e4ed; --c-muted: #8b8fa8;
    --c-critical: #ff4757; --c-high: #ff6b35; --c-medium: #ffd32a;
    --c-low: #2ed573; --c-info: #5352ed; --c-pass: #2ed573; --c-fail: #ff4757;
  }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--c-bg); color: var(--c-text); line-height: 1.6; padding: 32px; min-height: 100vh; }
  .header { max-width: 1200px; margin: 0 auto 32px; border-bottom: 1px solid var(--c-border); padding-bottom: 24px; }
  .header h1 { font-size: 1.8rem; font-weight: 700; letter-spacing: -0.5px; }
  .header h1 span { color: var(--c-muted); font-weight: 400; }
  .meta { color: var(--c-muted); font-size: 0.875rem; margin-top: 6px; }
  .container { max-width: 1200px; margin: 0 auto; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 32px; }
  .card { background: var(--c-surface); border: 1px solid var(--c-border); border-radius: 12px; padding: 20px; }
  .card.status-pass { border-color: var(--c-pass); }
  .card.status-fail { border-color: var(--c-fail); }
  .card-label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px; color: var(--c-muted); margin-bottom: 8px; }
  .card-value { font-size: 2rem; font-weight: 700; }
  .card-value.CRITICAL { color: var(--c-critical); }
  .card-value.HIGH     { color: var(--c-high); }
  .card-value.MEDIUM   { color: var(--c-medium); }
  .card-value.LOW      { color: var(--c-low); }
  .card-value.PASS     { color: var(--c-pass); }
  .card-value.FAIL     { color: var(--c-fail); }
  .card-value.score    { color: var(--c-text); }
  .section { margin-bottom: 40px; }
  .section h2 { font-size: 1.1rem; font-weight: 600; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid var(--c-border); }
  .alert-box { background: #1f1220; border: 1px solid var(--c-critical); border-radius: 8px; padding: 16px; margin-bottom: 16px; }
  .alert-box p { color: #ffacb3; font-size: 0.9rem; }
  .alert-box p + p { margin-top: 6px; }
  table { width: 100%; border-collapse: collapse; background: var(--c-surface); border-radius: 12px; overflow: hidden; border: 1px solid var(--c-border); }
  thead th { background: #12151f; padding: 14px 16px; text-align: left; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.8px; color: var(--c-muted); font-weight: 500; }
  tbody td { padding: 14px 16px; border-bottom: 1px solid var(--c-border); font-size: 0.875rem; vertical-align: top; }
  tbody tr:last-child td { border-bottom: none; }
  tbody tr:hover { background: rgba(255,255,255,0.02); }
  .badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 600; letter-spacing: 0.5px; }
  .badge.CRITICAL { background: rgba(255,71,87,0.15);  color: var(--c-critical); border: 1px solid rgba(255,71,87,0.3); }
  .badge.HIGH     { background: rgba(255,107,53,0.15); color: var(--c-high);     border: 1px solid rgba(255,107,53,0.3); }
  .badge.MEDIUM   { background: rgba(255,211,42,0.12); color: var(--c-medium);   border: 1px solid rgba(255,211,42,0.25); }
  .badge.LOW      { background: rgba(46,213,115,0.1);  color: var(--c-low);      border: 1px solid rgba(46,213,115,0.2); }
  .badge.INFO     { background: rgba(83,82,237,0.15);  color: #a29bfe;           border: 1px solid rgba(83,82,237,0.3); }
  .rec { font-size: 0.8rem; color: var(--c-muted); margin-top: 4px; }
  .type-label { font-family: 'Consolas', 'Monaco', monospace; font-size: 0.8rem; color: #a29bfe; background: rgba(83,82,237,0.1); padding: 2px 6px; border-radius: 4px; }
  .score-bar { height: 8px; background: var(--c-border); border-radius: 4px; overflow: hidden; margin-top: 8px; }
  .score-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }
  .score-low { background: var(--c-low); }
  .score-medium { background: var(--c-medium); }
  .score-high { background: var(--c-high); }
  .score-critical { background: var(--c-critical); }
  .filter-bar { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }
  .filter-btn { padding: 6px 14px; border-radius: 20px; border: 1px solid var(--c-border); background: var(--c-surface);
    color: var(--c-muted); font-size: 0.8rem; cursor: pointer; transition: all 0.15s; }
  .filter-btn:hover, .filter-btn.active { border-color: #5352ed; color: #a29bfe; background: rgba(83,82,237,0.1); }
  .owasp-tag { font-size: 0.72rem; color: var(--c-muted); background: rgba(255,255,255,0.05); padding: 2px 6px; border-radius: 3px; display: inline-block; margin-top: 4px; }
  footer { max-width: 1200px; margin: 40px auto 0; padding-top: 20px; border-top: 1px solid var(--c-border); font-size: 0.8rem; color: var(--c-muted); }
</style>
</head>
<body>
<div class="header">
  <h1>DevSecOps Security Scan Report <span>// {{ target }}</span></h1>
  <div class="meta">Scan completed at {{ timestamp }} UTC &nbsp;·&nbsp; Scanner v1.0.0 &nbsp;·&nbsp; {{ total }} findings</div>
</div>
<div class="container">
  <div class="grid">
    <div class="card status-{{ result_lower }}">
      <div class="card-label">Pipeline Status</div>
      <div class="card-value {{ result }}">{{ result }}</div>
    </div>
    <div class="card">
      <div class="card-label">Risk Score</div>
      <div class="card-value score">{{ risk_score }}/100</div>
      <div class="score-bar"><div class="score-fill score-{{ risk_class }}" style="width:{{ risk_score }}%"></div></div>
    </div>
    <div class="card"><div class="card-label">Critical</div><div class="card-value CRITICAL">{{ counts.CRITICAL }}</div></div>
    <div class="card"><div class="card-label">High</div><div class="card-value HIGH">{{ counts.HIGH }}</div></div>
    <div class="card"><div class="card-label">Medium</div><div class="card-value MEDIUM">{{ counts.MEDIUM }}</div></div>
    <div class="card"><div class="card-label">Low</div><div class="card-value LOW">{{ counts.LOW }}</div></div>
  </div>

  {% if failure_reasons %}
  <div class="section">
    <h2>Pipeline Failure Reasons</h2>
    {% for reason in failure_reasons %}
    <div class="alert-box"><p>{{ reason }}</p></div>
    {% endfor %}
  </div>
  {% endif %}

  {% if top_recommendations %}
  <div class="section">
    <h2>Top Recommendations</h2>
    <table>
      <thead><tr><th>#</th><th>Recommendation</th></tr></thead>
      <tbody>
        {% for rec in top_recommendations %}
        <tr><td style="width:40px;color:var(--c-muted)">{{ loop.index }}</td><td>{{ rec }}</td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  <div class="section">
    <h2>All Findings</h2>
    <div class="filter-bar">
      <button class="filter-btn active" onclick="filterTable('ALL')">All ({{ total }})</button>
      <button class="filter-btn" onclick="filterTable('CRITICAL')">Critical ({{ counts.CRITICAL }})</button>
      <button class="filter-btn" onclick="filterTable('HIGH')">High ({{ counts.HIGH }})</button>
      <button class="filter-btn" onclick="filterTable('MEDIUM')">Medium ({{ counts.MEDIUM }})</button>
      <button class="filter-btn" onclick="filterTable('LOW')">Low ({{ counts.LOW }})</button>
    </div>
    <table id="findings-table">
      <thead>
        <tr>
          <th style="width:100px">Severity</th>
          <th style="width:180px">Type</th>
          <th>Detail</th>
          <th style="width:200px">OWASP</th>
        </tr>
      </thead>
      <tbody>
        {% for f in findings %}
        <tr data-severity="{{ f.severity }}">
          <td><span class="badge {{ f.severity }}">{{ f.severity }}</span></td>
          <td><span class="type-label">{{ f.type }}</span></td>
          <td>
            {{ f.detail }}
            {% if f.recommendation %}<div class="rec">&#8594; {{ f.recommendation }}</div>{% endif %}
          </td>
          <td>{% if f.owasp_category %}<span class="owasp-tag">{{ f.owasp_category }}</span>{% else %}-{% endif %}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>
<footer>Generated by DevSecOps Security Scanner &nbsp;·&nbsp; {{ timestamp }} UTC</footer>
<script>
function filterTable(sev) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('#findings-table tbody tr').forEach(row => {
    row.style.display = (sev === 'ALL' || row.dataset.severity === sev) ? '' : 'none';
  });
}
</script>
</body>
</html>"""


def generate_reports(target: str, findings: list, evaluation: dict, out_dir: str = "reports") -> tuple:
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    enriched_findings = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        enriched_findings.extend(evaluation.get("findings_by_severity", {}).get(sev, []))

    report_data = {
        "meta": {
            "scanner": "DevSecOps Security Scanner",
            "version": "1.0.0",
            "target": target,
            "timestamp": ts,
            "generated_at": datetime.utcnow().isoformat() + "Z",
        },
        "evaluation": {
            k: v for k, v in evaluation.items() if k != "findings_by_severity"
        },
        "findings": enriched_findings,
        "summary": {
            "total": evaluation.get("total_findings", len(findings)),
            "severity_counts": evaluation.get("severity_counts", {}),
            "risk_score": evaluation.get("risk_score", 0),
            "risk_rating": evaluation.get("risk_rating", "UNKNOWN"),
            "passed": evaluation.get("passed", False),
        },
    }

    json_path = os.path.join(out_dir, f"scan_report_{ts}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, default=str)

    latest_json = os.path.join(out_dir, "scan_report_latest.json")
    with open(latest_json, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, default=str)

    counts = evaluation.get("severity_counts", {})
    risk_score = evaluation.get("risk_score", 0)
    result = "PASS" if evaluation.get("passed") else "FAIL"

    if risk_score >= 50:
        risk_class = "critical"
    elif risk_score >= 25:
        risk_class = "high"
    elif risk_score >= 10:
        risk_class = "medium"
    else:
        risk_class = "low"

    tmpl = Template(HTML_TEMPLATE)
    html = tmpl.render(
        target=target,
        timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        result=result,
        result_lower=result.lower(),
        total=evaluation.get("total_findings", len(findings)),
        counts=counts,
        risk_score=risk_score,
        risk_class=risk_class,
        failure_reasons=evaluation.get("failure_reasons", []),
        top_recommendations=evaluation.get("top_recommendations", []),
        findings=enriched_findings,
    )

    html_path = os.path.join(out_dir, f"scan_report_{ts}.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    latest_html = os.path.join(out_dir, "scan_report_latest.html")
    with open(latest_html, "w", encoding="utf-8") as f:
        f.write(html)

    return json_path, html_path