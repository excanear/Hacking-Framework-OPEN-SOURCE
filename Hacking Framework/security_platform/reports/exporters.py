"""
Report exporters — serialise report data to JSON and HTML formats.

Each exporter accepts a structured report_data dict and returns a string.
The exporters are intentionally stateless so they can be used independently
of the database layer (e.g. in tests or CLI one-shots).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict

from jinja2 import Environment, BaseLoader


# ─── JSON exporter ────────────────────────────────────────────────────────────

class JSONExporter:
    """Serialise report data to a formatted JSON string."""

    def export(self, report_data: Dict[str, Any]) -> str:
        """Return a pretty-printed JSON string of *report_data*."""
        return json.dumps(report_data, indent=2, default=str)


# ─── HTML exporter ────────────────────────────────────────────────────────────

_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{ title }}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', Arial, sans-serif; background: #0f1117; color: #e2e8f0; line-height: 1.6; }
    .container { max-width: 1100px; margin: 0 auto; padding: 2rem; }
    header { border-bottom: 2px solid #2d3748; padding-bottom: 1.5rem; margin-bottom: 2rem; }
    h1 { font-size: 1.8rem; color: #63b3ed; }
    h2 { font-size: 1.2rem; color: #90cdf4; margin: 1.5rem 0 0.75rem; border-left: 3px solid #4299e1; padding-left: 0.75rem; }
    h3 { font-size: 1rem; color: #a0aec0; margin: 1rem 0 0.5rem; }
    .meta { color: #718096; font-size: 0.9rem; margin-top: 0.3rem; }
    .risk-badge {
      display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px;
      font-weight: bold; font-size: 0.9rem; text-transform: uppercase; margin-left: 1rem;
    }
    .risk-critical { background: #742a2a; color: #fc8181; }
    .risk-high     { background: #7b341e; color: #fbd38d; }
    .risk-medium   { background: #5f370e; color: #f6e05e; }
    .risk-low      { background: #22543d; color: #9ae6b4; }
    .risk-minimal  { background: #1a365d; color: #90cdf4; }
    .score-bar-wrap { background: #2d3748; border-radius: 4px; height: 10px; margin: 0.5rem 0; }
    .score-bar { height: 10px; border-radius: 4px; transition: width 0.3s; }
    table { width: 100%; border-collapse: collapse; margin: 0.75rem 0; font-size: 0.9rem; }
    th { background: #2d3748; color: #90cdf4; text-align: left; padding: 0.6rem 0.8rem; }
    td { padding: 0.5rem 0.8rem; border-bottom: 1px solid #2d3748; }
    tr:hover { background: #1a202c; }
    .sev-critical { color: #fc8181; font-weight: bold; }
    .sev-high     { color: #fbd38d; font-weight: bold; }
    .sev-medium   { color: #f6e05e; }
    .sev-low      { color: #9ae6b4; }
    .sev-info     { color: #a0aec0; }
    .badge       { display: inline-block; padding: 0.1rem 0.5rem; border-radius: 4px; font-size: 0.8rem; }
    .badge-open  { background: #fc8181; color: #1a1a1a; }
    .badge-cloud { background: #4299e1; color: #1a1a1a; }
    .card { background: #1a202c; border: 1px solid #2d3748; border-radius: 6px; padding: 1rem 1.25rem; margin-bottom: 1rem; }
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
    .stat { text-align: center; }
    .stat-value { font-size: 2rem; font-weight: bold; color: #63b3ed; }
    .stat-label { font-size: 0.8rem; color: #718096; text-transform: uppercase; }
    ul { padding-left: 1.5rem; margin: 0.5rem 0; }
    li { margin: 0.25rem 0; }
    footer { margin-top: 3rem; border-top: 1px solid #2d3748; padding-top: 1rem; color: #4a5568; font-size: 0.8rem; text-align: center; }
    pre { background: #1a202c; padding: 0.75rem; border-radius: 4px; overflow-x: auto; font-size: 0.8rem; color: #a0aec0; }
  </style>
</head>
<body>
<div class="container">
  <header>
    <h1>
      {{ title }}
      {% if risk_level %}
      <span class="risk-badge risk-{{ risk_level }}">{{ risk_level }}</span>
      {% endif %}
    </h1>
    <div class="meta">
      Target: <strong>{{ summary.target }}</strong> &nbsp;|&nbsp;
      Generated: {{ generated_at }} &nbsp;|&nbsp;
      Platform: Security Research Platform v{{ version }}
    </div>
    {% if risk_score is not none %}
    <div style="margin-top: 1rem;">
      <span style="font-size: 1.3rem; font-weight: bold; color: #63b3ed;">
        Risk Score: {{ "%.1f"|format(risk_score) }} / 10
      </span>
      <div class="score-bar-wrap" style="max-width: 300px; margin-top: 0.5rem;">
        <div class="score-bar" style="
          width: {{ (risk_score * 10)|int }}%;
          background: {% if risk_score >= 9 %}#fc8181{% elif risk_score >= 7 %}#fbd38d{% elif risk_score >= 4 %}#f6e05e{% else %}#9ae6b4{% endif %};
        "></div>
      </div>
    </div>
    {% endif %}
  </header>

  <!-- Statistics Overview -->
  <div class="card">
    <div class="grid-2">
      <div class="stat"><div class="stat-value">{{ summary.total_assets }}</div><div class="stat-label">Assets Found</div></div>
      <div class="stat"><div class="stat-value">{{ summary.total_services }}</div><div class="stat-label">Open Services</div></div>
    </div>
    <div class="grid-2" style="margin-top: 1rem;">
      <div class="stat"><div class="stat-value">{{ summary.total_vulnerabilities }}</div><div class="stat-label">Vulnerabilities</div></div>
      <div class="stat"><div class="stat-value">{{ summary.modules_run }}</div><div class="stat-label">Modules Run</div></div>
    </div>
  </div>

  <!-- Vulnerabilities -->
  {% if vulnerabilities %}
  <h2>Vulnerabilities Found</h2>
  <table>
    <thead>
      <tr><th>CVE ID</th><th>Title</th><th>Severity</th><th>CVSS</th><th>Product</th></tr>
    </thead>
    <tbody>
    {% for v in vulnerabilities %}
      <tr>
        <td>{% if v.cve_id %}<a href="https://nvd.nist.gov/vuln/detail/{{ v.cve_id }}" style="color:#63b3ed" target="_blank">{{ v.cve_id }}</a>{% else %}—{% endif %}</td>
        <td>{{ v.title }}</td>
        <td><span class="sev-{{ v.severity }}">{{ v.severity|upper }}</span></td>
        <td>{{ v.cvss_score if v.cvss_score else '—' }}</td>
        <td>{{ v.affected_software or '—' }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% endif %}

  <!-- Open Services -->
  {% if services %}
  <h2>Detected Services</h2>
  <table>
    <thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Version</th></tr></thead>
    <tbody>
    {% for s in services %}
      <tr>
        <td><span class="badge badge-open">{{ s.port }}</span></td>
        <td>{{ s.protocol }}</td>
        <td>{{ s.service_name or '—' }}</td>
        <td>{{ s.product or '—' }}</td>
        <td>{{ s.version or '—' }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% endif %}

  <!-- Discovered Assets -->
  {% if assets %}
  <h2>Discovered Assets ({{ assets|length }})</h2>
  <table>
    <thead><tr><th>Asset</th><th>Type</th><th>IP Address</th><th>Alive</th></tr></thead>
    <tbody>
    {% for a in assets %}
      <tr>
        <td>{{ a.value }}</td>
        <td>{% if 'cloud' in a.type %}<span class="badge badge-cloud">{{ a.type }}</span>{% else %}{{ a.type }}{% endif %}</td>
        <td>{{ a.ip_address or '—' }}</td>
        <td>{{ '✓' if a.is_alive else '—' }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% endif %}

  <!-- Risk Breakdown -->
  {% if risk_breakdown %}
  <h2>Risk Score Breakdown</h2>
  <div class="card">
    {% for factor in risk_breakdown.factors %}
    <div style="margin-bottom: 0.4rem;">
      <span style="color: #718096; font-size: 0.85rem;">{{ factor.name }}</span>
      <span style="color: #e2e8f0; float: right;">{{ "%.1f"|format(factor.delta) }}</span><br>
      <small style="color: #4a5568;">{{ factor.description }}</small>
    </div>
    {% endfor %}
  </div>
  {% endif %}

  <!-- Recommendations -->
  {% if recommendations %}
  <h2>Recommendations</h2>
  <div class="card">
    <ul>
    {% for rec in recommendations %}
      <li>{{ rec }}</li>
    {% endfor %}
    </ul>
  </div>
  {% endif %}

  <!-- OSINT Observations -->
  {% if osint_observations %}
  <h2>OSINT Observations</h2>
  <div class="card">
    <ul>
    {% for obs in osint_observations %}
      <li>{{ obs }}</li>
    {% endfor %}
    </ul>
  </div>
  {% endif %}

  <footer>
    Security Research Platform &mdash; For authorised testing only &mdash;
    Generated {{ generated_at }}
  </footer>
</div>
</body>
</html>
"""


class HTMLExporter:
    """Render report data into a self-contained HTML page."""

    def __init__(self) -> None:
        self._env = Environment(loader=BaseLoader(), autoescape=True)
        self._template = self._env.from_string(_HTML_TEMPLATE)

    def export(self, report_data: Dict[str, Any]) -> str:
        """Return a rendered HTML string from *report_data*."""
        return self._template.render(**report_data)


# ─── Factory ──────────────────────────────────────────────────────────────────

def get_exporter(fmt: str):
    """Return the appropriate exporter for *fmt* ('json' or 'html')."""
    if fmt == "html":
        return HTMLExporter()
    return JSONExporter()
