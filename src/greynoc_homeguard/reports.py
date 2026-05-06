from __future__ import annotations

import csv
import hashlib
import html
import json
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .models import HomeGuardReport
from .privacy import assert_share_safe, scrub_report

BRAND_NAVY = colors.HexColor("#0B1220")
BRAND_SLATE = colors.HexColor("#1E293B")
BRAND_BLUE = colors.HexColor("#2563EB")
BRAND_DEEP_BLUE = colors.HexColor("#1E3A8A")
BRAND_CYAN = colors.HexColor("#22D3EE")
BRAND_GREEN = colors.HexColor("#16A34A")
BRAND_AMBER = colors.HexColor("#D97706")
BRAND_RED = colors.HexColor("#DC2626")
BRAND_BG = colors.HexColor("#F8FAFC")
BRAND_LINE = colors.HexColor("#CBD5E1")
BRAND_TEXT = colors.HexColor("#172033")


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------
def _severity_class(severity: str) -> str:
    clean = str(severity or "info").lower()
    return clean if clean in {"critical", "high", "medium", "low", "info"} else "info"


def _safe_text(value: Any) -> str:
    return str(value or "-").replace("\n", " ").strip() or "-"


def _scan_metadata(report: HomeGuardReport, key: str, default: Any) -> Any:
    metadata = report.scan_metadata if isinstance(report.scan_metadata, dict) else {}
    return metadata.get(key, default)


def _protection_cards(report: HomeGuardReport) -> dict[str, dict[str, str]]:
    status = _scan_metadata(report, "protection_status", {})
    if isinstance(status, dict) and status:
        return {
            "network": status.get("network") or {"value": "Protected", "detail": ""},
            "device_trust": status.get("device_trust") or {"value": "Trusted", "detail": ""},
            "updates": status.get("updates") or {"value": "Current", "detail": ""},
        }
    # Fallback derived view if status was not computed (legacy reports)
    return {
        "network": {"value": "Protected" if report.overall_risk in {"clean", "low"} else "Review", "detail": report.summary},
        "device_trust": {"value": "Trusted", "detail": ""},
        "updates": {"value": "Current", "detail": ""},
    }


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


# ----------------------------------------------------------------------
# Markdown
# ----------------------------------------------------------------------
def render_markdown(report: HomeGuardReport) -> str:
    cards = _protection_cards(report)
    family = _scan_metadata(report, "family_summary", {})
    quarantined = _scan_metadata(report, "quarantined_devices", [])
    def_status = _scan_metadata(report, "definition_status", {}) or {}
    engine_status = _scan_metadata(report, "detection_engine", {}) or {}

    lines: list[str] = []
    lines.append("# HomeGuard Report")
    lines.append("")
    lines.append(f"Report ID: `{report.report_id}`")
    lines.append(f"Created: `{report.created_at}`")
    lines.append(f"Overall risk: `{report.overall_risk}` ({report.overall_score})")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(report.summary)
    lines.append("")
    lines.append("## Protection Status")
    lines.append("")
    lines.append(f"- **Network Protection:** {cards['network'].get('value')} - {cards['network'].get('detail', '')}")
    lines.append(f"- **Device Trust:** {cards['device_trust'].get('value')} - {cards['device_trust'].get('detail', '')}")
    lines.append(f"- **Security Updates:** {cards['updates'].get('value')} - {cards['updates'].get('detail', '')}")
    lines.append("")
    if isinstance(def_status, dict) and def_status:
        lines.append("## Security Definitions")
        lines.append("")
        lines.append(f"- Version: `{def_status.get('definitions_version', 'unknown')}`")
        lines.append(f"- Last updated: `{def_status.get('last_updated') or def_status.get('updated_at', 'unknown')}`")
        lines.append(f"- Update status: `{def_status.get('update_status', 'unknown')}`")
        lines.append(f"- CISA KEV records: `{def_status.get('kev_count', 0)}`")
        lines.append(f"- Recent NVD CVEs: `{def_status.get('recent_cve_count', 0)}`")
        feed_versions = def_status.get("feed_versions") or {}
        if isinstance(feed_versions, dict):
            for source, version in feed_versions.items():
                lines.append(f"- Feed `{source}`: {version or 'n/a'}")
        notice = def_status.get("notice")
        if notice:
            lines.append(f"- Notice: {notice}")
        lines.append("")

    lines.append("## Devices")
    lines.append("")
    lines.append("| IP | Name | Device ID | Vendor | Status | Open ports | Source |")
    lines.append("|---|---|---|---|---|---|---|")
    for device in report.devices:
        lines.append(
            "| "
            + " | ".join(
                [
                    device.ip,
                    device.hostname or "-",
                    device.mac_address or "-",
                    device.vendor or "-",
                    device.status,
                    ", ".join(str(port) for port in device.open_ports) or "-",
                    device.source,
                ]
            )
            + " |"
        )
    lines.append("")

    if isinstance(quarantined, list) and quarantined:
        lines.append("## Quarantined / Blocked Devices")
        lines.append("")
        for row in quarantined:
            lines.append(
                f"- {row.get('name', '-')} ({row.get('ip', '-')}) - owner: {row.get('owner', 'unknown')}, type: {row.get('device_type', 'unknown')}"
                + (" [active in scan]" if row.get("active_in_scan") else " [not on network right now]")
            )
        lines.append("")

    if isinstance(family, dict) and (family.get("by_owner") or family.get("by_type")):
        lines.append("## Family Device Summary")
        lines.append("")
        owners = family.get("by_owner") or {}
        types = family.get("by_type") or {}
        if owners:
            lines.append("By owner:")
            for owner, count in sorted(owners.items()):
                lines.append(f"  - {owner}: {count}")
        if types:
            lines.append("")
            lines.append("By device type:")
            for kind, count in sorted(types.items()):
                lines.append(f"  - {kind}: {count}")
        lines.append("")

    kev_findings = [finding for finding in report.findings if finding.category == "known_exploited_vulnerability"]
    if kev_findings:
        lines.append("## CVE / KEV Patch Priority")
        lines.append("")
        for finding in kev_findings:
            lines.append(
                f"- {finding.title} (priority {finding.priority}) - {finding.device_name} ({finding.device_ip})"
            )
        lines.append("")

    lines.append("## Risk Findings")
    lines.append("")
    if not report.findings:
        lines.append("No findings.")
    for finding in report.findings:
        lines.append(f"### {finding.title}")
        lines.append("")
        lines.append(f"- Severity: `{finding.severity}`")
        lines.append(f"- Priority: `{finding.priority}`")
        lines.append(f"- Risk score: `{finding.risk_score}`")
        lines.append(f"- Device: `{finding.device_name}` / `{finding.device_ip}`")
        lines.append(f"- Explanation: {finding.plain_english}")
        lines.append("- Recommended actions:")
        for action in finding.recommended_actions:
            lines.append(f"  - {action}")
        lines.append("")

    lines.append("## Recommended Actions")
    lines.append("")
    for step in report.next_steps:
        lines.append(f"- {step}")
    lines.append("")

    lines.append("## Detection Engine")
    lines.append("")
    if isinstance(engine_status, dict):
        lines.append(f"- Engine: `{engine_status.get('engine', 'HomeGuard Detection Engine')}`")
        lines.append(f"- Engine version: `{engine_status.get('engine_version', 'unknown')}`")
        lines.append(f"- Rules loaded: `{engine_status.get('rules_loaded', 0)}`")
        lines.append(f"- Definitions version: `{engine_status.get('definitions_version', 'unknown')}`")
    lines.append("")
    return "\n".join(lines)


# ----------------------------------------------------------------------
# HTML
# ----------------------------------------------------------------------
def render_html(report: HomeGuardReport) -> str:
    data = report.as_dict()
    json_payload = html.escape(json.dumps(data, sort_keys=True))
    cards = _protection_cards(report)
    def_status = _scan_metadata(report, "definition_status", {}) or {}
    engine_status = _scan_metadata(report, "detection_engine", {}) or {}
    family = _scan_metadata(report, "family_summary", {}) or {}
    quarantined = _scan_metadata(report, "quarantined_devices", []) or []

    finding_cards: list[str] = []
    for finding in report.findings:
        actions = "".join(f"<li>{html.escape(action)}</li>" for action in finding.recommended_actions)
        finding_cards.append(
            f"""
            <section class="finding-card severity-{html.escape(_severity_class(finding.severity))}">
              <div class="card-head">
                <h3>{html.escape(finding.title)}</h3>
                <span>{html.escape(finding.priority)} / {html.escape(finding.severity.upper())}</span>
              </div>
              <p>{html.escape(finding.plain_english)}</p>
              <p class="meta">Device: {html.escape(finding.device_name)} ({html.escape(finding.device_ip)}) | Risk: {finding.risk_score} | Confidence: {finding.confidence}</p>
              <ul>{actions}</ul>
            </section>
            """
        )
    findings_html = "".join(finding_cards) if finding_cards else "<p>No findings. Keep HomeGuard updated and scan again later.</p>"

    device_rows: list[str] = []
    for device in report.devices:
        device_rows.append(
            "<tr>"
            f"<td>{html.escape(device.ip)}</td>"
            f"<td>{html.escape(device.hostname or '-')}</td>"
            f"<td>{html.escape(device.mac_address or '-')}</td>"
            f"<td>{html.escape(device.vendor or '-')}</td>"
            f"<td>{html.escape(device.status)}</td>"
            f"<td>{html.escape(', '.join(str(p) for p in device.open_ports) or '-')}</td>"
            "</tr>"
        )

    quarantined_section = ""
    if quarantined:
        rows = "".join(
            f"<tr><td>{html.escape(str(item.get('name', '-')))}</td>"
            f"<td>{html.escape(str(item.get('ip', '-')))}</td>"
            f"<td>{html.escape(str(item.get('mac_address', '-')))}</td>"
            f"<td>{html.escape(str(item.get('owner', 'unknown')))}</td>"
            f"<td>{html.escape(str(item.get('device_type', 'unknown')))}</td>"
            f"<td>{'Yes' if item.get('active_in_scan') else 'No'}</td></tr>"
            for item in quarantined
        )
        quarantined_section = (
            "<section class=\"panel\">"
            "<h2>Quarantined / Blocked Devices</h2>"
            "<table><thead><tr><th>Name</th><th>IP</th><th>Device ID</th><th>Owner</th><th>Type</th><th>Active in scan</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
            "<p class=\"meta\">Quarantine flags devices in HomeGuard reports. To actually block traffic, "
            "remove the device from your router or change the WiFi password.</p>"
            "</section>"
        )

    family_section = ""
    if isinstance(family, dict) and (family.get("by_owner") or family.get("by_type")):
        owner_items = "".join(
            f"<li>{html.escape(str(owner))}: {count}</li>"
            for owner, count in sorted((family.get("by_owner") or {}).items())
        )
        type_items = "".join(
            f"<li>{html.escape(str(kind))}: {count}</li>"
            for kind, count in sorted((family.get("by_type") or {}).items())
        )
        family_section = (
            "<section class=\"panel\">"
            "<h2>Family Device Summary</h2>"
            "<div class=\"family-grid\">"
            f"<div><h4>By owner</h4><ul>{owner_items or '<li>None labeled</li>'}</ul></div>"
            f"<div><h4>By device type</h4><ul>{type_items or '<li>None labeled</li>'}</ul></div>"
            "</div>"
            "</section>"
        )

    kev_findings = [finding for finding in report.findings if finding.category == "known_exploited_vulnerability"]
    kev_section = ""
    if kev_findings:
        rows = "".join(
            f"<tr><td>{html.escape(f.title)}</td>"
            f"<td>{html.escape(f.priority)}</td>"
            f"<td>{html.escape(f.severity.upper())}</td>"
            f"<td>{html.escape(f.device_name)} ({html.escape(f.device_ip)})</td></tr>"
            for f in kev_findings
        )
        kev_section = (
            "<section class=\"panel\">"
            "<h2>CVE / KEV Patch Priority</h2>"
            "<table><thead><tr><th>Title</th><th>Priority</th><th>Severity</th><th>Device</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
            "</section>"
        )

    feed_versions = def_status.get("feed_versions") if isinstance(def_status, dict) else {}
    feed_html = ""
    if isinstance(feed_versions, dict) and feed_versions:
        feed_html = "<ul>" + "".join(
            f"<li><b>{html.escape(str(name))}:</b> {html.escape(str(version) or 'n/a')}</li>"
            for name, version in feed_versions.items()
        ) + "</ul>"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HomeGuard Report</title>
<style>
:root {{
  font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  color: #F4F7FB;
  background: #05070A;
  --app-bg: #05070A;
  --surface: #0B0F16;
  --surface-raised: #101722;
  --surface-muted: #070B10;
  --border: #223047;
  --border-strong: #2E4568;
  --text: #F4F7FB;
  --muted: #A8B3C5;
  --subtle: #7F8CA3;
  --blue: #0B3D91;
  --blue-hover: #123A7A;
}}
body {{ margin: 0; background:#05070A; color:#F4F7FB; }}
header {{ background: #05070A; color: #F4F7FB; padding: 34px 34px 78px; border-bottom:1px solid #223047; }}
.brand {{ display:flex; align-items:center; gap:14px; margin-bottom:20px; }}
.brand-mark {{ width:46px; height:46px; border-radius:10px; border:1px solid #2E4568; display:grid; place-items:center; font-weight:900; background:#142947; color:#F4F7FB; }}
.brand-title {{ letter-spacing:.08em; text-transform:uppercase; font-weight:800; font-size:13px; opacity:.88; }}
h1 {{ margin: 0 0 10px; font-size: 38px; color: #F4F7FB; }}
header p {{ max-width: 900px; line-height:1.55; color:#A8B3C5; }}
main {{ max-width: 1120px; margin: -58px auto 0; padding: 24px; }}
.actions {{ display:flex; flex-wrap:wrap; gap:10px; margin:0 0 18px; }}
.actions .action {{ border:1px solid #3B82F6; text-decoration:none; cursor:pointer; background:#174EA6; color:#fff; border-radius:6px; padding:10px 14px; font-weight:800; font-size:14px; }}
.actions .action:hover {{ background:#1D4ED8; border-color:#60A5FA; }}
.actions .action.secondary {{ background:#111827; color:#fff; border-color:#2E4568; }}
.summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }}
.secondary-metrics {{ margin-top: 16px; }}
.metric {{ background: #0B0F16; border-radius: 10px; padding: 20px; box-shadow: 0 18px 42px rgba(0, 0, 0, .34); border:1px solid #223047; }}
.metric b {{ display: block; font-size: 26px; margin-bottom: 4px; color:#F4F7FB; }}
.metric small {{ color:#A8B3C5; font-size: 13px; }}
.metric.protected b {{ color:#16A34A; }}
.metric.review b {{ color:#D97706; }}
.metric.action b {{ color:#DC2626; }}
.panel, .finding-card {{ background: #0B0F16; border-radius: 10px; padding: 20px; box-shadow: 0 18px 42px rgba(0, 0, 0, .34); margin: 16px 0; border:1px solid #223047; }}
.finding-card {{ border-left: 7px solid #64748b; }}
.card-head {{ display: flex; gap: 16px; align-items: start; justify-content: space-between; }}
.card-head h3 {{ margin: 0; color:#F4F7FB; }}
.card-head span {{ background: #142947; border:1px solid #2E4568; color:#F4F7FB; border-radius: 8px; padding: 7px 11px; font-weight: 800; white-space: nowrap; }}
.severity-critical, .severity-high {{ border-left-color: #dc2626; }}
.severity-medium {{ border-left-color: #d97706; }}
.severity-low {{ border-left-color: #0b3d91; }}
.severity-info {{ border-left-color: #64748b; }}
.meta, p, li, td {{ color: #A8B3C5; }}
.meta {{ font-size: 14px; }}
table {{ width: 100%; border-collapse: collapse; background: #0B0F16; border-radius: 10px; overflow: hidden; box-shadow: 0 18px 42px rgba(0, 0, 0, .34); border:1px solid #223047; }}
th, td {{ text-align: left; padding: 13px; border-bottom: 1px solid #223047; vertical-align:top; }}
th {{ background: #101722; color:#F4F7FB; }}
td {{ color:#A8B3C5; }}
.search {{ margin: 20px 0; }}
.search input {{ width: 100%; border: 1px solid #223047; border-radius: 8px; padding: 13px 15px; font-size: 16px; box-sizing:border-box; background:#070B10; color:#F4F7FB; }}
.family-grid {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap:14px; }}
.family-grid h4, h2 {{ margin: 0 0 6px; color:#F4F7FB; }}
footer {{ color: #7F8CA3; padding: 24px; text-align: center; }}
details summary {{ color:#F4F7FB; }}
details pre {{ white-space: pre-wrap; overflow:auto; max-height: 460px; background:#070B10; color:#D8E6FF; padding:18px; border:1px solid #223047; border-radius:8px; }}
@media print {{ .actions, .search {{ display:none; }} main {{ margin:0; }} header {{ padding-bottom:34px; }} }}
</style>
</head>
<body>
<header>
  <div class="brand"><div class="brand-mark">GN</div><div><div class="brand-title">HomeGuard</div><div>Home Network Risk Review Report</div></div></div>
  <h1>Home Security Report</h1>
  <p>{html.escape(report.summary)}</p>
</header>
<main>
  <nav class="actions" aria-label="Report downloads">
    <button class="action" onclick="downloadHtmlReport()">Download HTML</button>
    <a class="action" href="report.pdf" download>Download PDF</a>
    <a class="action secondary" href="report.json" download>Download JSON</a>
    <a class="action secondary" href="devices.csv" download>Download Devices CSV</a>
    <a class="action secondary" href="findings.csv" download>Download Findings CSV</a>
    <button class="action secondary" onclick="window.print()">Print / Save as PDF</button>
  </nav>

  <section class="summary">
    <div class="metric {_card_class(cards['network']['value'])}"><small>Network Protection</small><b>{html.escape(str(cards['network']['value']))}</b><small>{html.escape(str(cards['network'].get('detail', '')))}</small></div>
    <div class="metric {_card_class(cards['device_trust']['value'])}"><small>Device Trust</small><b>{html.escape(str(cards['device_trust']['value']))}</b><small>{html.escape(str(cards['device_trust'].get('detail', '')))}</small></div>
    <div class="metric {_card_class(cards['updates']['value'])}"><small>Security Updates</small><b>{html.escape(str(cards['updates']['value']))}</b><small>{html.escape(str(cards['updates'].get('detail', '')))}</small></div>
  </section>

  <section class="summary secondary-metrics">
    <div class="metric"><small>DEVICES</small><b>{len(report.devices)}</b></div>
    <div class="metric"><small>FINDINGS</small><b>{len(report.findings)}</b></div>
    <div class="metric"><small>OVERALL RISK</small><b>{html.escape(report.overall_risk.upper())}</b></div>
    <div class="metric"><small>SCORE</small><b>{report.overall_score}</b></div>
  </section>

  <section class="panel">
    <div class="card-head"><h3>Security definitions</h3><span>{html.escape(str(def_status.get('definitions_version', 'unknown')))}</span></div>
    <p class="meta">Updated: {html.escape(str(def_status.get('last_updated') or def_status.get('updated_at', 'unknown')))} | Status: {html.escape(str(def_status.get('update_status', 'unknown')))} | CISA KEV: {html.escape(str(def_status.get('kev_count', 0)))} | Recent NVD CVEs: {html.escape(str(def_status.get('recent_cve_count', 0)))} | Records: {html.escape(str(def_status.get('record_count', 0)))}</p>
    {feed_html}
  </section>

  <section class="panel">
    <div class="card-head"><h3>Detection engine</h3><span>{html.escape(str(engine_status.get('engine_version', 'unknown')))}</span></div>
    <p class="meta">{html.escape(str(engine_status.get('engine', 'HomeGuard Detection Engine')))} | Rules loaded: {html.escape(str(engine_status.get('rules_loaded', 0)))}</p>
  </section>

  {kev_section}
  {family_section}
  {quarantined_section}

  <section class="search"><input id="filter" placeholder="Filter findings or devices..." oninput="filterCards()"></section>

  <h2>Risk Findings</h2>
  <div id="findings">{findings_html}</div>

  <h2>Device Inventory</h2>
  <table id="devices">
    <thead><tr><th>IP</th><th>Name</th><th>Device ID</th><th>Vendor</th><th>Status</th><th>Open ports</th></tr></thead>
    <tbody>{''.join(device_rows)}</tbody>
  </table>

  <section class="panel">
    <h2>Recommended Actions</h2>
    <ol>{''.join(f'<li>{html.escape(step)}</li>' for step in report.next_steps)}</ol>
  </section>

  <details><summary>Raw report JSON</summary><pre>{json_payload}</pre></details>
</main>
<footer>Report {html.escape(report.report_id)} generated {html.escape(report.created_at)}. HomeGuard findings are indicators, not proof of compromise.</footer>
<script>
function filterCards() {{
  const term = document.getElementById('filter').value.toLowerCase();
  document.querySelectorAll('.finding-card, #devices tbody tr').forEach(el => {{
    el.style.display = el.textContent.toLowerCase().includes(term) ? '' : 'none';
  }});
}}
function downloadHtmlReport() {{
  const htmlText = '<!doctype html>\\n' + document.documentElement.outerHTML;
  const blob = new Blob([htmlText], {{type: 'text/html;charset=utf-8'}});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'HomeGuard-{html.escape(report.report_id)}.html';
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}}
</script>
</body>
</html>"""


def _card_class(value: Any) -> str:
    text = str(value or "").lower()
    if "protected" in text or "current" in text or "trusted" in text:
        return "protected"
    if "review" in text or "available" in text or "new" in text:
        return "review"
    if "action" in text or "failed" in text or "risky" in text or "never" in text:
        return "action"
    return ""


# ----------------------------------------------------------------------
# PDF
# ----------------------------------------------------------------------
def _risk_color(severity: str) -> colors.Color:
    clean = _severity_class(severity)
    if clean in {"critical", "high"}:
        return BRAND_RED
    if clean == "medium":
        return BRAND_AMBER
    if clean == "low":
        return BRAND_BLUE
    return colors.HexColor("#64748B")


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "brand": ParagraphStyle(
            "brand",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=11,
            textColor=colors.white,
            alignment=TA_LEFT,
            uppercase=True,
        ),
        "title": ParagraphStyle(
            "title",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=25,
            leading=30,
            textColor=colors.white,
            spaceAfter=8,
        ),
        "subtitle": ParagraphStyle(
            "subtitle",
            parent=base["Normal"],
            fontSize=10.5,
            leading=15,
            textColor=colors.HexColor("#E2E8F0"),
        ),
        "h2": ParagraphStyle(
            "h2",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=15,
            leading=19,
            textColor=BRAND_NAVY,
            spaceBefore=14,
            spaceAfter=6,
        ),
        "h3": ParagraphStyle(
            "h3",
            parent=base["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=11.5,
            leading=15,
            textColor=BRAND_NAVY,
            spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "body",
            parent=base["BodyText"],
            fontSize=9.4,
            leading=13,
            textColor=BRAND_TEXT,
        ),
        "small": ParagraphStyle(
            "small",
            parent=base["BodyText"],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#475569"),
        ),
        "white": ParagraphStyle(
            "white",
            parent=base["BodyText"],
            fontSize=9,
            leading=12,
            textColor=colors.white,
        ),
        "card_label": ParagraphStyle(
            "card_label",
            parent=base["Normal"],
            fontSize=7.5,
            leading=10,
            textColor=colors.white,
            alignment=TA_CENTER,
        ),
        "card_value": ParagraphStyle(
            "card_value",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=15,
            leading=18,
            textColor=colors.white,
            alignment=TA_CENTER,
        ),
        "card_detail": ParagraphStyle(
            "card_detail",
            parent=base["Normal"],
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#DBEAFE"),
            alignment=TA_CENTER,
        ),
        "metric_label": ParagraphStyle(
            "metric_label",
            parent=base["Normal"],
            fontSize=7.5,
            leading=9,
            textColor=colors.HexColor("#64748B"),
            alignment=TA_CENTER,
        ),
        "metric_value": ParagraphStyle(
            "metric_value",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=21,
            textColor=BRAND_NAVY,
            alignment=TA_CENTER,
        ),
    }


def _header_footer(canvas, doc) -> None:  # type: ignore[no-untyped-def]
    canvas.saveState()
    width, height = LETTER
    canvas.setFillColor(BRAND_DEEP_BLUE)
    canvas.rect(0, height - 0.42 * inch, width, 0.42 * inch, fill=1, stroke=0)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 9)
    canvas.drawString(0.55 * inch, height - 0.26 * inch, "HomeGuard")
    canvas.setFont("Helvetica", 7)
    canvas.drawRightString(width - 0.55 * inch, 0.34 * inch, f"Page {doc.page}")
    canvas.setFillColor(colors.HexColor("#64748B"))
    canvas.drawString(
        0.55 * inch,
        0.34 * inch,
        "Home network risk review. Findings are indicators, not proof of compromise.",
    )
    canvas.restoreState()


def _metric_box(label: str, value: str, styles: dict[str, ParagraphStyle]) -> list[Paragraph]:
    return [Paragraph(value, styles["metric_value"]), Paragraph(label, styles["metric_label"])]


def _status_card(label: str, value: str, detail: str, styles: dict[str, ParagraphStyle]) -> list[Paragraph]:
    return [
        Paragraph(label.upper(), styles["card_label"]),
        Paragraph(html.escape(value), styles["card_value"]),
        Paragraph(html.escape(detail or ""), styles["card_detail"]),
    ]


def write_pdf(path: Path, report: HomeGuardReport) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    styles = _styles()
    doc = SimpleDocTemplate(
        str(path),
        pagesize=LETTER,
        rightMargin=0.55 * inch,
        leftMargin=0.55 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.62 * inch,
        title="HomeGuard Report",
        author="GreyNOC",
        subject="Home network protection report",
    )
    story: list[Any] = []

    # ---- Cover ----
    hero = Table(
        [
            [
                [
                    Paragraph("HOMEGUARD", styles["brand"]),
                    Paragraph("Home Security Report", styles["title"]),
                    Paragraph(html.escape(report.summary), styles["subtitle"]),
                ]
            ]
        ],
        colWidths=[7.4 * inch],
    )
    hero.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), BRAND_DEEP_BLUE),
                ("BOX", (0, 0), (-1, -1), 0, BRAND_DEEP_BLUE),
                ("LEFTPADDING", (0, 0), (-1, -1), 22),
                ("RIGHTPADDING", (0, 0), (-1, -1), 22),
                ("TOPPADDING", (0, 0), (-1, -1), 20),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 22),
            ]
        )
    )
    story.append(hero)
    story.append(Spacer(1, 8))

    # ---- Protection Status Cards ----
    cards = _protection_cards(report)
    status_table = Table(
        [
            [
                _status_card("Network Protection", str(cards["network"]["value"]), str(cards["network"].get("detail", "")), styles),
                _status_card("Device Trust", str(cards["device_trust"]["value"]), str(cards["device_trust"].get("detail", "")), styles),
                _status_card("Security Updates", str(cards["updates"]["value"]), str(cards["updates"].get("detail", "")), styles),
            ]
        ],
        colWidths=[2.46 * inch, 2.46 * inch, 2.46 * inch],
    )
    status_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), BRAND_BLUE),
                ("BACKGROUND", (1, 0), (1, 0), BRAND_DEEP_BLUE),
                ("BACKGROUND", (2, 0), (2, 0), BRAND_NAVY),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                ("TOPPADDING", (0, 0), (-1, -1), 14),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
            ]
        )
    )
    story.append(status_table)
    story.append(Spacer(1, 12))

    # ---- Executive summary ----
    story.append(Paragraph("Executive Summary", styles["h2"]))
    story.append(Paragraph(html.escape(report.summary), styles["body"]))

    # ---- Numeric metrics row ----
    metrics = Table(
        [
            [
                _metric_box("DEVICES", str(len(report.devices)), styles),
                _metric_box("FINDINGS", str(len(report.findings)), styles),
                _metric_box("RISK", report.overall_risk.upper(), styles),
                _metric_box("SCORE", str(report.overall_score), styles),
            ]
        ],
        colWidths=[1.85 * inch, 1.85 * inch, 1.85 * inch, 1.85 * inch],
    )
    metrics.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.75, BRAND_LINE),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, BRAND_LINE),
                ("TOPPADDING", (0, 0), (-1, -1), 12),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
            ]
        )
    )
    story.append(Spacer(1, 8))
    story.append(metrics)

    # ---- Definition metadata ----
    def_status = _scan_metadata(report, "definition_status", {}) or {}
    if isinstance(def_status, dict) and def_status:
        story.append(Paragraph("Security Definitions", styles["h2"]))
        defs = Table(
            [
                ["Version", _safe_text(def_status.get("definitions_version")), "Updated", _safe_text(def_status.get("last_updated") or def_status.get("updated_at"))],
                ["Status", _safe_text(def_status.get("update_status")), "Records", _safe_text(def_status.get("record_count"))],
                ["CISA KEV", _safe_text(def_status.get("kev_count")), "Recent CVEs", _safe_text(def_status.get("recent_cve_count"))],
            ],
            colWidths=[1.05 * inch, 2.3 * inch, 1.05 * inch, 3.0 * inch],
        )
        defs.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), BRAND_BG),
                    ("BOX", (0, 0), (-1, -1), 0.6, BRAND_LINE),
                    ("INNERGRID", (0, 0), (-1, -1), 0.4, BRAND_LINE),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                    ("PADDING", (0, 0), (-1, -1), 7),
                ]
            )
        )
        story.append(defs)

    # ---- Recommended actions ----
    story.append(Paragraph("Recommended Actions", styles["h2"]))
    if report.next_steps:
        for index, step in enumerate(report.next_steps[:8], start=1):
            story.append(Paragraph(f"{index}. {html.escape(step)}", styles["body"]))
    else:
        story.append(Paragraph("No immediate actions required.", styles["body"]))

    # ---- KEV / patch priority ----
    kev_findings = [f for f in report.findings if f.category == "known_exploited_vulnerability"]
    if kev_findings:
        story.append(Paragraph("CVE / KEV Patch Priority", styles["h2"]))
        rows: list[list[Any]] = [["Title", "Priority", "Severity", "Device"]]
        for finding in kev_findings[:30]:
            rows.append(
                [
                    Paragraph(html.escape(finding.title), styles["small"]),
                    finding.priority,
                    finding.severity.upper(),
                    Paragraph(html.escape(f"{finding.device_name} ({finding.device_ip})"), styles["small"]),
                ]
            )
        kev_table = Table(rows, repeatRows=1, colWidths=[3.2 * inch, 0.8 * inch, 0.9 * inch, 2.5 * inch])
        kev_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), BRAND_NAVY),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 8.5),
                    ("GRID", (0, 0), (-1, -1), 0.35, BRAND_LINE),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BRAND_BG]),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("PADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.append(kev_table)

    # ---- Family summary ----
    family = _scan_metadata(report, "family_summary", {}) or {}
    if isinstance(family, dict) and (family.get("by_owner") or family.get("by_type")):
        story.append(Paragraph("Family Device Summary", styles["h2"]))
        owners = family.get("by_owner") or {}
        types = family.get("by_type") or {}
        rows = [["By owner", "Count", "By device type", "Count"]]
        owner_items = sorted(owners.items())
        type_items = sorted(types.items())
        max_rows = max(len(owner_items), len(type_items))
        for i in range(max_rows):
            row = ["", "", "", ""]
            if i < len(owner_items):
                row[0] = owner_items[i][0]
                row[1] = str(owner_items[i][1])
            if i < len(type_items):
                row[2] = type_items[i][0]
                row[3] = str(type_items[i][1])
            rows.append(row)
        family_table = Table(rows, repeatRows=1, colWidths=[2.0 * inch, 0.9 * inch, 2.0 * inch, 0.9 * inch])
        family_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), BRAND_DEEP_BLUE),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.35, BRAND_LINE),
                    ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                    ("PADDING", (0, 0), (-1, -1), 6),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BRAND_BG]),
                ]
            )
        )
        story.append(family_table)

    # ---- Quarantined devices ----
    quarantined = _scan_metadata(report, "quarantined_devices", []) or []
    if isinstance(quarantined, list) and quarantined:
        story.append(Paragraph("Quarantined / Blocked Devices", styles["h2"]))
        rows = [["Name", "IP", "Owner", "Type", "Active"]]
        for item in quarantined[:30]:
            rows.append(
                [
                    Paragraph(html.escape(str(item.get("name", "-"))), styles["small"]),
                    str(item.get("ip", "-")),
                    str(item.get("owner", "unknown")),
                    str(item.get("device_type", "unknown")),
                    "Yes" if item.get("active_in_scan") else "No",
                ]
            )
        q_table = Table(rows, repeatRows=1, colWidths=[2.4 * inch, 1.3 * inch, 1.0 * inch, 1.0 * inch, 0.7 * inch])
        q_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), BRAND_RED),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.35, BRAND_LINE),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BRAND_BG]),
                    ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                    ("PADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.append(q_table)

    # ---- Findings ----
    story.append(PageBreak())
    story.append(Paragraph("Risk Findings", styles["h2"]))
    if not report.findings:
        story.append(Paragraph("No findings were generated for this scan.", styles["body"]))
    for finding in report.findings[:25]:
        badge_color = _risk_color(finding.severity)
        finding_table = Table(
            [
                [
                    Paragraph(html.escape(finding.title), styles["h3"]),
                    Paragraph(
                        f"<b>{html.escape(finding.priority)} / {html.escape(finding.severity.upper())}</b><br/>Risk {finding.risk_score}",
                        styles["small"],
                    ),
                ],
                [Paragraph(html.escape(finding.plain_english), styles["body"]), ""],
                [
                    Paragraph("Device", styles["small"]),
                    Paragraph(html.escape(f"{finding.device_name} ({finding.device_ip})"), styles["small"]),
                ],
                [
                    Paragraph("Recommended actions", styles["small"]),
                    Paragraph(html.escape("; ".join(finding.recommended_actions[:4])), styles["small"]),
                ],
            ],
            colWidths=[5.55 * inch, 1.65 * inch],
        )
        finding_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                    ("BOX", (0, 0), (-1, -1), 0.7, BRAND_LINE),
                    ("LINEBEFORE", (0, 0), (0, -1), 6, badge_color),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("SPAN", (0, 1), (1, 1)),
                    ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#F1F5F9")),
                    ("PADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        story.append(KeepTogether([finding_table, Spacer(1, 6)]))
    if len(report.findings) > 25:
        story.append(
            Paragraph(
                f"Additional findings omitted from PDF preview: {len(report.findings) - 25}. "
                "See report.html or report.json for all findings.",
                styles["small"],
            )
        )

    # ---- Devices ----
    story.append(PageBreak())
    story.append(Paragraph("Device Inventory", styles["h2"]))
    rows = [["IP", "Name", "Vendor", "Status", "Open ports"]]
    for device in report.devices[:80]:
        rows.append(
            [
                Paragraph(html.escape(device.ip), styles["small"]),
                Paragraph(html.escape(device.hostname or "-"), styles["small"]),
                Paragraph(html.escape(device.vendor or "-"), styles["small"]),
                Paragraph(html.escape(device.status), styles["small"]),
                Paragraph(html.escape(", ".join(str(port) for port in device.open_ports) or "-"), styles["small"]),
            ]
        )
    device_table = Table(rows, repeatRows=1, colWidths=[1.05 * inch, 2.0 * inch, 1.3 * inch, 1.0 * inch, 2.0 * inch])
    device_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), BRAND_SLATE),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 8.5),
                ("GRID", (0, 0), (-1, -1), 0.35, BRAND_LINE),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BRAND_BG]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(device_table)
    if len(report.devices) > 80:
        story.append(Spacer(1, 8))
        story.append(
            Paragraph(
                f"Additional devices omitted from PDF preview: {len(report.devices) - 80}. See report.json for all devices.",
                styles["small"],
            )
        )

    # ---- Detection engine metadata ----
    engine_status = _scan_metadata(report, "detection_engine", {}) or {}
    if isinstance(engine_status, dict) and engine_status:
        story.append(Paragraph("Detection Engine", styles["h2"]))
        rows = [
            ["Engine", _safe_text(engine_status.get("engine"))],
            ["Engine version", _safe_text(engine_status.get("engine_version"))],
            ["Rules loaded", _safe_text(engine_status.get("rules_loaded"))],
            ["Definitions", _safe_text(engine_status.get("definitions_version"))],
        ]
        eng_table = Table(rows, colWidths=[1.6 * inch, 5.6 * inch])
        eng_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), BRAND_BG),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.35, BRAND_LINE),
                    ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                    ("PADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.append(eng_table)

    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Report ID: {html.escape(report.report_id)}", styles["small"]))
    story.append(Paragraph(f"Generated: {html.escape(report.created_at)}", styles["small"]))
    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)


def write_csv(path: Path, report: HomeGuardReport) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["ip", "hostname", "device_id", "vendor", "status", "open_ports", "source"],
        )
        writer.writeheader()
        for device in report.devices:
            writer.writerow(
                {
                    "ip": device.ip,
                    "hostname": device.hostname,
                    "device_id": device.mac_address,
                    "vendor": device.vendor,
                    "status": device.status,
                    "open_ports": ",".join(str(port) for port in device.open_ports),
                    "source": device.source,
                }
            )


def write_findings_csv(path: Path, report: HomeGuardReport) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "finding_id",
                "rule_id",
                "title",
                "severity",
                "priority",
                "risk_score",
                "category",
                "device_ip",
                "device_name",
                "plain_english",
                "recommended_actions",
            ],
        )
        writer.writeheader()
        for finding in report.findings:
            writer.writerow(
                {
                    "finding_id": finding.finding_id,
                    "rule_id": finding.rule_id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "priority": finding.priority,
                    "risk_score": finding.risk_score,
                    "category": finding.category,
                    "device_ip": finding.device_ip,
                    "device_name": finding.device_name,
                    "plain_english": finding.plain_english,
                    "recommended_actions": " | ".join(finding.recommended_actions),
                }
            )


def write_manifest(directory: Path) -> None:
    rows: list[str] = []
    for path in sorted(directory.glob("*")):
        if path.name == "manifest.sha256" or not path.is_file():
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        rows.append(f"{digest}  {path.name}")
    (directory / "manifest.sha256").write_text("\n".join(rows) + "\n", encoding="utf-8")


def export_report(report: HomeGuardReport, out_dir: str | Path) -> dict[str, Path]:
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    public_report = scrub_report(report)
    paths = {
        "json": directory / "report.json",
        "findings": directory / "findings.json",
        "findings_csv": directory / "findings.csv",
        "devices": directory / "devices.csv",
        "markdown": directory / "report.md",
        "html": directory / "report.html",
        "pdf": directory / "report.pdf",
        "manifest": directory / "manifest.sha256",
    }
    write_json(paths["json"], public_report.as_dict())
    write_json(paths["findings"], [finding.as_dict() for finding in public_report.findings])
    paths["markdown"].write_text(render_markdown(public_report), encoding="utf-8")
    paths["html"].write_text(render_html(public_report), encoding="utf-8")
    write_pdf(paths["pdf"], public_report)
    write_csv(paths["devices"], public_report)
    write_findings_csv(paths["findings_csv"], public_report)
    write_manifest(directory)
    for key in ("json", "findings", "markdown", "html", "devices", "findings_csv"):
        assert_share_safe(paths[key].read_text(encoding="utf-8", errors="ignore"))
    return paths
