from __future__ import annotations

import html
import ipaddress
import json
import secrets
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .models import Device, Finding, HomeGuardReport
from .reports import render_html

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _is_loopback_host(host: str) -> bool:
    """Best-effort loopback check for the dashboard bind address.

    The dashboard serves the report HTML, the parsed report JSON, and any
    sibling PDF/CSV files in the report directory. Binding it to anything
    other than the loopback interface exposes the user's full report —
    which can include device hostnames, MAC fragments, and CVE matches —
    to every other device on their LAN. We refuse non-loopback by default
    so a typo (or copy-paste of an example) cannot accidentally publish
    the report.
    """

    if not host:
        return True
    if host.lower() in LOOPBACK_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _report_from_dict(data: dict[str, Any]) -> HomeGuardReport:
    devices = [Device.from_dict(item) for item in data.get("devices", []) if isinstance(item, dict)]
    findings = []
    for item in data.get("findings", []):
        if not isinstance(item, dict):
            continue
        findings.append(
            Finding(
                finding_id=str(item.get("finding_id") or ""),
                rule_id=str(item.get("rule_id") or ""),
                title=str(item.get("title") or "Finding"),
                severity=str(item.get("severity") or "info"),
                confidence=float(item.get("confidence") or 0.0),
                risk_score=float(item.get("risk_score") or 0.0),
                priority=str(item.get("priority") or "P4"),
                category=str(item.get("category") or "general"),
                device_ip=str(item.get("device_ip") or ""),
                device_name=str(item.get("device_name") or ""),
                plain_english=str(item.get("plain_english") or ""),
                recommended_actions=list(item.get("recommended_actions") or []),
                evidence=dict(item.get("evidence") or {}),
                created_at=str(item.get("created_at") or ""),
            )
        )
    return HomeGuardReport(
        report_id=str(data.get("report_id") or "imported_report"),
        created_at=str(data.get("created_at") or ""),
        summary=str(data.get("summary") or "Imported HomeGuard report."),
        overall_risk=str(data.get("overall_risk") or "unknown"),
        overall_score=float(data.get("overall_score") or 0.0),
        devices=devices,
        findings=findings,
        next_steps=list(data.get("next_steps") or []),
        scan_metadata=dict(data.get("scan_metadata") or {}),
    )


def _append_dashboard_token(url: str, token: str) -> str:
    if not token:
        return url
    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    query.append(("token", token))
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(query), parts.fragment)
    )


def _add_token_to_report_links(html_text: str, token: str) -> str:
    if not token:
        return html_text
    replacements = {
        'href="report.pdf"': f'href="{html.escape(_append_dashboard_token("report.pdf", token))}"',
        'href="report.json"': f'href="{html.escape(_append_dashboard_token("report.json", token))}"',
        'href="devices.csv"': f'href="{html.escape(_append_dashboard_token("devices.csv", token))}"',
        'href="findings.csv"': f'href="{html.escape(_append_dashboard_token("findings.csv", token))}"',
    }
    for old, new in replacements.items():
        html_text = html_text.replace(old, new)
    return html_text


def serve_report(
    report_path: str | Path,
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    allow_lan: bool = False,
) -> None:
    bind_is_loopback = _is_loopback_host(host)
    if not bind_is_loopback:
        if not allow_lan:
            raise ValueError(
                f"Refusing to bind the HomeGuard dashboard to {host!r} because it is "
                "not a loopback address. Anyone on your network would be able to "
                "read the report. Pass --allow-lan if you really intend to expose "
                "it, or use 127.0.0.1 (the default)."
            )
        print(
            f"WARNING: HomeGuard dashboard is binding to {host} — anyone on your "
            "local network can read the report if they have the session URL. "
            "Stop the server (Ctrl+C) when done.",
            file=sys.stderr,
            flush=True,
        )
    path = Path(report_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    report = _report_from_dict(data)
    auth_token = secrets.token_urlsafe(32) if allow_lan and not bind_is_loopback else ""
    html_text = _add_token_to_report_links(render_html(report), auth_token)
    html_payload = html_text.encode("utf-8")
    json_payload = json.dumps(report.as_dict(), indent=2, sort_keys=True).encode("utf-8")
    report_dir = path.parent

    def _file_payload(filename: str) -> tuple[bytes, str] | None:
        targets = {
            "report.pdf": "application/pdf",
            "devices.csv": "text/csv; charset=utf-8",
            "findings.csv": "text/csv; charset=utf-8",
            "findings.json": "application/json; charset=utf-8",
        }
        if filename not in targets:
            return None
        target = (report_dir / filename).resolve()
        if not target.exists() or not target.is_file():
            return None
        return target.read_bytes(), targets[filename]

    def _request_has_valid_token(raw_path: str) -> bool:
        if not auth_token:
            return True
        query = urllib.parse.urlsplit(raw_path).query
        values = urllib.parse.parse_qs(query).get("token") or []
        return any(secrets.compare_digest(value, auth_token) for value in values)

    class Handler(BaseHTTPRequestHandler):
        def _send_security_headers(self) -> None:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")

        def _reject_unauthorized(self) -> bool:
            if _request_has_valid_token(self.path):
                return False
            body = b"Forbidden: invalid or missing HomeGuard dashboard token."
            self.send_response(403)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self._send_security_headers()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return True

        def do_GET(self) -> None:  # noqa: N802
            if self._reject_unauthorized():
                return
            clean_path = self.path.split("?", 1)[0].lstrip("/") or "report.html"
            if clean_path in {"api/report", "report.json"}:
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self._send_security_headers()
                self.send_header("Content-Length", str(len(json_payload)))
                self.end_headers()
                self.wfile.write(json_payload)
                return
            payload = _file_payload(clean_path)
            if payload is not None:
                body, content_type = payload
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Disposition", f'attachment; filename="{clean_path}"')
                self._send_security_headers()
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self._send_security_headers()
            self.send_header("Content-Length", str(len(html_payload)))
            self.end_headers()
            self.wfile.write(html_payload)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer((host, port), Handler)
    display_url = f"http://{host}:{port}"
    if auth_token:
        display_url = _append_dashboard_token(display_url, auth_token)
    print(f"HomeGuard dashboard: {display_url}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard.")
    finally:
        server.server_close()
