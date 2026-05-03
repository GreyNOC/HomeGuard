from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .models import Device, Finding, HomeGuardReport
from .reports import render_html


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


def serve_report(report_path: str | Path, host: str = "127.0.0.1", port: int = 8765) -> None:
    path = Path(report_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    report = _report_from_dict(data)
    html_payload = render_html(report).encode("utf-8")
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

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            clean_path = self.path.split("?", 1)[0].lstrip("/") or "report.html"
            if clean_path in {"api/report", "report.json"}:
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
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
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html_payload)))
            self.end_headers()
            self.wfile.write(html_payload)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer((host, port), Handler)
    print(f"HomeGuard dashboard: http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard.")
    finally:
        server.server_close()
