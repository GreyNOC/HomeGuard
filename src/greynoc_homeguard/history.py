from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import HomeGuardReport, utcnow
from .paths import history_file

DEFAULT_RETENTION = 30


@dataclass
class HistoryEntry:
    report_id: str
    created_at: str
    device_count: int
    finding_count: int
    highest_severity: str
    overall_risk: str
    overall_score: float
    report_dir: str
    html_path: str
    pdf_path: str
    json_path: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "created_at": self.created_at,
            "device_count": self.device_count,
            "finding_count": self.finding_count,
            "highest_severity": self.highest_severity,
            "overall_risk": self.overall_risk,
            "overall_score": self.overall_score,
            "report_dir": self.report_dir,
            "html_path": self.html_path,
            "pdf_path": self.pdf_path,
            "json_path": self.json_path,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "HistoryEntry":
        return cls(
            report_id=str(payload.get("report_id") or ""),
            created_at=str(payload.get("created_at") or ""),
            device_count=int(payload.get("device_count") or 0),
            finding_count=int(payload.get("finding_count") or 0),
            highest_severity=str(payload.get("highest_severity") or "info"),
            overall_risk=str(payload.get("overall_risk") or "clean"),
            overall_score=float(payload.get("overall_score") or 0.0),
            report_dir=str(payload.get("report_dir") or ""),
            html_path=str(payload.get("html_path") or ""),
            pdf_path=str(payload.get("pdf_path") or ""),
            json_path=str(payload.get("json_path") or ""),
        )


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _highest_severity(report: HomeGuardReport) -> str:
    best = "info"
    best_rank = -1
    for finding in report.findings:
        rank = SEVERITY_ORDER.get(finding.severity, -1)
        if rank > best_rank:
            best_rank = rank
            best = finding.severity
    return best


class ProtectionHistory:
    def __init__(self, path: str | Path | None = None, retention: int = DEFAULT_RETENTION):
        self.path = Path(path) if path else history_file()
        self.retention = max(1, int(retention))
        self.data: dict[str, Any] = {
            "schema_version": "1.0",
            "retention": self.retention,
            "entries": [],
        }

    def load(self) -> "ProtectionHistory":
        if self.path.exists():
            try:
                loaded = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    self.data = loaded
                    self.data.setdefault("schema_version", "1.0")
                    self.data.setdefault("entries", [])
                    self.data.setdefault("retention", self.retention)
                    self.retention = int(self.data.get("retention") or self.retention)
            except (OSError, json.JSONDecodeError):
                pass
        return self

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(self.data, indent=2, sort_keys=True), encoding="utf-8"
        )

    def entries(self) -> list[HistoryEntry]:
        rows = self.data.get("entries") or []
        return [HistoryEntry.from_dict(row) for row in rows if isinstance(row, dict)]

    def latest(self) -> HistoryEntry | None:
        entries = self.entries()
        return entries[0] if entries else None

    def add(self, report: HomeGuardReport, paths: dict[str, Path]) -> HistoryEntry:
        report_dir = paths.get("json").parent if paths.get("json") else None
        entry = HistoryEntry(
            report_id=report.report_id,
            created_at=report.created_at or utcnow(),
            device_count=len(report.devices),
            finding_count=len(report.findings),
            highest_severity=_highest_severity(report),
            overall_risk=report.overall_risk,
            overall_score=report.overall_score,
            report_dir=str(report_dir) if report_dir else "",
            html_path=str(paths.get("html") or ""),
            pdf_path=str(paths.get("pdf") or ""),
            json_path=str(paths.get("json") or ""),
        )
        rows = self.data.setdefault("entries", [])
        rows.insert(0, entry.as_dict())
        if len(rows) > self.retention:
            del rows[self.retention:]
        return entry

    def set_retention(self, retention: int) -> None:
        self.retention = max(1, int(retention))
        self.data["retention"] = self.retention
        rows = self.data.setdefault("entries", [])
        if len(rows) > self.retention:
            del rows[self.retention:]
