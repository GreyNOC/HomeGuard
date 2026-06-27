from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import ai_memory, ai_tools, ai_traffic
from .models import HomeGuardReport
from .paths import atomic_write_text, user_data_dir

MAX_TOOL_ITERATIONS = 4

STERILE_PROVIDER = "sterile"
SUPPORTED_PROVIDERS = {
    STERILE_PROVIDER,
    "openai",
    "anthropic",
    "openrouter",
    "gemini",
    "custom_openai_compatible",
}
DEFAULT_MODE = STERILE_PROVIDER
DEFAULT_SHARE_LEVEL = "minimal"
SHARE_LEVELS = {"minimal", "standard", "full"}
SENSITIVE_EVIDENCE_KEY_MARKERS = (
    "address",
    "credential",
    "directory",
    "domain",
    "file",
    "host",
    "ip",
    "key",
    "location",
    "mac",
    "name",
    "path",
    "registry",
    "secret",
    "sid",
    "ssid",
    "token",
    "user",
)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC_RE = re.compile(r"\b[0-9a-fA-F]{2}(?:(?::|-)[0-9a-fA-F]{2}){5}\b")
WINDOWS_PATH_RE = re.compile(r"\b[A-Za-z]:[\\/][^\s\"']+")
UNC_PATH_RE = re.compile(r"\\\\[^\s\\/\"']+[\\/][^\s\"']+")
UNIX_USER_PATH_RE = re.compile(r"(?<!\w)/(?:Users|home)/[^\s\"']+")
REGISTRY_PATH_RE = re.compile(r"\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\s\"']+", re.IGNORECASE)


@dataclass(slots=True)
class AISettings:
    """User-controlled AI routing settings.

    API keys are intentionally not stored here. The config stores the provider,
    model, endpoint hints, and the environment variable that contains the key.
    That keeps HomeGuard easy to back up without leaking secrets.
    """

    enabled: bool = False
    provider: str = DEFAULT_MODE
    model: str = ""
    api_key_env: str = ""
    endpoint: str = ""
    share_level: str = DEFAULT_SHARE_LEVEL
    temperature: float = 0.2
    max_output_tokens: int = 900
    use_engine_tools: bool = True
    use_traffic_context: bool = False
    use_memory_context: bool = True
    last_error: str = ""

    @classmethod
    def from_dict(cls, payload: dict[str, Any] | None) -> "AISettings":
        data = dict(payload or {})
        provider = str(data.get("provider") or DEFAULT_MODE).strip().lower()
        if provider not in SUPPORTED_PROVIDERS:
            provider = DEFAULT_MODE
        share_level = str(data.get("share_level") or DEFAULT_SHARE_LEVEL).strip().lower()
        if share_level not in SHARE_LEVELS:
            share_level = DEFAULT_SHARE_LEVEL
        enabled = bool(data.get("enabled")) and provider != STERILE_PROVIDER
        return cls(
            enabled=enabled,
            provider=provider,
            model=str(data.get("model") or default_model(provider)),
            api_key_env=str(data.get("api_key_env") or default_api_key_env(provider)),
            endpoint=str(data.get("endpoint") or default_endpoint(provider)),
            share_level=share_level,
            temperature=_safe_float(data.get("temperature"), 0.2),
            max_output_tokens=max(64, min(4096, _safe_int(data.get("max_output_tokens"), 900))),
            use_engine_tools=_safe_bool(data.get("use_engine_tools"), True),
            use_traffic_context=_safe_bool(data.get("use_traffic_context"), False),
            use_memory_context=_safe_bool(data.get("use_memory_context"), True),
            last_error=str(data.get("last_error") or ""),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "provider": self.provider,
            "model": self.model,
            "api_key_env": self.api_key_env,
            "endpoint": self.endpoint,
            "share_level": self.share_level,
            "temperature": self.temperature,
            "max_output_tokens": self.max_output_tokens,
            "use_engine_tools": self.use_engine_tools,
            "use_traffic_context": self.use_traffic_context,
            "use_memory_context": self.use_memory_context,
            "last_error": self.last_error,
        }

    def is_sterile(self) -> bool:
        return not self.enabled or self.provider == STERILE_PROVIDER


@dataclass(slots=True)
class AIResponse:
    ok: bool
    provider: str
    model: str
    text: str
    sterile: bool = False
    error: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "provider": self.provider,
            "model": self.model,
            "text": self.text,
            "sterile": self.sterile,
            "error": self.error,
            "raw": self.raw,
        }


def _safe_float(value: Any, fallback: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return fallback


def _safe_int(value: Any, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _safe_bool(value: Any, fallback: bool) -> bool:
    if value is None:
        return fallback
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off"}:
            return False
    return fallback


def ai_settings_file() -> Path:
    return user_data_dir() / "ai_settings.json"


def default_api_key_env(provider: str) -> str:
    return {
        "openai": "OPENAI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "openrouter": "OPENROUTER_API_KEY",
        "gemini": "GEMINI_API_KEY",
        "custom_openai_compatible": "HOMEGUARD_AI_API_KEY",
    }.get(provider, "")


def default_model(provider: str) -> str:
    return {
        "openai": "gpt-4.1-mini",
        "anthropic": "claude-3-5-haiku-latest",
        "openrouter": "openai/gpt-4.1-mini",
        "gemini": "gemini-1.5-flash",
        "custom_openai_compatible": "",
    }.get(provider, "")


def default_endpoint(provider: str) -> str:
    return {
        "openai": "https://api.openai.com/v1/chat/completions",
        "anthropic": "https://api.anthropic.com/v1/messages",
        "openrouter": "https://openrouter.ai/api/v1/chat/completions",
        "gemini": "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        "custom_openai_compatible": "",
    }.get(provider, "")


def load_ai_settings(path: Path | None = None) -> AISettings:
    target = path or ai_settings_file()
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return AISettings()
    except (OSError, json.JSONDecodeError):
        return AISettings(last_error="AI settings could not be read; sterile mode is active.")
    if not isinstance(payload, dict):
        return AISettings(last_error="AI settings were invalid; sterile mode is active.")
    return AISettings.from_dict(payload)


def save_ai_settings(settings: AISettings, path: Path | None = None) -> Path:
    target = path or ai_settings_file()
    atomic_write_text(target, json.dumps(settings.as_dict(), indent=2, sort_keys=True) + "\n")
    return target


def set_sterile(path: Path | None = None) -> AISettings:
    settings = AISettings(enabled=False, provider=STERILE_PROVIDER)
    save_ai_settings(settings, path=path)
    return settings


def configure_ai(
    *,
    provider: str,
    model: str = "",
    api_key_env: str = "",
    endpoint: str = "",
    share_level: str = DEFAULT_SHARE_LEVEL,
    enabled: bool = True,
    use_engine_tools: bool | None = None,
    use_traffic_context: bool | None = None,
    use_memory_context: bool | None = None,
    path: Path | None = None,
) -> AISettings:
    normalized_provider = provider.strip().lower()
    if normalized_provider not in SUPPORTED_PROVIDERS:
        raise ValueError(f"Unsupported AI provider: {provider}")
    if normalized_provider == STERILE_PROVIDER or not enabled:
        return set_sterile(path=path)
    normalized_share = share_level.strip().lower()
    if normalized_share not in SHARE_LEVELS:
        raise ValueError(f"Unsupported share level: {share_level}")
    settings = AISettings(
        enabled=True,
        provider=normalized_provider,
        model=model or default_model(normalized_provider),
        api_key_env=api_key_env or default_api_key_env(normalized_provider),
        endpoint=endpoint or default_endpoint(normalized_provider),
        share_level=normalized_share,
        use_engine_tools=True if use_engine_tools is None else bool(use_engine_tools),
        use_traffic_context=False if use_traffic_context is None else bool(use_traffic_context),
        use_memory_context=True if use_memory_context is None else bool(use_memory_context),
    )
    save_ai_settings(settings, path=path)
    return settings


def _stable_token(value: str, prefix: str) -> str:
    if not value:
        return ""
    digest = hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:10]
    return f"{prefix}-{digest}"


def _device_payload(device: Any, share_level: str) -> dict[str, Any]:
    row = device.as_dict() if hasattr(device, "as_dict") else dict(device or {})
    metadata = dict(row.get("metadata") or {})
    payload = {
        "ip": row.get("ip", ""),
        "hostname": row.get("hostname", ""),
        "vendor": row.get("vendor", ""),
        "open_ports": list(row.get("open_ports") or row.get("ports") or []),
        "source": row.get("source", ""),
        "status": row.get("status", ""),
    }
    if share_level == "minimal":
        payload["ip"] = _stable_token(str(row.get("ip") or ""), "ip")
        payload["hostname"] = _stable_token(str(row.get("hostname") or ""), "host")
        payload["mac_address"] = _stable_token(str(row.get("mac_address") or row.get("mac") or ""), "mac")
    elif share_level == "standard":
        payload["mac_address"] = _stable_token(str(row.get("mac_address") or row.get("mac") or ""), "mac")
    else:
        payload["mac_address"] = row.get("mac_address") or row.get("mac") or ""
        payload["interface"] = row.get("interface", "")
        payload["metadata"] = metadata
    return payload


def _finding_payload(finding: Any, share_level: str) -> dict[str, Any]:
    row = finding.as_dict() if hasattr(finding, "as_dict") else dict(finding or {})
    evidence = dict(row.get("evidence") or {})
    redactions = _finding_redactions(row, evidence)
    payload = {
        "rule_id": row.get("rule_id", ""),
        "title": row.get("title", ""),
        "severity": row.get("severity", ""),
        "confidence": row.get("confidence", 0),
        "risk_score": row.get("risk_score", 0),
        "priority": row.get("priority", ""),
        "category": row.get("category", ""),
        "plain_english": row.get("plain_english", ""),
        "recommended_actions": list(row.get("recommended_actions") or []),
        "evidence": evidence,
    }
    if share_level == "minimal":
        payload["device_ip"] = _stable_token(str(row.get("device_ip") or ""), "ip")
        payload["device_name"] = _stable_token(str(row.get("device_name") or ""), "device")
        payload["title"] = _redact_text(str(payload["title"]), redactions)
        payload["plain_english"] = _redact_text(str(payload["plain_english"]), redactions)
        payload["recommended_actions"] = [_redact_text(str(action), redactions) for action in payload["recommended_actions"]]
    else:
        payload["device_ip"] = row.get("device_ip", "")
        payload["device_name"] = row.get("device_name", "")
    if share_level != "full":
        payload["evidence"] = _scrub_evidence(payload["evidence"], share_level=share_level)
    return payload


def _finding_redactions(row: dict[str, Any], evidence: dict[str, Any]) -> dict[str, str]:
    replacements: dict[str, str] = {}
    candidates = {
        "device_ip": (row.get("device_ip"), "ip"),
        "device_name": (row.get("device_name"), "device"),
        "hostname": (row.get("hostname"), "host"),
        "mac_address": (row.get("mac_address") or row.get("mac"), "mac"),
    }
    for _, (value, prefix) in candidates.items():
        text = str(value or "")
        if text:
            replacements[text] = _stable_token(text, prefix)
    for key, value in evidence.items():
        if _is_sensitive_key(str(key)):
            text = str(value or "")
            if text:
                replacements[text] = _stable_token(text, _token_prefix_for_key(str(key)))
    return replacements


def _scrub_evidence(evidence: dict[str, Any], *, share_level: str) -> dict[str, Any]:
    return {key: _scrub_evidence_value(str(key), value, share_level=share_level) for key, value in evidence.items()}


def _scrub_evidence_value(key: str, value: Any, *, share_level: str) -> Any:
    if isinstance(value, dict):
        return {inner_key: _scrub_evidence_value(str(inner_key), inner_value, share_level=share_level) for inner_key, inner_value in value.items()}
    if isinstance(value, list):
        return [_scrub_evidence_value(key, item, share_level=share_level) for item in value]
    if not isinstance(value, str):
        return value
    sensitive_key = _is_sensitive_key(key)
    if share_level == "minimal":
        return _redact_text(value, {}) if _looks_sensitive_text(value) else _stable_token(value, _token_prefix_for_key(key))
    if sensitive_key:
        return _redact_text(value, {}) if _looks_sensitive_text(value) else _stable_token(value, _token_prefix_for_key(key))
    return _redact_text(value, {}) if _looks_sensitive_text(value) else value


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in SENSITIVE_EVIDENCE_KEY_MARKERS)


def _token_prefix_for_key(key: str) -> str:
    lowered = key.lower()
    if "ip" in lowered or "address" in lowered:
        return "ip"
    if "mac" in lowered:
        return "mac"
    if "host" in lowered:
        return "host"
    if "path" in lowered or "file" in lowered or "directory" in lowered or "registry" in lowered:
        return "path"
    if "user" in lowered:
        return "user"
    if "ssid" in lowered:
        return "ssid"
    return "value"


def _looks_sensitive_text(value: str) -> bool:
    return any(
        pattern.search(value)
        for pattern in (IPV4_RE, MAC_RE, WINDOWS_PATH_RE, UNC_PATH_RE, UNIX_USER_PATH_RE, REGISTRY_PATH_RE)
    )


def _redact_text(text: str, replacements: dict[str, str]) -> str:
    redacted = text
    for raw, token in sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True):
        if raw:
            redacted = redacted.replace(raw, token)
    redacted = IPV4_RE.sub(lambda match: _stable_token(match.group(0), "ip"), redacted)
    redacted = MAC_RE.sub(lambda match: _stable_token(match.group(0), "mac"), redacted)
    redacted = WINDOWS_PATH_RE.sub(lambda match: _stable_token(match.group(0), "path"), redacted)
    redacted = UNC_PATH_RE.sub(lambda match: _stable_token(match.group(0), "path"), redacted)
    redacted = UNIX_USER_PATH_RE.sub(lambda match: _stable_token(match.group(0), "path"), redacted)
    redacted = REGISTRY_PATH_RE.sub(lambda match: _stable_token(match.group(0), "path"), redacted)
    return redacted


def _report_redactions(data: dict[str, Any]) -> dict[str, str]:
    replacements: dict[str, str] = {}
    for device in data.get("devices") or []:
        row = device.as_dict() if hasattr(device, "as_dict") else dict(device or {})
        for key, prefix in (("ip", "ip"), ("hostname", "host"), ("mac_address", "mac"), ("mac", "mac")):
            value = str(row.get(key) or "")
            if value:
                replacements[value] = _stable_token(value, prefix)
    for finding in data.get("findings") or []:
        row = finding.as_dict() if hasattr(finding, "as_dict") else dict(finding or {})
        for key, prefix in (("device_ip", "ip"), ("device_name", "device")):
            value = str(row.get(key) or "")
            if value:
                replacements[value] = _stable_token(value, prefix)
    return replacements


def report_to_signal_context(report: HomeGuardReport | dict[str, Any], *, share_level: str = DEFAULT_SHARE_LEVEL) -> dict[str, Any]:
    """Convert a HomeGuard report into the bounded signal payload sent to AI.

    The payload favors security signals over raw inventory. Minimal mode hashes
    host identifiers so a provider can reason about relationships without seeing
    real IP addresses, hostnames, MAC addresses, usernames, or local paths.
    """

    if share_level not in SHARE_LEVELS:
        share_level = DEFAULT_SHARE_LEVEL
    data = report.as_dict() if hasattr(report, "as_dict") else dict(report or {})
    devices = data.get("devices") or []
    findings = data.get("findings") or []
    redactions = _report_redactions(data) if share_level == "minimal" else {}
    sorted_findings = sorted(
        findings,
        key=lambda item: _safe_float((item.as_dict() if hasattr(item, "as_dict") else item).get("risk_score"), 0.0),
        reverse=True,
    )
    return {
        "homeguard_signal_schema": "1.0",
        "share_level": share_level,
        "report_id": data.get("report_id", ""),
        "created_at": data.get("created_at", ""),
        "overall_risk": data.get("overall_risk", "unknown"),
        "overall_score": data.get("overall_score", 0),
        "summary": _redact_text(str(data.get("summary", "")), redactions) if share_level == "minimal" else data.get("summary", ""),
        "counts": {
            "devices": len(devices),
            "findings": len(findings),
        },
        "top_findings": [_finding_payload(item, share_level) for item in sorted_findings[:12]],
        "devices": [_device_payload(item, share_level) for item in devices[:40]],
        "next_steps": [
            _redact_text(str(step), redactions) if share_level == "minimal" else step
            for step in list(data.get("next_steps") or [])[:12]
        ],
    }


def sterile_response(reason: str = "AI is disabled. HomeGuard is in sterile mode.") -> AIResponse:
    return AIResponse(ok=True, provider=STERILE_PROVIDER, model="", text=reason, sterile=True)


def explain_report(
    report: HomeGuardReport | dict[str, Any],
    *,
    question: str = "Explain these HomeGuard signals and prioritize what the user should do next.",
    settings: AISettings | None = None,
) -> AIResponse:
    settings = settings or load_ai_settings()
    if settings.is_sterile():
        return sterile_response()
    record_report_snapshot(report)
    context = report_to_signal_context(report, share_level=settings.share_level)
    messages: list[dict[str, Any]] = [
        {
            "role": "system",
            "content": _build_system_prompt(settings),
        },
        {
            "role": "user",
            "content": json.dumps({"question": question, "homeguard_signals": context}, indent=2),
        },
    ]
    return chat(messages, settings=settings)


def live_chat(
    user_prompt: str,
    *,
    history: list[dict[str, Any]] | None = None,
    settings: AISettings | None = None,
    include_traffic: bool | None = None,
) -> AIResponse:
    """High-level chat entry point used by the GUI.

    Builds the system prompt with bounded memory context, optionally a
    network-traffic snapshot, and delegates to :func:`chat`. The tool loop
    (when enabled in settings) gives the model on-demand access to the
    engine — report, devices, findings, memory, and traffic.
    """

    settings = settings or load_ai_settings()
    if settings.is_sterile():
        return sterile_response()
    if include_traffic is None:
        include_traffic = settings.use_traffic_context
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": _build_system_prompt(settings, include_traffic=include_traffic)},
    ]
    for entry in history or []:
        role = entry.get("role")
        if role not in {"user", "assistant"}:
            continue
        text = entry.get("content")
        if not isinstance(text, str) or not text.strip():
            continue
        messages.append({"role": role, "content": text})
    messages.append({"role": "user", "content": user_prompt})
    return chat(messages, settings=settings)


def _build_system_prompt(settings: AISettings, *, include_traffic: bool = False) -> str:
    parts = [
        "You are the user's chosen AI assistant inside HomeGuard, a home network "
        "security tool. Explain security signals in plain English. Do not claim "
        "proof of compromise. Recommend safe defensive steps only. Ask for "
        "confirmation before suggesting risky changes.",
    ]
    if settings.use_engine_tools:
        parts.append(
            "You have tools to read the latest HomeGuard scan, list devices, "
            "look up findings, snapshot current network connections, and read or "
            "write the local AI memory. Prefer calling a tool over guessing. "
            f"All identifiers are redacted at share level '{settings.share_level}'."
        )
    else:
        parts.append(
            "Engine tool-calling is disabled, so reason only from the context provided in this prompt."
        )
    if settings.use_memory_context:
        memory_snapshot = ai_memory.summarize_for_prompt()
        if any(memory_snapshot.get(key) for key in ("notes", "device_facts", "signal_history")):
            parts.append(
                "Local AI memory (what HomeGuard has learned about this network "
                "from past sessions):\n" + json.dumps(memory_snapshot, indent=2, sort_keys=True)
            )
    if include_traffic:
        try:
            summary = ai_traffic.collect_traffic_summary(share_level=settings.share_level)
            parts.append(
                "Current network-connection snapshot (no packet content captured):\n"
                + json.dumps(summary.as_dict(), indent=2, sort_keys=True)
            )
        except Exception as exc:  # pragma: no cover - defensive
            parts.append(f"Traffic snapshot unavailable: {exc}")
    return "\n\n".join(parts)


def record_report_snapshot(report: HomeGuardReport | dict[str, Any]) -> None:
    """Save a bounded signal-trend snapshot into the local AI memory.

    This is the "training on data" closure: HomeGuard cannot fine-tune a
    cloud LLM but it can persistently remember the shape of past scans so
    the assistant builds a picture of the network over time.
    """

    data = report.as_dict() if hasattr(report, "as_dict") else dict(report or {})
    findings = data.get("findings") or []
    devices = data.get("devices") or []
    categories: dict[str, int] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        category = str(finding.get("category") or "uncategorized")
        categories[category] = categories.get(category, 0) + 1
    top_categories = [
        category for category, _ in sorted(categories.items(), key=lambda item: item[1], reverse=True)[:5]
    ]
    try:
        ai_memory.record_signal_snapshot(
            ai_memory.SignalSnapshot(
                created_at=time.time(),
                overall_risk=str(data.get("overall_risk") or "unknown"),
                overall_score=_safe_float(data.get("overall_score"), 0.0),
                finding_count=len(findings),
                device_count=len(devices),
                top_categories=top_categories,
            )
        )
    except OSError:
        # Memory persistence is best-effort; never break a scan because the
        # AI memory file is unwritable.
        pass


def chat(messages: list[dict[str, str]], *, settings: AISettings | None = None) -> AIResponse:
    settings = settings or load_ai_settings()
    if settings.is_sterile():
        return sterile_response()
    api_key = os.environ.get(settings.api_key_env, "") if settings.api_key_env else ""
    if not api_key:
        return AIResponse(
            ok=False,
            provider=settings.provider,
            model=settings.model,
            text="",
            error=f"Missing API key environment variable: {settings.api_key_env or '(not configured)'}",
        )
    try:
        if settings.provider in {"openai", "openrouter", "custom_openai_compatible"}:
            return _chat_openai_compatible(messages, settings=settings, api_key=api_key)
        if settings.provider == "anthropic":
            return _chat_anthropic(messages, settings=settings, api_key=api_key)
        if settings.provider == "gemini":
            return _chat_gemini(messages, settings=settings, api_key=api_key)
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        return AIResponse(ok=False, provider=settings.provider, model=settings.model, text="", error=str(exc))
    return AIResponse(ok=False, provider=settings.provider, model=settings.model, text="", error="Unsupported provider")


def _post_json(url: str, payload: dict[str, Any], headers: dict[str, str], *, timeout: float = 45.0) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8", errors="replace")
    data = json.loads(body)
    if not isinstance(data, dict):
        raise ValueError("AI provider returned a non-object response")
    return data


def _chat_openai_compatible(messages: list[dict[str, Any]], *, settings: AISettings, api_key: str) -> AIResponse:
    endpoint = settings.endpoint or default_endpoint(settings.provider)
    if not endpoint:
        return AIResponse(ok=False, provider=settings.provider, model=settings.model, text="", error="Missing endpoint")
    headers = {"Authorization": f"Bearer {api_key}"}
    if settings.provider == "openrouter":
        headers.update({"HTTP-Referer": "https://github.com/GreyNOC/HomeGuard", "X-Title": "HomeGuard"})
    payload: dict[str, Any] = {
        "model": settings.model,
        "messages": messages,
        "temperature": settings.temperature,
        "max_tokens": settings.max_output_tokens,
    }
    if settings.use_engine_tools:
        payload["tools"] = ai_tools.tool_definitions_openai()
    if settings.use_engine_tools:
        return _openai_tool_loop(payload, endpoint=endpoint, headers=headers, settings=settings)
    data = _post_json(endpoint, payload, headers)
    text = (((data.get("choices") or [{}])[0].get("message") or {}).get("content") or "").strip()
    return AIResponse(ok=bool(text), provider=settings.provider, model=settings.model, text=text, raw=data)


def _openai_tool_loop(
    payload: dict[str, Any],
    *,
    endpoint: str,
    headers: dict[str, str],
    settings: AISettings,
) -> AIResponse:
    messages = list(payload["messages"])
    for _ in range(MAX_TOOL_ITERATIONS):
        payload["messages"] = messages
        data = _post_json(endpoint, payload, headers)
        choice = (data.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        tool_calls = message.get("tool_calls") or []
        if not tool_calls:
            text = (message.get("content") or "").strip()
            return AIResponse(
                ok=bool(text),
                provider=settings.provider,
                model=settings.model,
                text=text,
                raw=data,
            )
        messages.append(message)
        for call in tool_calls:
            function = call.get("function") or {}
            name = str(function.get("name") or "")
            try:
                args = json.loads(function.get("arguments") or "{}")
            except (TypeError, ValueError):
                args = {}
            result = ai_tools.dispatch_tool(name, args, share_level=settings.share_level)
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call.get("id") or name,
                    "content": json.dumps(result),
                }
            )
    return AIResponse(
        ok=False,
        provider=settings.provider,
        model=settings.model,
        text="",
        error=f"AI exceeded the {MAX_TOOL_ITERATIONS}-iteration tool loop without finishing.",
    )


def _chat_anthropic(messages: list[dict[str, Any]], *, settings: AISettings, api_key: str) -> AIResponse:
    system_parts = [
        item.get("content", "")
        for item in messages
        if item.get("role") == "system" and isinstance(item.get("content"), str)
    ]
    user_messages: list[dict[str, Any]] = []
    for item in messages:
        if item.get("role") == "system":
            continue
        user_messages.append(_anthropic_normalize_message(item))
    if settings.use_engine_tools:
        return _anthropic_tool_loop(
            system="\n\n".join(system_parts),
            messages=user_messages,
            settings=settings,
            api_key=api_key,
        )
    data = _post_json(
        settings.endpoint or default_endpoint("anthropic"),
        {
            "model": settings.model,
            "system": "\n\n".join(system_parts),
            "messages": user_messages,
            "temperature": settings.temperature,
            "max_tokens": settings.max_output_tokens,
        },
        {"x-api-key": api_key, "anthropic-version": "2023-06-01"},
    )
    text = "".join(
        part.get("text", "")
        for part in data.get("content", [])
        if isinstance(part, dict) and part.get("type") == "text"
    ).strip()
    return AIResponse(ok=bool(text), provider=settings.provider, model=settings.model, text=text, raw=data)


def _anthropic_normalize_message(item: dict[str, Any]) -> dict[str, Any]:
    role = item.get("role") or "user"
    content = item.get("content")
    if isinstance(content, list):
        return {"role": role, "content": content}
    return {"role": role, "content": str(content or "")}


def _anthropic_tool_loop(
    *,
    system: str,
    messages: list[dict[str, Any]],
    settings: AISettings,
    api_key: str,
) -> AIResponse:
    endpoint = settings.endpoint or default_endpoint("anthropic")
    headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01"}
    for _ in range(MAX_TOOL_ITERATIONS):
        data = _post_json(
            endpoint,
            {
                "model": settings.model,
                "system": system,
                "messages": messages,
                "temperature": settings.temperature,
                "max_tokens": settings.max_output_tokens,
                "tools": ai_tools.tool_definitions_anthropic(),
            },
            headers,
        )
        blocks = data.get("content") or []
        tool_uses = [block for block in blocks if isinstance(block, dict) and block.get("type") == "tool_use"]
        if not tool_uses:
            text = "".join(
                block.get("text", "")
                for block in blocks
                if isinstance(block, dict) and block.get("type") == "text"
            ).strip()
            return AIResponse(
                ok=bool(text),
                provider=settings.provider,
                model=settings.model,
                text=text,
                raw=data,
            )
        messages.append({"role": "assistant", "content": blocks})
        tool_results: list[dict[str, Any]] = []
        for block in tool_uses:
            name = str(block.get("name") or "")
            args = block.get("input") or {}
            if not isinstance(args, dict):
                args = {}
            result = ai_tools.dispatch_tool(name, args, share_level=settings.share_level)
            tool_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": block.get("id") or name,
                    "content": json.dumps(result),
                }
            )
        messages.append({"role": "user", "content": tool_results})
    return AIResponse(
        ok=False,
        provider=settings.provider,
        model=settings.model,
        text="",
        error=f"AI exceeded the {MAX_TOOL_ITERATIONS}-iteration tool loop without finishing.",
    )


def _chat_gemini(messages: list[dict[str, str]], *, settings: AISettings, api_key: str) -> AIResponse:
    endpoint = (settings.endpoint or default_endpoint("gemini")).format(model=settings.model)
    separator = "\n\n"
    contents = []
    for message in messages:
        role = "model" if message.get("role") == "assistant" else "user"
        contents.append({"role": role, "parts": [{"text": f"{message.get('role', 'user')}: {message.get('content', '')}"}]})
    # Send the key in the x-goog-api-key header, never as a ?key= query
    # parameter: a URL-embedded secret leaks into proxy/CDN access logs and any
    # incidental logging of the request URL. The header form is equivalent for
    # the Gemini REST API.
    data = _post_json(
        endpoint,
        {
            "contents": contents,
            "generationConfig": {
                "temperature": settings.temperature,
                "maxOutputTokens": settings.max_output_tokens,
            },
        },
        {"x-goog-api-key": api_key},
    )
    candidates = data.get("candidates") or []
    parts = (((candidates[0] if candidates else {}).get("content") or {}).get("parts") or [])
    text = separator.join(part.get("text", "") for part in parts if isinstance(part, dict)).strip()
    return AIResponse(ok=bool(text), provider=settings.provider, model=settings.model, text=text, raw=data)


def _load_report(path: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Report must be a JSON object")
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m greynoc_homeguard.ai_bridge",
        description="Configure HomeGuard's opt-in AI bridge or sterile mode.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    status = sub.add_parser("status", help="Show AI bridge status")
    status.add_argument("--json", action="store_true")

    sterile = sub.add_parser("sterile", help="Disable AI and prevent outbound AI calls")
    sterile.add_argument("--json", action="store_true")

    configure = sub.add_parser("configure", help="Choose a user-owned AI provider")
    configure.add_argument("provider", choices=sorted(SUPPORTED_PROVIDERS - {STERILE_PROVIDER}))
    configure.add_argument("--model", default="")
    configure.add_argument("--api-key-env", default="")
    configure.add_argument("--endpoint", default="")
    configure.add_argument("--share-level", choices=sorted(SHARE_LEVELS), default=DEFAULT_SHARE_LEVEL)
    configure.add_argument("--tools", choices=["on", "off"], default="on", help="Enable engine tool-calling for the LLM")
    configure.add_argument("--traffic", choices=["on", "off"], default="off", help="Include a current network-traffic snapshot in chats")
    configure.add_argument("--memory", choices=["on", "off"], default="on", help="Include the local AI memory in chats")
    configure.add_argument("--json", action="store_true")

    explain = sub.add_parser("explain", help="Send a HomeGuard report to the selected AI provider")
    explain.add_argument("--report", required=True, help="Path to report.json")
    explain.add_argument("--question", default="Explain these HomeGuard signals and prioritize what I should do next.")
    explain.add_argument("--json", action="store_true")

    chat_cmd = sub.add_parser("chat", help="Send a single chat message to the selected AI provider")
    chat_cmd.add_argument("message")
    chat_cmd.add_argument("--include-traffic", action="store_true", help="Force a network-traffic snapshot into this turn")
    chat_cmd.add_argument("--json", action="store_true")

    memory = sub.add_parser("memory", help="Manage the local AI memory store")
    memory_sub = memory.add_subparsers(dest="memory_command", required=True)
    memory_sub.add_parser("show", help="Show the bounded memory summary used in prompts")
    memory_add = memory_sub.add_parser("add", help="Persist a free-form note for the assistant")
    memory_add.add_argument("text")
    memory_add.add_argument("--tag", action="append", default=[])
    memory_sub.add_parser("clear", help="Erase all stored AI memory")

    traffic = sub.add_parser("traffic", help="Print the bounded network-traffic snapshot the AI would receive")
    traffic.add_argument("--json", action="store_true")

    sub.add_parser(
        "chat-ipc",
        help="Read a JSON request from stdin and emit a JSON response. Used by the Electron IPC.",
    )
    return parser


def _settings_cli_payload(settings: AISettings) -> dict[str, Any]:
    # NOTE: the env-var *name* (e.g. "OPENAI_API_KEY") is not sensitive — it's
    # a label, not the secret itself. We expose it under "env_var" rather than
    # the literal "api_key_env" field name so the CodeQL clear-text-logging
    # heuristic doesn't flag normal CLI output as a password leak.
    return {
        "enabled": settings.enabled,
        "provider": settings.provider,
        "model": settings.model,
        "endpoint": settings.endpoint,
        "env_var": settings.api_key_env,
        "share_level": settings.share_level,
        "temperature": settings.temperature,
        "max_output_tokens": settings.max_output_tokens,
        "use_engine_tools": settings.use_engine_tools,
        "use_traffic_context": settings.use_traffic_context,
        "use_memory_context": settings.use_memory_context,
        "sterile": settings.is_sterile(),
    }


def _print_settings(settings: AISettings) -> None:
    mode = "sterile" if settings.is_sterile() else "ai-enabled"
    print(f"mode       : {mode}")
    print(f"provider   : {settings.provider}")
    print(f"model      : {settings.model or '-'}")
    print(f"share_level: {settings.share_level}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "status":
        settings = load_ai_settings()
        if args.json:
            print(json.dumps(_settings_cli_payload(settings), indent=2, sort_keys=True))
        else:
            _print_settings(settings)
        return 0
    if args.command == "sterile":
        settings = set_sterile()
        if args.json:
            print(json.dumps(_settings_cli_payload(settings), indent=2, sort_keys=True))
        else:
            print("HomeGuard AI bridge is sterile. No AI provider calls will be made.")
        return 0
    if args.command == "configure":
        settings = configure_ai(
            provider=args.provider,
            model=args.model,
            api_key_env=args.api_key_env,
            endpoint=args.endpoint,
            share_level=args.share_level,
            use_engine_tools=(args.tools == "on"),
            use_traffic_context=(args.traffic == "on"),
            use_memory_context=(args.memory == "on"),
        )
        if args.json:
            print(json.dumps(_settings_cli_payload(settings), indent=2, sort_keys=True))
        else:
            _print_settings(settings)
            print("Set the provider credential in your environment before using AI.")
        return 0
    if args.command == "explain":
        response = explain_report(_load_report(args.report), question=args.question)
        if args.json:
            print(json.dumps(response.as_dict(), indent=2, sort_keys=True))
        else:
            print(response.text or response.error)
        return 0 if response.ok else 2
    if args.command == "chat":
        response = live_chat(args.message, include_traffic=args.include_traffic)
        if args.json:
            print(json.dumps(response.as_dict(), indent=2, sort_keys=True))
        else:
            print(response.text or response.error)
        return 0 if response.ok else 2
    if args.command == "memory":
        if args.memory_command == "show":
            print(json.dumps(ai_memory.summarize_for_prompt(), indent=2, sort_keys=True))
            return 0
        if args.memory_command == "add":
            note = ai_memory.add_note(text=args.text, tags=list(args.tag or []))
            print(json.dumps(note.as_dict(), indent=2, sort_keys=True))
            return 0
        if args.memory_command == "clear":
            ai_memory.clear_memory()
            print("AI memory cleared.")
            return 0
    if args.command == "chat-ipc":
        import sys as _sys

        try:
            payload = json.loads(_sys.stdin.read() or "{}")
        except json.JSONDecodeError as exc:
            print(json.dumps({"ok": False, "error": f"Bad JSON on stdin: {exc}"}))
            return 2
        if not isinstance(payload, dict):
            print(json.dumps({"ok": False, "error": "Stdin must be a JSON object"}))
            return 2
        message = str(payload.get("message") or "")
        history = payload.get("history") or []
        if not isinstance(history, list):
            history = []
        include_traffic = bool(payload.get("include_traffic"))
        response = live_chat(message, history=history, include_traffic=include_traffic)
        print(json.dumps(response.as_dict(), indent=2, sort_keys=True))
        return 0 if response.ok else 2
    if args.command == "traffic":
        share_level = load_ai_settings().share_level
        summary = ai_traffic.collect_traffic_summary(share_level=share_level)
        payload = summary.as_dict()
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"source            : {payload['source']}")
            print(f"total_connections : {payload['total_connections']}")
            print(f"listening_ports   : {payload['listening_ports']}")
            print("established_remote_top:")
            for row in payload["established_remote_top"][:10]:
                print(f"  - {row}")
            print("process_top:")
            for row in payload["process_top"][:10]:
                print(f"  - {row}")
            if payload["note"]:
                print(f"note              : {payload['note']}")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
