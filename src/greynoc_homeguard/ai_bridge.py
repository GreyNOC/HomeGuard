from __future__ import annotations

import argparse
import hashlib
import json
import os
import textwrap
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import HomeGuardReport
from .paths import atomic_write_text, user_data_dir

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
        "evidence": dict(row.get("evidence") or {}),
    }
    if share_level == "minimal":
        payload["device_ip"] = _stable_token(str(row.get("device_ip") or ""), "ip")
        payload["device_name"] = _stable_token(str(row.get("device_name") or ""), "device")
    else:
        payload["device_ip"] = row.get("device_ip", "")
        payload["device_name"] = row.get("device_name", "")
    if share_level != "full":
        payload["evidence"] = _scrub_evidence(payload["evidence"])
    return payload


def _scrub_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    scrubbed: dict[str, Any] = {}
    for key, value in evidence.items():
        lowered = str(key).lower()
        if any(marker in lowered for marker in ("mac", "ip", "host", "path", "user", "ssid")):
            scrubbed[key] = _stable_token(str(value), lowered[:8] or "value")
        else:
            scrubbed[key] = value
    return scrubbed


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
        "summary": data.get("summary", ""),
        "counts": {
            "devices": len(devices),
            "findings": len(findings),
        },
        "top_findings": [_finding_payload(item, share_level) for item in sorted_findings[:12]],
        "devices": [_device_payload(item, share_level) for item in devices[:40]],
        "next_steps": list(data.get("next_steps") or [])[:12],
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
    context = report_to_signal_context(report, share_level=settings.share_level)
    messages = [
        {
            "role": "system",
            "content": (
                "You are the user's chosen AI assistant inside HomeGuard. "
                "Explain security signals in plain English. Do not claim proof of compromise. "
                "Recommend safe defensive steps only. Ask for confirmation before suggesting risky changes."
            ),
        },
        {
            "role": "user",
            "content": json.dumps({"question": question, "homeguard_signals": context}, indent=2),
        },
    ]
    return chat(messages, settings=settings)


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


def _chat_openai_compatible(messages: list[dict[str, str]], *, settings: AISettings, api_key: str) -> AIResponse:
    endpoint = settings.endpoint or default_endpoint(settings.provider)
    if not endpoint:
        return AIResponse(ok=False, provider=settings.provider, model=settings.model, text="", error="Missing endpoint")
    headers = {"Authorization": f"Bearer {api_key}"}
    if settings.provider == "openrouter":
        headers.update({"HTTP-Referer": "https://github.com/GreyNOC/HomeGuard", "X-Title": "HomeGuard"})
    data = _post_json(
        endpoint,
        {
            "model": settings.model,
            "messages": messages,
            "temperature": settings.temperature,
            "max_tokens": settings.max_output_tokens,
        },
        headers,
    )
    text = (((data.get("choices") or [{}])[0].get("message") or {}).get("content") or "").strip()
    return AIResponse(ok=bool(text), provider=settings.provider, model=settings.model, text=text, raw=data)


def _chat_anthropic(messages: list[dict[str, str]], *, settings: AISettings, api_key: str) -> AIResponse:
    system_parts = [item.get("content", "") for item in messages if item.get("role") == "system"]
    user_messages = [item for item in messages if item.get("role") != "system"]
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
    text = "".join(part.get("text", "") for part in data.get("content", []) if isinstance(part, dict)).strip()
    return AIResponse(ok=bool(text), provider=settings.provider, model=settings.model, text=text, raw=data)


def _chat_gemini(messages: list[dict[str, str]], *, settings: AISettings, api_key: str) -> AIResponse:
    endpoint = (settings.endpoint or default_endpoint("gemini")).format(model=settings.model)
    separator = "\n\n"
    contents = []
    for message in messages:
        role = "model" if message.get("role") == "assistant" else "user"
        contents.append({"role": role, "parts": [{"text": f"{message.get('role', 'user')}: {message.get('content', '')}"}]})
    data = _post_json(
        f"{endpoint}?key={api_key}",
        {
            "contents": contents,
            "generationConfig": {
                "temperature": settings.temperature,
                "maxOutputTokens": settings.max_output_tokens,
            },
        },
        {},
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
    configure.add_argument("--json", action="store_true")

    explain = sub.add_parser("explain", help="Send a HomeGuard report to the selected AI provider")
    explain.add_argument("--report", required=True, help="Path to report.json")
    explain.add_argument("--question", default="Explain these HomeGuard signals and prioritize what I should do next.")
    explain.add_argument("--json", action="store_true")

    chat_cmd = sub.add_parser("chat", help="Send a single chat message to the selected AI provider")
    chat_cmd.add_argument("message")
    chat_cmd.add_argument("--json", action="store_true")
    return parser


def _print_settings(settings: AISettings) -> None:
    mode = "sterile" if settings.is_sterile() else "ai-enabled"
    print(f"mode       : {mode}")
    print(f"provider   : {settings.provider}")
    print(f"model      : {settings.model or '-'}")
    print(f"api_key_env: {settings.api_key_env or '-'}")
    print(f"endpoint   : {settings.endpoint or '-'}")
    print(f"share_level: {settings.share_level}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "status":
        settings = load_ai_settings()
        if args.json:
            print(json.dumps(settings.as_dict(), indent=2, sort_keys=True))
        else:
            _print_settings(settings)
        return 0
    if args.command == "sterile":
        settings = set_sterile()
        if args.json:
            print(json.dumps(settings.as_dict(), indent=2, sort_keys=True))
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
        )
        if args.json:
            print(json.dumps(settings.as_dict(), indent=2, sort_keys=True))
        else:
            _print_settings(settings)
            print(textwrap.dedent(f"""
                Set your API key before using AI:
                  {settings.api_key_env}=<your key>
            """).strip())
        return 0
    if args.command == "explain":
        response = explain_report(_load_report(args.report), question=args.question)
        if args.json:
            print(json.dumps(response.as_dict(), indent=2, sort_keys=True))
        else:
            print(response.text or response.error)
        return 0 if response.ok else 2
    if args.command == "chat":
        response = chat([{"role": "user", "content": args.message}])
        if args.json:
            print(json.dumps(response.as_dict(), indent=2, sort_keys=True))
        else:
            print(response.text or response.error)
        return 0 if response.ok else 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
