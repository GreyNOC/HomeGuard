# HomeGuard AI Bridge

HomeGuard is sterile by default. That means scan signals, reports, device inventory, hostnames, MAC addresses, local paths, and chat messages stay local unless the user explicitly chooses an AI provider.

The AI bridge lets a user bring their preferred AI API to HomeGuard without locking HomeGuard to one vendor. HomeGuard only stores provider settings. API keys stay in environment variables controlled by the user.

## Modes

- `sterile`: default. No outbound AI calls.
- `openai`: OpenAI chat completions API.
- `anthropic`: Anthropic Messages API.
- `openrouter`: OpenRouter chat completions API.
- `gemini`: Google Gemini generateContent API.
- `custom_openai_compatible`: any OpenAI-compatible chat endpoint supplied by the user.

## Privacy levels

HomeGuard sends a bounded signal context instead of the full raw report.

- `minimal`: hashes IP addresses, hostnames, MAC addresses, device names, and sensitive evidence fields. Best default for consumer users.
- `standard`: keeps IP addresses and hostnames but hashes MAC addresses and strips sensitive evidence fields.
- `full`: sends the report signal context with raw identifiers and metadata. Use only when the user understands what they are sharing.

## Configure sterile mode

```bash
python -m greynoc_homeguard.ai_bridge sterile
python -m greynoc_homeguard.ai_bridge status
```

Sterile mode writes this local config file:

```text
%LOCALAPPDATA%\GreyNOC\HomeGuard\ai_settings.json
```

On macOS and Linux, it follows HomeGuard's normal app-data directory rules.

## Configure a preferred AI provider

OpenAI example:

```bash
python -m greynoc_homeguard.ai_bridge configure openai --model gpt-4.1-mini --share-level minimal
set OPENAI_API_KEY=your-key-here
```

PowerShell:

```powershell
python -m greynoc_homeguard.ai_bridge configure openai --model gpt-4.1-mini --share-level minimal
$env:OPENAI_API_KEY = "your-key-here"
```

Anthropic example:

```bash
python -m greynoc_homeguard.ai_bridge configure anthropic --model claude-3-5-haiku-latest --share-level minimal
set ANTHROPIC_API_KEY=your-key-here
```

OpenRouter example:

```bash
python -m greynoc_homeguard.ai_bridge configure openrouter --model openai/gpt-4.1-mini --share-level minimal
set OPENROUTER_API_KEY=your-key-here
```

Gemini example:

```bash
python -m greynoc_homeguard.ai_bridge configure gemini --model gemini-1.5-flash --share-level minimal
set GEMINI_API_KEY=your-key-here
```

Custom OpenAI-compatible endpoint example:

```bash
python -m greynoc_homeguard.ai_bridge configure custom_openai_compatible ^
  --endpoint http://127.0.0.1:11434/v1/chat/completions ^
  --model local-model-name ^
  --api-key-env HOMEGUARD_AI_API_KEY ^
  --share-level minimal
set HOMEGUARD_AI_API_KEY=local-or-placeholder-key
```

## Explain a report with the selected AI

```bash
python -m greynoc_homeguard.ai_bridge explain --report path\to\report.json
```

Ask a specific question:

```bash
python -m greynoc_homeguard.ai_bridge explain --report path\to\report.json --question "Which finding should I fix first?"
```

## Simple chat

```bash
python -m greynoc_homeguard.ai_bridge chat "What does RDP exposure mean for a home PC?"
```

## Configure the bridge from the GUI

Open **AI Settings** in the HomeGuard sidebar. Pick a provider, paste the model
name, set the environment-variable name HomeGuard should read the key from,
and (optionally) override the endpoint. Three toggles control how the AI uses
local data:

- **Engine tools** — when on, the LLM can call into HomeGuard to read the
  latest scan, list devices, look up findings, snapshot current network
  connections, and read/write the local AI memory. When off, the model
  reasons only from the prompt context you send.
- **Memory context** — when on, the AI memory store is injected into every
  chat turn so the assistant carries facts across sessions.
- **Traffic snapshot** — when on, a bounded current-connections summary is
  included with every chat. Off by default.

Use the **Test connection** button to send a one-shot ping. Use **Switch to
sterile** to disable all outbound calls in one click.

## Engine tool calling

When tool calling is enabled, HomeGuard exposes these tools to the LLM
(provider-agnostic; mapped to OpenAI `tools` and Anthropic `tool_use`):

- `homeguard_get_latest_report` — bounded signal context of the most recent
  scan, redacted to the active share level.
- `homeguard_list_devices` — up to N devices from the latest scan.
- `homeguard_get_finding` — fetch findings by `rule_id` or `finding_id`.
- `homeguard_get_traffic_summary` — current connection snapshot (no packet
  content captured).
- `homeguard_get_memory` — recall notes, device facts, and recent scan
  trend snapshots.
- `homeguard_save_memory_note` — persist a short note for future chats.
- `homeguard_record_device_fact` — persist structured facts (label, trust,
  owner) keyed by device fingerprint. Fingerprints are hashed in
  minimal/standard share levels.

The tool loop is bounded to four iterations per turn so a misbehaving model
cannot run away.

## Local AI memory ("training")

HomeGuard cannot fine-tune a cloud LLM. The next-best thing — and what most
users mean by "let it train on my data" — is a persistent local memory that
gets injected back into prompts. The store lives at:

```text
%LOCALAPPDATA%\GreyNOC\HomeGuard\ai_memory.json
```

It holds three buckets, each bounded in size:

- `notes`           — free-form facts the user (or AI) has saved.
- `device_facts`    — label / trust / owner / risk keyed by device fingerprint.
- `signal_history`  — recent scan trend snapshots (counts, top finding
  categories, overall risk/score).

A signal snapshot is recorded automatically whenever the AI explains a
report, so the trend view fills up as you use the app.

CLI helpers:

```bash
python -m greynoc_homeguard.ai_bridge memory show
python -m greynoc_homeguard.ai_bridge memory add "trust the camera on 192.168.1.42"
python -m greynoc_homeguard.ai_bridge memory clear
```

## Network-traffic snapshot

HomeGuard does **not** capture raw packets. The traffic feed is a bounded
connection-state summary built from `psutil.net_connections` (preferred) or
`netstat` (fallback). External endpoints are hashed in `minimal` share level;
LAN addresses pass through unchanged at `standard`. Run the snapshot the AI
would receive:

```bash
python -m greynoc_homeguard.ai_bridge traffic --json
```

## Design rules

- AI is opt-in.
- Sterile mode is the default and must be easy to restore.
- API keys are never written into HomeGuard config.
- Outbound context is intentionally bounded.
- The assistant must stay defensive: explain indicators, avoid proof-of-compromise claims, and recommend safe actions.
- Provider failures must not break scanning, reporting, or sterile operation.
- Tool loops are bounded so a runaway model cannot exhaust quota.
- Traffic capture is connection-summary only, never packet content.
