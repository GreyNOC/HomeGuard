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

## Design rules

- AI is opt-in.
- Sterile mode is the default and must be easy to restore.
- API keys are never written into HomeGuard config.
- Outbound context is intentionally bounded.
- The assistant must stay defensive: explain indicators, avoid proof-of-compromise claims, and recommend safe actions.
- Provider failures must not break scanning, reporting, or sterile operation.
