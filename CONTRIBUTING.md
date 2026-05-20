# Contributing

Thanks for improving HomeGuard.

## Community Access and Approval

- Stars, watches, forks, comments, issues, discussions, and pull requests are welcome when GitHub permissions allow them.
- Direct push access is not granted through comments, stars, forks, or pull requests.
- A change may be merged only after approval by @GreyNOC or by a maintainer explicitly trusted by @GreyNOC. Codex-assisted review may be used when GreyNOC authorizes it.
- Security-sensitive reports should follow SECURITY.md instead of being posted publicly.

## Local Checks

```bash
python -m pip install -e .
PYTHONPATH=src python -m unittest discover -s tests -v
GNHL --scan --out out/scan
```

## Pull Request Guidelines

- Keep scanning features bounded to private/local networks.
- Keep active probing opt-in.
- Do not add exploitation, credential guessing, stealth, persistence, or evasion features.
- Do not submit secrets, credentials, private data, malware, backdoors, or destructive payloads.
- Use plain-English finding explanations for consumers.
- Add tests for parser, scoring, baseline, definitions, PDF, or report changes.
