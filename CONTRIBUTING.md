# Contributing

Thanks for improving HomeGuard.

## Local checks

```bash
python -m pip install -e .
PYTHONPATH=src python -m unittest discover -s tests -v
GNHL --scan --out out/scan
```

## Pull request guidelines

- Keep scanning features bounded to private/local networks.
- Keep active probing opt-in.
- Do not add exploitation, credential guessing, stealth, persistence, or evasion features.
- Use plain-English finding explanations for consumers.
- Add tests for parser, scoring, baseline, definitions, PDF, or report changes.
