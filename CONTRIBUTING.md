# Contributing

Thank you for improving LordMs Recon.

## Ground rules

- Test only systems you own or are explicitly authorized to assess.
- Keep active integrations opt-in and preserve conservative defaults.
- Do not commit secrets, personal data, target results, or generated `recon_*` folders.
- Prefer small pull requests with a clear rationale and tests.

## Local workflow

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m compileall -q src recon_prime.py
python -m unittest discover -s tests -v
```

Before opening a pull request, update documentation when behavior or CLI options change. Describe what changed, why it changed, how it was tested, and any compatibility or security implications.

