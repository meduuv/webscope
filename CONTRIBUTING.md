# Contributing

Contributions are welcome when they improve correctness, portability, documentation or test coverage.

## Local setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
python -m unittest discover -s tests -v
```

On Windows, activate the environment with `.venv\Scripts\activate`.

## Pull requests

Keep changes focused. Add or update tests when behavior changes, avoid unrelated formatting churn, and explain any network or compatibility impact clearly.

WebScope is intended for ordinary DNS, TLS and HTTP inspection. Contributions that add intrusive scanning or exploitation behavior are out of scope.

## Reporting issues

Remove credentials, private hostnames, tokens and other sensitive data from reports before posting them publicly.
