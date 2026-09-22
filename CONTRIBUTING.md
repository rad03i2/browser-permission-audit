# Contributing

Contributions are welcome when they keep the auditor deterministic, offline, and explainable.

1. Fork and create a focused branch.
2. Use Python 3.10+ and install with `python -m pip install -e . pytest`.
3. Add or update tests for behavior changes.
4. Run `python -m compileall -q src tests` and `pytest -q`.
5. Keep permission rules evidence-based; avoid labeling an extension malicious from permissions alone.
6. Open a concise pull request describing the behavior and tests.

Please avoid unrelated generated files, telemetry, secrets, or network-dependent tests.
