# API Attack Detector

Small Cloudflare Python Worker that analyses JSON API requests and returns a verdict, score, explanation, and evidence.

Live app: https://security-api-detector.tbbkcc2rkr.workers.dev/

## Architecture

```text
Browser → Cloudflare Worker → detector.py → verdict, score, reasons, evidence
```

The Worker accepts JSON from the web form. `detector.py` analyses the request and returns structured results. The Worker renders those results as HTML and escapes user values before display.

The detector is separate from the web layer. This makes it reusable from another interface or security pipeline.

## Detection approach

The detector checks request paths, query parameters, headers, bodies, and nested JSON values for:

- SQL injection, including boolean conditions, `UNION SELECT`, and SQL comments
- Path traversal, including `../` and encoded traversal
- SSRF, including localhost, private networks, and cloud metadata targets

Python regular expressions search for recognisable attack patterns. The detector reports the matching value as evidence, with a limit of three short values.

It detects attack indicators. It does not prove that exploitation succeeded.

## Design decisions and trade-offs

The detector uses fixed rules instead of machine learning. Each rule is visible in `detector.py`, so its behaviour is easy to inspect and test. This also avoids needing a large labelled dataset.

The detector recursively checks dictionaries and lists. This means it can find suspicious values inside nested JSON, even when request fields have different names or structures.

The detector displays only short matching values as evidence. This helps explain the result without showing an entire request body, which could contain sensitive information.

The score is a heuristic, not a probability. Signals add points, with a maximum of 100:

| Signal | Points | Reason |
|---|---:|---|
| SQL injection | 70 | Strong indicator of an attempt to alter a database query. |
| Path traversal | 70 | Repeated or encoded traversal can access files outside the intended directory. |
| Generic SSRF | 60 | Private-network target is suspicious, but may be an internal service used legitimately. |
| Cloud metadata SSRF | 75 | Metadata endpoints can expose cloud credentials and instance details. |

```text
0–29   Benign
30–69  Suspicious
70–100 Malicious
```

These starting values need calibration against labelled traffic in production.

## Known limitations

- Rules can create false positives.
- Obfuscated or new attacks may evade the rules.
- The detector does not retain request history, so it cannot identify activity across multiple requests.
- It does not use authentication context, behaviour baselines, external IP reputation, or threat intelligence.
- It does not detect every API issue, including IDOR, multi-request brute force, account compromise, or confirmed data access.
- It does not confirm successful exploitation. That requires application, database, network, or host telemetry.
- The Worker is a demonstration application, not a production API gateway.

## Technologies

- Python 3.11+
- Cloudflare Workers Python runtime
- `workers-py`
- Wrangler
- Python standard library, including `json` and `re`
- Pytest

## Detection logic

Detection logic is mainly in `detector.py`, especially `analyse_request()`.

- `_values()` walks dictionaries and lists.
- `SQL_INJECTION`, `PATH_TRAVERSAL`, and `SSRF_TARGET` hold compiled regular expressions.
- `_matching_evidence()` returns up to three short matching values.
- `analyse_request()` runs detectors, calculates the score, and assigns the verdict.
- `load_request()` parses JSON and checks that its root is an object.

`worker.py` handles the Cloudflare web page. Keep detection rules in `detector.py`, not `worker.py`.

## How to change detection logic

1. Edit the relevant regular expression, reason, or score in `detector.py`.
2. For a new detector, add a compiled regular expression and check inside `analyse_request()`.
3. Return a signal with a detector name, severity, score, reason, and evidence.
4. Add tests in `tests/test_detector.py`.
5. Add an example to `examples/scenarios.md`.
6. Update scoring or scope documentation if needed.
7. Run `./.venv/bin/pytest -q` before deployment.

The repository also contains a local Flask entry point in `app.py` for development and testing.

## Scenario testing

All 12 scenarios in `examples/scenarios.md` were tested. Each returned its documented result, including benign requests, attack indicators, nested JSON, missing fields, and malformed JSON.
