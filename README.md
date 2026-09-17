# API Security Checker

A small Cloudflare Python Worker that analyses JSON descriptions of API requests and returns a risk verdict with supporting evidence.

## Technologies used

- Python 3.11+
- Cloudflare Workers with the Python Workers runtime
- `workers-py` for the Worker entry point and response handling
- `wrangler` for deployment
- Python's standard library, including `json`, `re`, and HTML escaping utilities
- Pytest for automated tests

## Architecture

The browser sends a JSON request through the web form to the Cloudflare Worker. The Worker parses the input and passes it to the detection engine. The engine returns a structured result, which the Worker renders as HTML.

```text
Browser
  ↓
Cloudflare Python Worker
  ↓
Detection engine
  ↓
Verdict, score, reasons, and evidence
```

The detection engine is separate from the web layer, so it could be reused by another interface or security pipeline. User-provided values are escaped before they are rendered in HTML.

## Detection approach

The detector checks values in the request path, query parameters, headers, and body. It currently looks for indicators of:

- SQL injection, including boolean conditions, `UNION SELECT`, and SQL comment syntax
- Path traversal, including `../` and encoded traversal sequences
- SSRF, including requests to localhost, private network ranges, and the cloud metadata service

Each matching detector returns its name, severity, score contribution, explanation, and up to three matching evidence values.

The final score is capped at 100:

```text
0–29   Benign
30–69  Suspicious
70–100 Malicious
```

The result identifies a suspicious request or attack attempt. It does not prove that the target application was vulnerable or that exploitation succeeded.

## Scope

This version focuses on three attack techniques at the individual request level:

- SQL injection
- Path traversal
- Server-side request forgery (SSRF)

It checks values in the request path, query parameters, headers, and body, including nested JSON. The detector looks for recognisable indicators of attack attempts and returns an explainable score with the matching evidence.

Authentication context, request history, behavioural baselines, and external threat intelligence are outside the current implementation. The detector also does not cover every API security issue, including IDOR, brute-force activity across multiple requests, account compromise, or confirmed unauthorised data access.

These boundaries were chosen to keep the demonstration focused. A production system would need identity, application, network, and host telemetry, along with calibrated rules tested against labelled traffic.

## Where the detection logic lives

The detection logic is in `detector.py`, mainly in `analyse_request()`.

The main components are:

- `_values()` walks through dictionaries and lists so nested request values are inspected.
- `SQL_INJECTION`, `PATH_TRAVERSAL`, and `SSRF_TARGET` contain the current regular-expression indicators.
- `_matching_evidence()` returns values that matched a detector, limited to three results and 160 characters per value.
- `analyse_request()` runs the detectors, builds the signals, adds their score contributions, and assigns the final verdict.
- `load_request()` parses the submitted JSON and checks that the root is an object.

The Cloudflare-specific web code is in `worker.py`. It accepts the form submission, calls `load_request()` and `analyse_request()`, escapes values for HTML, and renders the result. Detection rules should normally be changed in `detector.py`, rather than copied into `worker.py`.

## How to change the detection logic

To change an existing detector, update its regular expression and, if needed, its reason or score in `detector.py`. For example, adding another SQL injection indicator means updating `SQL_INJECTION` and the related explanation.

To add a new detector:

1. Add a compiled regular expression near the other detector patterns.
2. Add a check in `analyse_request()`.
3. Add a signal with a detector name, severity, score, reason, and evidence.
4. Add a test in `tests/test_detector.py`.
5. Add a matching example to `examples/scenarios.md`.
6. Update this README if the supported attack types or scoring change.
7. Run the tests before deploying with Wrangler.

Tests should check the expected behaviour. For example, a SQL injection test should check the verdict, score range, detector name, and evidence.

## Design decisions and trade-offs

The detector uses visible, deterministic rules instead of machine learning. This keeps the results easy to test and explain during the interview, especially when the available traffic is not labelled.

The score is a heuristic, not a probability. SQL injection and path traversal each contribute 70 points, generic SSRF contributes 60 points, and cloud metadata targeting contributes 75 points. These values are starting assumptions that would need to be calibrated against labelled traffic in a production system.

Recursive inspection supports nested JSON without requiring a fixed request schema. The trade-off is that a pattern may be flagged even when it appears in a legitimate context. Evidence is limited to short matching values so the result stays readable and does not expose an entire request body.

## Known limitations

- Simple pattern matching can produce false positives.
- Obfuscated or novel attacks may evade the rules.
- The detector does not retain request history, so it cannot identify rate-based enumeration.
- It does not use external IP reputation or threat-intelligence services.
- It does not confirm whether an exploit succeeded. That requires application, database, network, or host telemetry.
- The Worker is a demonstration application and is not hardened to act as a production API gateway.

## Deployment

The project is deployed as the `security-api-detector` Cloudflare Worker:

https://security-api-detector.tbbkcc2rkr.workers.dev/

Deploy updates from the project directory with:

```bash
npx wrangler deploy
```

Deployment requires `CLOUDFLARE_API_TOKEN` to be supplied as a local environment variable. The token must not be committed to Git or stored in project source files.

## Tests

The repository includes automated tests covering the current detector behaviour. The latest reported result is:

```text
2 passed
```
