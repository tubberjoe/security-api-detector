# API Attack Detector

A small Flask web application for analysing JSON descriptions of API requests and returning an explainable risk verdict.

## Run it

```bash
cd /home/bob47/security-assignment
.venv/bin/python app.py
```

Open http://127.0.0.1:5000 in a browser. Paste a JSON request and select **Analyse request**.

Run the tests with:

```bash
.venv/bin/pytest -q
```

## Architecture

The browser sends JSON to the Flask web layer. Flask parses the input and calls the independent `analyse_request` function. The detector recursively inspects values in the request and runs three explainable detectors:

- SQL injection indicators
- Path traversal indicators
- SSRF indicators targeting private or metadata-service addresses

The web layer only presents results. The detector can also be reused by a CLI, API gateway, queue consumer, or security pipeline.

## Scoring

- SQL injection: 70 points
- Path traversal: 65 points
- SSRF: 60 points

Scores are capped at 100:

- 0–29: Benign
- 30–69: Suspicious
- 70–100: Malicious

These are initial heuristics, not a claim that the score is a probability. In a production system, the thresholds would be calibrated against labelled traffic and reviewed for false positives.

## Design decisions and trade-offs

The implementation uses deterministic rules rather than machine learning because the assignment values explainability and the sample size is unknown. Each result includes the detector and a human-readable reason. Recursive inspection allows nested JSON fields to be analysed without assuming a fixed request schema.

The detector identifies suspicious request indicators and attack attempts. It does not prove that an exploit succeeded. Confirming exploitation would require application, database, network, or host telemetry.

## Known limitations

- Simple pattern matching can produce false positives.
- Obfuscated or novel attacks may evade these rules.
- The application does not maintain request history yet, so it cannot detect rate-based enumeration.
- It does not perform external IP reputation or threat-intelligence lookups.
- It is a demonstration application and is not hardened for direct Internet exposure.
- Sensitive headers should be redacted before storing or displaying requests; this first version does not persist requests.
