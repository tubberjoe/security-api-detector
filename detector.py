"""Explainable, request-level API attack detection."""

import json
import re
from typing import Any


SQL_INJECTION = re.compile(r"(?:\bor\b\s+\d+\s*=\s*\d+|\bunion\b\s+select|--|/\*)", re.IGNORECASE)
PATH_TRAVERSAL = re.compile(r"(?:\.\./|%2e%2e|%252e%252e)", re.IGNORECASE)
SSRF_TARGET = re.compile(r"(?:https?://(?:127\.0\.0\.1|localhost|169\.254\.169\.254)|https?://10\.|https?://192\.168\.)", re.IGNORECASE)


def _values(value: Any):
    if isinstance(value, dict):
        for child in value.values():
            yield from _values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _values(child)
    elif value is not None:
        yield str(value)


def analyse_request(request: dict[str, Any]) -> dict[str, Any]:
    signals = []
    searchable = list(_values(request))
    combined = " ".join(searchable)

    if SQL_INJECTION.search(combined):
        signals.append({
            "detector": "sql_injection",
            "severity": "high",
            "points": 70,
            "reason": "Request contains syntax commonly associated with SQL injection.",
        })
    if PATH_TRAVERSAL.search(combined):
        signals.append({
            "detector": "path_traversal",
            "severity": "high",
            "points": 65,
            "reason": "Request contains path traversal indicators.",
        })
    if SSRF_TARGET.search(combined):
        signals.append({
            "detector": "ssrf",
            "severity": "high",
            "points": 60,
            "reason": "Request references a private or metadata-service address.",
        })

    score = min(sum(signal["points"] for signal in signals), 100)
    verdict = "Malicious" if score >= 70 else "Suspicious" if score >= 30 else "Benign"
    return {"verdict": verdict, "risk_score": score, "signals": signals}


def load_request(text: str) -> dict[str, Any]:
    request = json.loads(text)
    if not isinstance(request, dict):
        raise ValueError("The JSON root must be an object.")
    return request
