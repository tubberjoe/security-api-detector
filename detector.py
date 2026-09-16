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


def _matching_evidence(values: list[str], pattern: re.Pattern[str]) -> list[str]:
    matches = []
    for value in values:
        if pattern.search(value):
            matches.append(value[:160])
    return matches[:3]


def analyse_request(request: dict[str, Any]) -> dict[str, Any]:
    signals = []
    searchable = list(_values(request))
    combined = " ".join(searchable)

    if SQL_INJECTION.search(combined):
        evidence = _matching_evidence(searchable, SQL_INJECTION)
        signals.append({
            "detector": "sql_injection",
            "severity": "high",
            "points": 70,
            "reason": "Request contains SQL-style boolean logic, UNION SELECT, comment markers, or block-comment syntax.",
            "evidence": evidence,
        })
    if PATH_TRAVERSAL.search(combined):
        evidence = _matching_evidence(searchable, PATH_TRAVERSAL)
        signals.append({
            "detector": "path_traversal",
            "severity": "high",
            "points": 65,
            "reason": "Request contains ../ or encoded traversal sequences that can escape an intended directory.",
            "evidence": evidence,
        })
    if SSRF_TARGET.search(combined):
        evidence = _matching_evidence(searchable, SSRF_TARGET)
        signals.append({
            "detector": "ssrf",
            "severity": "high",
            "points": 60,
            "reason": "Request references localhost, a private network address, or the cloud metadata service.",
            "evidence": evidence,
        })

    score = min(sum(signal["points"] for signal in signals), 100)
    verdict = "Malicious" if score >= 70 else "Suspicious" if score >= 30 else "Benign"
    return {"verdict": verdict, "risk_score": score, "signals": signals}


def load_request(text: str) -> dict[str, Any]:
    request = json.loads(text)
    if not isinstance(request, dict):
        raise ValueError("The JSON root must be an object.")
    return request
