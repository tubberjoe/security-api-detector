"""Cloudflare Python Worker entry point for the API attack detector."""

from html import escape
from urllib.parse import parse_qs

from detector import analyse_request, load_request
from workers import Response, WorkerEntrypoint

EXAMPLE = '{\n  "method": "POST",\n  "path": "/api/v1/users/search",\n  "body": {\n    "username": "admin\' OR 1=1--"\n  }\n}'

STYLE = """
:root { color-scheme: light; --ink: #172033; --muted: #667085; --line: #d9e0ea; --panel: #fff; --blue: #2457d6; }
* { box-sizing: border-box; } body { background: #f4f7fb; color: var(--ink); font: 16px/1.5 system-ui, sans-serif; margin: 0; }
main { max-width: 960px; margin: 0 auto; padding: 3rem 1.25rem; } .eyebrow { color: var(--blue); font-size: .78rem; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; }
h1 { font-size: clamp(2rem, 5vw, 3.4rem); line-height: 1.05; margin: .4rem 0 .8rem; } .intro { color: var(--muted); max-width: 62ch; }
.panel, .result { background: var(--panel); border: 1px solid var(--line); border-radius: 16px; box-shadow: 0 12px 30px rgb(23 32 51 / 7%); padding: 1.25rem; }
label { display: block; font-weight: 700; margin-bottom: .5rem; } textarea { border: 1px solid #b9c4d4; border-radius: 10px; display: block; font: 14px/1.5 ui-monospace, monospace; min-height: 280px; padding: 1rem; resize: vertical; width: 100%; }
button { background: var(--blue); border: 0; border-radius: 9px; color: white; cursor: pointer; font-weight: 700; margin-top: 1rem; min-height: 44px; padding: .7rem 1.2rem; }
.result { margin-top: 1.25rem; } .result-header { align-items: center; display: flex; gap: 1rem; justify-content: space-between; } .verdict { border-radius: 999px; font-size: .8rem; font-weight: 800; letter-spacing: .04em; padding: .35rem .7rem; }
.Malicious { border-left: 6px solid #c52d45; } .Malicious .verdict { background: #fde8ed; color: #a51f38; } .Suspicious { border-left: 6px solid #d99000; } .Suspicious .verdict { background: #fff3d6; color: #895c00; } .Benign { border-left: 6px solid #16855b; } .Benign .verdict { background: #e3f7ee; color: #126744; }
.score { font-size: 1.2rem; font-variant-numeric: tabular-nums; } .signal { border-top: 1px solid var(--line); margin-top: 1rem; padding-top: 1rem; } .signal-title { font-weight: 800; text-transform: capitalize; } .signal p { color: var(--muted); margin: .3rem 0; }
.evidence { background: #f5f7fa; border-radius: 8px; color: #39445a; font: 13px/1.4 ui-monospace, monospace; margin-top: .5rem; overflow-wrap: anywhere; padding: .7rem; } .error { border-left: 6px solid #c52d45; }
"""


def _signals(result: dict) -> str:
    parts = []
    for signal in result["signals"]:
        evidence = "".join(f'<div class="evidence">{escape(value)}</div>' for value in signal.get("evidence", []))
        parts.append(
            '<div class="signal">'
            f'<div class="signal-title">{escape(signal["detector"].replace("_", " "))} · {escape(signal["severity"])} severity</div>'
            f'<p>{escape(signal["reason"])}</p>{evidence}</div>'
        )
    return "".join(parts)


def _page(request_json: str, result: dict | None = None, error: str | None = None) -> str:
    result_html = ""
    if result is not None:
        signals = _signals(result) if result["signals"] else "<p>No suspicious indicators were detected in the supplied request.</p>"
        result_html = (
            f'<div class="result {escape(result["verdict"])}"><div class="result-header">'
            f'<h2>{escape(result["verdict"])}</h2><span class="verdict">{escape(result["verdict"])}</span></div>'
            f'<p class="score"><strong>Risk score:</strong> {result["risk_score"]}/100</p>'
            f'<h3>Why this was flagged</h3>{signals}</div>'
        )
    error_html = f'<div class="result error"><strong>Input error:</strong> {escape(error)}</div>' if error else ""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>API Attack Detector</title><style>{STYLE}</style></head><body><main>
<div class="eyebrow">Security analysis · explainable heuristics</div><h1>API Attack Detector</h1>
<p class="intro">Paste a JSON representation of an API request. The detector checks request fields for indicators of SQL injection, path traversal, and SSRF.</p>
<form class="panel" method="post"><label for="request_json">API request JSON</label><textarea id="request_json" name="request_json">{escape(request_json)}</textarea><button type="submit">Analyse request</button></form>
{error_html}{result_html}</main></body></html>"""


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        request_json = EXAMPLE
        result = None
        error = None
        if request.method == "POST":
            body = await request.text()
            request_json = parse_qs(body).get("request_json", [EXAMPLE])[0]
            try:
                result = analyse_request(load_request(request_json))
            except (ValueError, TypeError) as exc:
                error = f"Invalid request JSON: {exc}"
        return Response(_page(request_json, result, error), headers={"content-type": "text/html; charset=UTF-8"})
