"""Cloudflare Python Worker entry point for the API attack detector."""

from html import escape
from urllib.parse import parse_qs

from detector import analyse_request, load_request
from workers import Response, WorkerEntrypoint


EXAMPLE = '{\n  "method": "POST",\n  "path": "/api/v1/users/search",\n  "body": {\n    "username": "admin\' OR 1=1--"\n  }\n}'


def _page(request_json: str, result: dict | None = None, error: str | None = None) -> str:
    result_html = f"<pre>{escape(str(result))}</pre>" if result is not None else ""
    error_html = f'<p class="error">{escape(error)}</p>' if error else ""
    return f"""<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>API Attack Detector</title></head>
  <body>
    <h1>API Attack Detector</h1>
    <form method="post">
      <label for="request_json">Request JSON</label><br>
      <textarea id="request_json" name="request_json" rows="16" cols="80">{escape(request_json)}</textarea><br>
      <button type="submit">Analyse request</button>
    </form>
    {error_html}
    {result_html}
  </body>
</html>"""


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
