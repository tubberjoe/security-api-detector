from flask import Flask, render_template, request

from detector import analyse_request, load_request

app = Flask(__name__)

EXAMPLE = '{\n  "method": "POST",\n  "path": "/api/v1/users/search",\n  "body": {\n    "username": "admin\' OR 1=1--"\n  }\n}'


@app.route("/", methods=["GET", "POST"])
def index():
    request_json = request.form.get("request_json", EXAMPLE)
    result = None
    error = None
    if request.method == "POST":
        try:
            result = analyse_request(load_request(request_json))
        except (ValueError, TypeError) as exc:
            error = f"Invalid request JSON: {exc}"
    return render_template("index.html", request_json=request_json, result=result, error=error)


if __name__ == "__main__":
    app.run(debug=True)
