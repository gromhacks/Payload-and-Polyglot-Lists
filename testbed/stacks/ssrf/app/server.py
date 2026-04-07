import time

import requests as http_requests
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/health")
def health():
    return "ok"


@app.route("/fetch", methods=["POST"])
def fetch_endpoint():
    user_input = request.form.get("input", "")
    start = time.perf_counter()
    try:
        output = http_requests.get(user_input, timeout=5).text
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": output, "error": None, "time_ms": round(elapsed, 2)})
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": None, "error": str(e), "time_ms": round(elapsed, 2)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
