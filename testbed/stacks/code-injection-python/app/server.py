import time

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/health")
def health():
    return "ok"


@app.route("/eval", methods=["POST"])
def eval_endpoint():
    user_input = request.form.get("input", "")
    start = time.perf_counter()
    try:
        result = eval(user_input)
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": str(result), "error": None, "time_ms": round(elapsed, 2)})
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": None, "error": str(e), "time_ms": round(elapsed, 2)})


@app.route("/exec", methods=["POST"])
def exec_endpoint():
    user_input = request.form.get("input", "")
    start = time.perf_counter()
    try:
        namespace = {}
        exec(user_input, namespace)
        output = str(namespace.get("result", ""))
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": output, "error": None, "time_ms": round(elapsed, 2)})
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": None, "error": str(e), "time_ms": round(elapsed, 2)})


@app.route("/import", methods=["POST"])
def import_endpoint():
    """eval with __import__ available (documents intent for import-based code injection)."""
    user_input = request.form.get("input", "")
    start = time.perf_counter()
    try:
        result = eval(user_input, {"__builtins__": {"__import__": __import__}})
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": str(result), "error": None, "time_ms": round(elapsed, 2)})
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": None, "error": str(e), "time_ms": round(elapsed, 2)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
