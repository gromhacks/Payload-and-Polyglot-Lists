import base64
import pickle
import time

import yaml
import jsonpickle
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/health")
def health():
    return "ok"


@app.route("/pickle", methods=["POST"])
def pickle_endpoint():
    user_input = request.form.get("input", "")
    start = time.perf_counter()
    try:
        obj = pickle.loads(base64.b64decode(user_input))
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": str(obj), "error": None, "time_ms": round(elapsed, 2)})
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": None, "error": str(e), "time_ms": round(elapsed, 2)})


@app.route("/yaml", methods=["POST"])
def yaml_endpoint():
    user_input = request.form.get("input", "")
    start = time.perf_counter()
    try:
        obj = yaml.load(user_input, Loader=yaml.Loader)
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": str(obj), "error": None, "time_ms": round(elapsed, 2)})
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": None, "error": str(e), "time_ms": round(elapsed, 2)})


@app.route("/jsonpickle", methods=["POST"])
def jsonpickle_endpoint():
    user_input = request.form.get("input", "")
    start = time.perf_counter()
    try:
        obj = jsonpickle.decode(user_input)
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": str(obj), "error": None, "time_ms": round(elapsed, 2)})
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": None, "error": str(e), "time_ms": round(elapsed, 2)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
