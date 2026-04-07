import os
import subprocess
import tempfile
import time

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/health")
def health():
    return "ok"


@app.route("/system", methods=["POST"])
def system_endpoint():
    user_input = request.form.get("input", "")
    start = time.perf_counter()
    try:
        tmp = tempfile.mktemp()
        os.system(f"{user_input} > {tmp} 2>&1")
        with open(tmp, "r") as f:
            output = f.read()
        os.unlink(tmp)
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": output, "error": None, "time_ms": round(elapsed, 2)})
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": None, "error": str(e), "time_ms": round(elapsed, 2)})


@app.route("/popen", methods=["POST"])
def popen_endpoint():
    user_input = request.form.get("input", "")
    start = time.perf_counter()
    try:
        output = os.popen(user_input).read()
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": output, "error": None, "time_ms": round(elapsed, 2)})
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": None, "error": str(e), "time_ms": round(elapsed, 2)})


@app.route("/subprocess", methods=["POST"])
def subprocess_endpoint():
    user_input = request.form.get("input", "")
    start = time.perf_counter()
    try:
        output = subprocess.check_output(user_input, shell=True, stderr=subprocess.STDOUT)
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": output.decode("utf-8", errors="replace"), "error": None, "time_ms": round(elapsed, 2)})
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": None, "error": str(e), "time_ms": round(elapsed, 2)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
