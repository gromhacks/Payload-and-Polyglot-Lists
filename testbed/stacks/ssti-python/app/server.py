import time

import jinja2
import mako.template
import tornado.template
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/health")
def health():
    return "ok"


@app.route("/jinja2", methods=["POST"])
def jinja2_endpoint():
    user_input = request.form.get("input", "")
    start = time.perf_counter()
    try:
        output = jinja2.Environment().from_string(user_input).render()
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": output, "error": None, "time_ms": round(elapsed, 2)})
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": None, "error": str(e), "time_ms": round(elapsed, 2)})


@app.route("/mako", methods=["POST"])
def mako_endpoint():
    user_input = request.form.get("input", "")
    start = time.perf_counter()
    try:
        output = mako.template.Template(user_input).render()
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": output, "error": None, "time_ms": round(elapsed, 2)})
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": None, "error": str(e), "time_ms": round(elapsed, 2)})


@app.route("/tornado", methods=["POST"])
def tornado_endpoint():
    user_input = request.form.get("input", "")
    start = time.perf_counter()
    try:
        output = tornado.template.Template(user_input).generate()
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": output.decode("utf-8", errors="replace"), "error": None, "time_ms": round(elapsed, 2)})
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": None, "error": str(e), "time_ms": round(elapsed, 2)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
