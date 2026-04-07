import json
import os
import time

from elasticsearch import Elasticsearch
from flask import Flask, request, jsonify

app = Flask(__name__)

ES_HOST = os.environ.get("ES_HOST", "elasticsearch")
es = Elasticsearch([f"http://{ES_HOST}:9200"])

INDEX = "testbed"

SEED_DOCS = [
    {"name": "admin", "role": "admin", "id": 1},
    {"name": "user", "role": "user", "id": 2},
    {"name": "guest", "role": "guest", "id": 3},
]


def init_es():
    max_retries = 30
    for i in range(max_retries):
        try:
            if es.ping():
                break
        except Exception as e:
            print(f"Attempt {i + 1}/{max_retries} - waiting for Elasticsearch: {e}")
        time.sleep(2)
    else:
        raise RuntimeError("Could not connect to Elasticsearch after 30 attempts")

    if not es.indices.exists(index=INDEX):
        es.indices.create(index=INDEX)
        for doc in SEED_DOCS:
            es.index(index=INDEX, body=doc, refresh=True)
        print("Index created and seeded.")
    else:
        print("Index already exists.")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/search", methods=["POST"])
def search():
    start = time.time()
    raw_input = request.form.get("input", "{}")
    try:
        try:
            body = json.loads(raw_input)
        except (json.JSONDecodeError, ValueError):
            body = {"query": {"query_string": {"query": raw_input}}}

        result = es.search(index=INDEX, body=body)
        hits = result.get("hits", {}).get("hits", [])
        output_parts = []
        for h in hits:
            entry = h.get("_source", {})
            if "fields" in h:
                entry.update(h["fields"])
            output_parts.append(entry)
        elapsed = (time.time() - start) * 1000
        return jsonify({"output": str(output_parts), "error": None, "time_ms": round(elapsed, 2)})
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        return jsonify({"output": "", "error": str(e), "time_ms": round(elapsed, 2)})


@app.route("/script", methods=["POST"])
def script():
    start = time.time()
    raw_input = request.form.get("input", "")
    try:
        body = {
            "script_fields": {
                "result": {
                    "script": {
                        "source": raw_input
                    }
                }
            }
        }
        result = es.search(index=INDEX, body=body)
        hits = result.get("hits", {}).get("hits", [])
        output_parts = []
        for h in hits:
            fields = h.get("fields", {})
            output_parts.append(fields)
        elapsed = (time.time() - start) * 1000
        return jsonify({"output": str(output_parts), "error": None, "time_ms": round(elapsed, 2)})
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        return jsonify({"output": "", "error": str(e), "time_ms": round(elapsed, 2)})


if __name__ == "__main__":
    init_es()
    app.run(host="0.0.0.0", port=8080)
