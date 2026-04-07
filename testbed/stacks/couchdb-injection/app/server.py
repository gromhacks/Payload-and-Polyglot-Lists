import json
import os
import time

import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

COUCHDB_URL = os.environ.get("COUCHDB_URL", "http://admin:testbed@couchdb:5984")
DB_NAME = "testbed"
DB_URL = f"{COUCHDB_URL}/{DB_NAME}"


def init_db():
    """Create the testbed database and seed documents."""
    for _ in range(30):
        try:
            r = requests.get(f"{COUCHDB_URL}/_up", timeout=3)
            if r.status_code == 200:
                break
        except Exception:
            pass
        time.sleep(1)

    # Create database (ignore if exists)
    requests.put(DB_URL)

    # Seed documents
    seed_docs = [
        {"name": "admin", "role": "admin", "password": "s3cret"},
        {"name": "user", "role": "user", "password": "password123"},
        {"name": "guest", "role": "guest", "password": "guest"},
    ]
    for doc in seed_docs:
        # Check if doc already exists by name
        resp = requests.post(
            f"{DB_URL}/_find",
            json={"selector": {"name": doc["name"]}, "limit": 1},
            headers={"Content-Type": "application/json"},
        )
        if resp.ok and not resp.json().get("docs"):
            requests.post(
                DB_URL,
                json=doc,
                headers={"Content-Type": "application/json"},
            )


@app.route("/find", methods=["POST"])
def find():
    start = time.time()
    try:
        raw_input = request.form.get("input", "")
        if not raw_input:
            raw_input = request.get_data(as_text=True)

        # Try to parse as JSON
        try:
            parsed = json.loads(raw_input)
        except json.JSONDecodeError as e:
            elapsed = int((time.time() - start) * 1000)
            return jsonify({"output": "", "error": f"JSON parse error: {str(e)}", "time_ms": elapsed})

        # If parsed input has "selector" key, treat as full Mango query
        if isinstance(parsed, dict) and "selector" in parsed:
            query = parsed
        else:
            # Wrap simple value as selector
            query = {"selector": parsed}

        resp = requests.post(
            f"{DB_URL}/_find",
            json=query,
            headers={"Content-Type": "application/json"},
            timeout=30,
        )

        elapsed = int((time.time() - start) * 1000)

        if resp.ok:
            docs = resp.json().get("docs", [])
            return jsonify({"output": str(docs), "error": None, "time_ms": elapsed})
        else:
            return jsonify({"output": "", "error": resp.text, "time_ms": elapsed})

    except Exception as e:
        elapsed = int((time.time() - start) * 1000)
        return jsonify({"output": "", "error": str(e), "time_ms": elapsed})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8080)
