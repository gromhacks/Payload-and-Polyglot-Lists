import os
import time
import json
from flask import Flask, request, jsonify
from neo4j import GraphDatabase

app = Flask(__name__)

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASS = os.environ.get("NEO4J_PASS", "testbed123")

driver = None

SEED_USERS = [
    {"name": "admin", "role": "admin", "password": "secret123"},
    {"name": "user", "role": "user", "password": "password"},
    {"name": "guest", "role": "guest", "password": "guestpass"},
]


def wait_for_neo4j():
    global driver
    max_retries = 30
    for i in range(max_retries):
        try:
            driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
            driver.verify_connectivity()
            print("Connected to Neo4j.")
            return
        except Exception as e:
            print(f"Attempt {i + 1}/{max_retries} - waiting for Neo4j: {e}")
            time.sleep(2)
    raise RuntimeError("Could not connect to Neo4j after 30 attempts")


def seed_data():
    with driver.session() as session:
        count = session.run("MATCH (u:User) RETURN count(u) AS c").single()["c"]
        if count == 0:
            for u in SEED_USERS:
                session.run(
                    "CREATE (u:User {name: $name, role: $role, password: $password})",
                    name=u["name"],
                    role=u["role"],
                    password=u["password"],
                )
            print("Seed data created.")
        else:
            print("Seed data already exists.")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/query", methods=["POST"])
def query():
    start = time.time()
    user_input = request.form.get("input", "")
    try:
        # Intentionally vulnerable: string concatenation
        cypher = f"MATCH (u:User) WHERE u.name = '{user_input}' RETURN u"
        with driver.session() as session:
            result = session.run(cypher)
            records = [dict(record["u"]) for record in result]
        elapsed = (time.time() - start) * 1000
        return jsonify({"output": json.dumps(records), "error": None, "time_ms": round(elapsed, 2)})
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        return jsonify({"output": "", "error": str(e), "time_ms": round(elapsed, 2)})


@app.route("/search", methods=["POST"])
def search():
    start = time.time()
    user_input = request.form.get("input", "")
    try:
        # Intentionally vulnerable: string concatenation
        cypher = f"MATCH (u:User) WHERE u.name CONTAINS '{user_input}' RETURN u"
        with driver.session() as session:
            result = session.run(cypher)
            records = [dict(record["u"]) for record in result]
        elapsed = (time.time() - start) * 1000
        return jsonify({"output": json.dumps(records), "error": None, "time_ms": round(elapsed, 2)})
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        return jsonify({"output": "", "error": str(e), "time_ms": round(elapsed, 2)})


if __name__ == "__main__":
    wait_for_neo4j()
    seed_data()
    app.run(host="0.0.0.0", port=8080)
