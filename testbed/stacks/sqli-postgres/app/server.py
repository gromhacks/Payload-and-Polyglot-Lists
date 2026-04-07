import time
import psycopg2
from flask import Flask, jsonify, request

app = Flask(__name__)

DB_CONFIG = {
    "host": "postgres",
    "port": 5432,
    "dbname": "testbed",
    "user": "postgres",
    "password": "testbed",
}


def get_conn():
    return psycopg2.connect(**DB_CONFIG)


def init_db():
    """Create users table and seed data, with retry logic for postgres startup."""
    import time as _time

    for attempt in range(30):
        try:
            conn = get_conn()
            conn.autocommit = True
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    role TEXT NOT NULL
                )
                """
            )
            cur.execute("SELECT count(*) FROM users")
            if cur.fetchone()[0] == 0:
                cur.execute(
                    "INSERT INTO users (name, role) VALUES (%s, %s), (%s, %s), (%s, %s)",
                    ("admin", "administrator", "user", "standard", "guest", "readonly"),
                )
            cur.close()
            conn.close()
            print("Database initialized successfully.")
            return
        except Exception as e:
            print(f"DB init attempt {attempt + 1}/30 failed: {e}")
            _time.sleep(2)
    raise RuntimeError("Could not connect to postgres after 30 attempts")


@app.route("/health")
def health():
    return "ok"


@app.route("/sqli", methods=["POST"])
def sqli():
    user_input = request.form.get("input", "")
    start = time.perf_counter()
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
        rows = cur.fetchall()
        output = str(rows)
        cur.close()
        conn.close()
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": output, "error": None, "time_ms": round(elapsed, 2)})
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": None, "error": str(e), "time_ms": round(elapsed, 2)})


@app.route("/sqli-numeric", methods=["POST"])
def sqli_numeric():
    user_input = request.form.get("input", "")
    start = time.perf_counter()
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(f"SELECT * FROM users WHERE id = {user_input}")
        rows = cur.fetchall()
        output = str(rows)
        cur.close()
        conn.close()
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": output, "error": None, "time_ms": round(elapsed, 2)})
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": None, "error": str(e), "time_ms": round(elapsed, 2)})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8080)
