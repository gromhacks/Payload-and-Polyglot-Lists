import os
import time
import json
import pymysql
from flask import Flask, request, jsonify

app = Flask(__name__)

DB_HOST = os.environ.get("DB_HOST", "mysql")
DB_USER = "root"
DB_PASS = "testbed"
DB_NAME = "testbed"


def get_connection():
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME,
        cursorclass=pymysql.cursors.DictCursor,
    )


def init_db():
    for attempt in range(30):
        try:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute(
                """CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(255) NOT NULL,
                    email VARCHAR(255),
                    password VARCHAR(255),
                    role VARCHAR(50)
                )"""
            )
            cursor.execute("SELECT COUNT(*) AS cnt FROM users")
            if cursor.fetchone()["cnt"] == 0:
                cursor.execute(
                    "INSERT INTO users (name, email, password, role) VALUES "
                    "('admin', 'admin@test.com', 'secret123', 'admin'), "
                    "('user', 'user@test.com', 'password', 'user'), "
                    "('guest', 'guest@test.com', 'guest', 'guest')"
                )
            conn.commit()
            conn.close()
            print("Database initialized successfully.")
            return
        except Exception as e:
            print(f"Attempt {attempt + 1}/30 - waiting for MySQL: {e}")
            time.sleep(2)
    raise RuntimeError("Could not connect to MySQL after 30 attempts")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/sqli", methods=["POST"])
def sqli():
    start = time.time()
    user_input = request.form.get("input", "")
    try:
        conn = get_connection()
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE name = '{user_input}'"
        cursor.execute(query)
        rows = cursor.fetchall()
        conn.close()
        elapsed = (time.time() - start) * 1000
        return jsonify({"output": json.dumps(rows, default=str), "error": None, "time_ms": round(elapsed, 2)})
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        return jsonify({"output": "", "error": str(e), "time_ms": round(elapsed, 2)})


@app.route("/sqli-numeric", methods=["POST"])
def sqli_numeric():
    start = time.time()
    user_input = request.form.get("input", "")
    try:
        conn = get_connection()
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE id = {user_input}"
        cursor.execute(query)
        rows = cursor.fetchall()
        conn.close()
        elapsed = (time.time() - start) * 1000
        return jsonify({"output": json.dumps(rows, default=str), "error": None, "time_ms": round(elapsed, 2)})
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        return jsonify({"output": "", "error": str(e), "time_ms": round(elapsed, 2)})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8080)
