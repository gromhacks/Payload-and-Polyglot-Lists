#!/usr/bin/env python3
"""SQLi testbed - SQLite. Intentionally vulnerable."""
import sqlite3
import time
from flask import Flask, request, jsonify

app = Flask(__name__)

DB_PATH = '/tmp/testbed.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, password TEXT)')
    conn.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin@test.com', 'secret123')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'user@test.com', 'password')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (3, 'guest', 'guest@test.com', 'guest')")
    conn.commit()
    conn.close()

def get_db():
    return sqlite3.connect(DB_PATH)

init_db()

@app.route('/sqli', methods=['POST'])
def sqli():
    user_input = request.form.get('input', '')
    start = time.time()
    try:
        # Intentionally vulnerable: string concatenation in SQL
        query = f"SELECT * FROM users WHERE name = '{user_input}'"
        conn = get_db()
        cursor = conn.execute(query)
        rows = cursor.fetchall()
        elapsed = (time.time() - start) * 1000
        return jsonify(output=str(rows), error=None, time_ms=round(elapsed, 2))
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        return jsonify(output=None, error=str(e), time_ms=round(elapsed, 2))

@app.route('/sqli-numeric', methods=['POST'])
def sqli_numeric():
    user_input = request.form.get('input', '')
    start = time.time()
    try:
        query = f"SELECT * FROM users WHERE id = {user_input}"
        conn = get_db()
        cursor = conn.execute(query)
        rows = cursor.fetchall()
        elapsed = (time.time() - start) * 1000
        return jsonify(output=str(rows), error=None, time_ms=round(elapsed, 2))
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        return jsonify(output=None, error=str(e), time_ms=round(elapsed, 2))

@app.route('/health', methods=['GET'])
def health():
    return 'ok'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
