import os
import time
import json

import ldap
from flask import Flask, request, jsonify

app = Flask(__name__)

LDAP_HOST = os.environ.get("LDAP_HOST", "ldap")
LDAP_URI = f"ldap://{LDAP_HOST}:389"
BASE_DN = "dc=testbed,dc=local"
ADMIN_DN = "cn=admin,dc=testbed,dc=local"
ADMIN_PW = "admin"
USERS_OU = f"ou=users,{BASE_DN}"

SEED_USERS = [
    {
        "dn": f"uid=admin,{USERS_OU}",
        "attrs": {
            "objectClass": [b"inetOrgPerson"],
            "uid": [b"admin"],
            "cn": [b"admin"],
            "sn": [b"Administrator"],
            "userPassword": [b"secret123"],
            "description": [b"Admin account"],
        },
    },
    {
        "dn": f"uid=user,{USERS_OU}",
        "attrs": {
            "objectClass": [b"inetOrgPerson"],
            "uid": [b"user"],
            "cn": [b"user"],
            "sn": [b"Regular User"],
            "userPassword": [b"password"],
            "description": [b"Standard user"],
        },
    },
    {
        "dn": f"uid=guest,{USERS_OU}",
        "attrs": {
            "objectClass": [b"inetOrgPerson"],
            "uid": [b"guest"],
            "cn": [b"guest"],
            "sn": [b"Guest User"],
            "userPassword": [b"guest"],
            "description": [b"Guest account"],
        },
    },
]


def get_conn():
    conn = ldap.initialize(LDAP_URI)
    conn.simple_bind_s(ADMIN_DN, ADMIN_PW)
    return conn


def seed_data():
    max_retries = 30
    for attempt in range(max_retries):
        try:
            conn = get_conn()
            # Create OU if it doesn't exist
            try:
                conn.add_s(
                    USERS_OU,
                    [
                        ("objectClass", [b"organizationalUnit"]),
                        ("ou", [b"users"]),
                    ],
                )
            except ldap.ALREADY_EXISTS:
                pass

            for user in SEED_USERS:
                try:
                    conn.add_s(user["dn"], list(user["attrs"].items()))
                except ldap.ALREADY_EXISTS:
                    pass

            conn.unbind_s()
            print("LDAP seed data initialized.")
            return
        except ldap.SERVER_DOWN:
            print(f"Attempt {attempt + 1}/{max_retries} - waiting for LDAP server...")
            time.sleep(2)

    raise RuntimeError("Could not connect to LDAP server after retries")


def format_results(results):
    """Convert LDAP result tuples into JSON-serializable list."""
    formatted = []
    for dn, attrs in results:
        if dn is None:
            continue
        entry = {"dn": dn}
        for key, values in attrs.items():
            entry[key] = [v.decode("utf-8", errors="replace") for v in values]
        formatted.append(entry)
    return formatted


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/search", methods=["POST"])
def search():
    user_input = request.form.get("input", "")
    # Intentionally vulnerable: direct string concatenation
    ldap_filter = f"(cn={user_input})"
    start = time.time()
    try:
        conn = get_conn()
        results = conn.search_s(BASE_DN, ldap.SCOPE_SUBTREE, ldap_filter)
        conn.unbind_s()
        elapsed = (time.time() - start) * 1000
        output = json.dumps(format_results(results))
        return jsonify({"output": output, "error": None, "time_ms": round(elapsed, 2)})
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        return jsonify({"output": "", "error": str(e), "time_ms": round(elapsed, 2)})


@app.route("/auth", methods=["POST"])
def auth():
    user_input = request.form.get("input", "")
    # Intentionally vulnerable: direct string concatenation in auth filter
    ldap_filter = f"(&(uid={user_input})(userPassword=test))"
    start = time.time()
    try:
        conn = get_conn()
        results = conn.search_s(BASE_DN, ldap.SCOPE_SUBTREE, ldap_filter)
        conn.unbind_s()
        elapsed = (time.time() - start) * 1000
        output = json.dumps(format_results(results))
        return jsonify({"output": output, "error": None, "time_ms": round(elapsed, 2)})
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        return jsonify({"output": "", "error": str(e), "time_ms": round(elapsed, 2)})


if __name__ == "__main__":
    seed_data()
    app.run(host="0.0.0.0", port=8080)
