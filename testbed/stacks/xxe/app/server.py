import time
import urllib.request

from lxml import etree
from flask import Flask, jsonify, request

app = Flask(__name__)


class HTTPResolver(etree.Resolver):
    """Custom resolver that fetches HTTP/HTTPS URLs (libxml2 2.14+ dropped HTTP I/O)."""
    def resolve(self, system_url, public_id, context):
        if system_url and (system_url.startswith('http://') or system_url.startswith('https://')):
            try:
                data = urllib.request.urlopen(system_url, timeout=5).read()
                return self.resolve_string(data, context)
            except Exception:
                return self.resolve_string(b'', context)
        return None


http_resolver = HTTPResolver()


@app.route("/health")
def health():
    return "ok"


@app.route("/parse", methods=["POST"])
def parse_endpoint():
    user_input = request.form.get("input", "")
    start = time.perf_counter()
    try:
        parser = etree.XMLParser(resolve_entities=True, no_network=False, load_dtd=True)
        parser.resolvers.add(http_resolver)
        tree = etree.fromstring(user_input.encode("utf-8"), parser)
        output = etree.tostring(tree, pretty_print=True).decode("utf-8", errors="replace")
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": output, "error": None, "time_ms": round(elapsed, 2)})
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": None, "error": str(e), "time_ms": round(elapsed, 2)})


@app.route("/xinclude", methods=["POST"])
def xinclude_endpoint():
    user_input = request.form.get("input", "")
    start = time.perf_counter()
    try:
        parser = etree.XMLParser(resolve_entities=True, no_network=False, load_dtd=True)
        parser.resolvers.add(http_resolver)
        tree = etree.fromstring(user_input.encode("utf-8"), parser)
        tree.getroottree().xinclude()
        output = etree.tostring(tree, pretty_print=True).decode("utf-8", errors="replace")
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": output, "error": None, "time_ms": round(elapsed, 2)})
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return jsonify({"output": None, "error": str(e), "time_ms": round(elapsed, 2)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
