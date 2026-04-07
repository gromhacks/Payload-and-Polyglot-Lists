import time
import json
from flask import Flask, request, jsonify
from lxml import etree

app = Flask(__name__)

SOURCE_XML = b"<root><data>test</data></root>"

WRAPPER_TEMPLATE = (
    '<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">'
    '<xsl:template match="/">{fragment}</xsl:template>'
    '</xsl:stylesheet>'
)


def parse_source():
    return etree.fromstring(SOURCE_XML)


@app.route("/transform", methods=["POST"])
def transform():
    raw = request.form.get("input", "")
    start = time.time()
    output = ""
    error = None

    try:
        stripped = raw.strip()
        xslt_str = None

        # If it looks like a complete stylesheet, use it directly
        if stripped.startswith("<xsl:stylesheet") or stripped.startswith("<?xml"):
            xslt_str = stripped
        else:
            # Wrap the fragment in a minimal stylesheet
            xslt_str = WRAPPER_TEMPLATE.format(fragment=stripped)

        xslt_doc = etree.fromstring(xslt_str.encode("utf-8"))
        transform_fn = etree.XSLT(xslt_doc)
        source_doc = parse_source()
        result = transform_fn(source_doc)
        output = str(result)
    except Exception as e:
        error = str(e)

    elapsed = int((time.time() - start) * 1000)
    return jsonify({"output": output, "error": error, "time_ms": elapsed})


@app.route("/xpath", methods=["POST"])
def xpath():
    raw = request.form.get("input", "")
    start = time.time()
    output = ""
    error = None

    try:
        source_doc = parse_source()
        xpath_expr = etree.XPath(raw)
        result = xpath_expr(source_doc)

        if isinstance(result, list):
            parts = []
            for item in result:
                if isinstance(item, etree._Element):
                    parts.append(etree.tostring(item, encoding="unicode"))
                else:
                    parts.append(str(item))
            output = "\n".join(parts)
        else:
            output = str(result)
    except Exception as e:
        error = str(e)

    elapsed = int((time.time() - start) * 1000)
    return jsonify({"output": output, "error": error, "time_ms": elapsed})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
