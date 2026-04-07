"""SSI/ESI injection testbed. Simulates server-side include parsing."""

import re
import time
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)


def process_ssi(text):
    """Parse and execute SSI directives in text."""
    variables = {}
    output_parts = []

    # Process <!--#set var="name" value="val" -->
    def handle_set(m):
        variables[m.group(1)] = m.group(2)
        return ''

    # Process <!--#echo var="name" -->
    def handle_echo(m):
        return variables.get(m.group(1), '(none)')

    # Process <!--#exec cmd="command" -->
    def handle_exec(m):
        try:
            result = subprocess.check_output(
                m.group(1), shell=True, stderr=subprocess.STDOUT, timeout=10
            )
            return result.decode(errors='replace').strip()
        except Exception as e:
            return f'[exec error: {e}]'

    # Process <!--#include virtual="path" -->
    def handle_include(m):
        try:
            with open(m.group(1)) as f:
                return f.read()
        except Exception as e:
            return f'[include error: {e}]'

    text = re.sub(r'<!--#set\s+var="([^"]+)"\s+value="([^"]*?)"\s*-->', handle_set, text)
    text = re.sub(r'<!--#echo\s+var="([^"]+)"\s*-->', handle_echo, text)
    text = re.sub(r'<!--#exec\s+cmd="([^"]*?)"\s*-->', handle_exec, text)
    text = re.sub(r'<!--#include\s+virtual="([^"]*?)"\s*-->', handle_include, text)

    return text, variables


@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})


@app.route('/ssi', methods=['POST'])
def ssi():
    start = time.time()
    user_input = request.form.get('input', '')
    try:
        output, variables = process_ssi(user_input)
        elapsed = (time.time() - start) * 1000
        return jsonify({
            'output': output.strip(),
            'error': None,
            'time_ms': round(elapsed, 2),
        })
    except Exception as e:
        elapsed = (time.time() - start) * 1000
        return jsonify({
            'output': '',
            'error': str(e),
            'time_ms': round(elapsed, 2),
        })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
