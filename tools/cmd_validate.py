"""Unified payload validation against running testbed endpoints."""

import os
import re
import time
import requests

OOB_URL = 'http://localhost:9999'

# Endpoint mapping: category -> [urls]
ENDPOINTS = {
    'sqli': [
        'http://localhost:8001/sqli', 'http://localhost:8001/sqli-numeric',
        'http://localhost:8030/sqli', 'http://localhost:8050/sqli',
    ],
    'ssti': [
        'http://localhost:8003/jinja2', 'http://localhost:8003/mako',
        'http://localhost:8003/tornado', 'http://localhost:8011/ejs',
        'http://localhost:8011/nunjucks', 'http://localhost:8011/pug',
        'http://localhost:8020/twig', 'http://localhost:8020/smarty',
        'http://localhost:8025/erb', 'http://localhost:8040/freemarker',
        'http://localhost:8040/velocity', 'http://localhost:8040/pebble',
    ],
    'os-cmd': ['http://localhost:8002/system', 'http://localhost:8002/popen'],
    'code-injection': [
        'http://localhost:8004/eval', 'http://localhost:8012/eval',
        'http://localhost:8021/eval', 'http://localhost:8026/eval',
        'http://localhost:8031/eval',
    ],
    'xss': ['http://localhost:8010/reflected'],
    'xxe': ['http://localhost:8008/parse', 'http://localhost:8008/xinclude'],
    'ssrf': ['http://localhost:8007/fetch'],
    'path-traversal': ['http://localhost:8006/read'],
    'nosql': ['http://localhost:8015/eval', 'http://localhost:8051/where'],
    'el-injection': ['http://localhost:8041/spel', 'http://localhost:8041/ognl'],
    'prototype-pollution': ['http://localhost:8013/merge'],
    'crlf': ['http://localhost:8010/reflected'],
    # Deserialization
    'deser-python': ['http://localhost:8005/pickle'],
    'deser-python-yaml': ['http://localhost:8005/yaml'],
    'deser-python-jsonpickle': ['http://localhost:8005/jsonpickle'],
    'deser-node': ['http://localhost:8014/unserialize'],
    'deser-node-yaml': ['http://localhost:8014/yaml'],
    'deser-node-funcster': ['http://localhost:8014/funcster'],
    'deser-php': ['http://localhost:8022/unserialize'],
    'deser-ruby-yaml': ['http://localhost:8026/yaml'],
    'deser-ruby-marshal': ['http://localhost:8026/marshal'],
    'deser-ruby-oj': ['http://localhost:8026/oj'],
    'deser-perl-storable': ['http://localhost:8031/storable'],
    'deser-perl-yaml': ['http://localhost:8031/yaml'],
    'deser-java': ['http://localhost:8042/deserialize'],
    'deser-java-yaml': ['http://localhost:8042/yaml'],
    'deser-java-jackson': ['http://localhost:8042/jackson'],
    'deser-java-fastjson': ['http://localhost:8042/fastjson'],
    'deser-java-xstream': ['http://localhost:8042/xstream'],
    'deser-java-xmldecoder': ['http://localhost:8042/xmldecoder'],
    'deser-java-hessian': ['http://localhost:8042/hessian'],
    'deser-dotnet': ['http://localhost:8045/jsonnet'],
    'deser-jndi': ['http://localhost:8046/log'],
    'ssi-esi': ['http://localhost:8035/ssi'],
    'ldap': ['http://localhost:8055/search', 'http://localhost:8055/auth'],
    'xslt': ['http://localhost:8056/transform', 'http://localhost:8056/xpath'],
    'elasticsearch': ['http://localhost:8057/search', 'http://localhost:8057/script'],
    'cypher': ['http://localhost:8058/query', 'http://localhost:8058/search'],
    'couchdb': ['http://localhost:8059/find'],
    'groovy': ['http://localhost:8060/eval'],
    # Edge-case fallback
    'edge-cases': ['http://localhost:8004/eval', 'http://localhost:8001/sqli', 'http://localhost:8012/eval'],
}

# Engine-specific header -> endpoint override
ENGINE_MAP = {
    'Tornado': ['http://localhost:8003/tornado'],
    'Nunjucks': ['http://localhost:8011/nunjucks'],
    'Pug': ['http://localhost:8011/pug'],
    'Smarty': ['http://localhost:8020/smarty'],
    'Blade': ['http://localhost:8020/blade'],
    'ERB (Ruby)': ['http://localhost:8025/erb'],
    'Slim (Ruby)': ['http://localhost:8025/slim'],
    'Haml (Ruby)': ['http://localhost:8025/haml'],
    'Thymeleaf': ['http://localhost:8040/thymeleaf'],
    'Pebble': ['http://localhost:8040/pebble'],
    'Freemarker': ['http://localhost:8040/freemarker'],
    'Velocity': ['http://localhost:8040/velocity'],
    'Mustache': ['http://localhost:8011/nunjucks'],
    'Liquid': ['http://localhost:8011/nunjucks'],
    'Lua Code': ['http://localhost:8004/eval'],
    'PHP Code Injection': ['http://localhost:8021/eval'],
    'Perl Code Injection': ['http://localhost:8031/eval'],
    'Java ScriptEngine': ['http://localhost:8041/spel', 'http://localhost:8040/freemarker'],
    'Razor': ['http://localhost:8004/eval'],
    'Go text/template': ['http://localhost:8011/nunjucks'],
    'Format String.*C/C': ['http://localhost:8004/eval'],
    'Format String.*Python': ['http://localhost:8004/eval'],
    'Format String.*\\.NET': ['http://localhost:8004/eval'],
    'Format String.*Overflow': ['http://localhost:8004/eval'],
}


def _get_endpoints(header):
    """Route a section header to testbed endpoints."""
    clean = header.strip('#').strip()

    # Engine-specific
    for engine, urls in ENGINE_MAP.items():
        if engine in clean:
            return urls, engine

    # Category patterns (order matters)
    ROUTES = [
        (r'SQLi|SQLite|PostgreSQL|CockroachDB', 'sqli'),
        (r'SSTI', 'ssti'),
        (r'OS Cmd', 'os-cmd'),
        (r'Groovy', 'groovy'),
        (r'MVEL', 'el-injection'),
        (r'Code Injection', 'code-injection'),
        (r'XSS', 'xss'),
        (r'XXE', 'xxe'),
        (r'LDAP Injection', 'ldap'),
        (r'XSLT', 'xslt'),
        (r'Elasticsearch|Elastic|Painless|Query String Injection', 'elasticsearch'),
        (r'Cypher|Neo4j', 'cypher'),
        (r'CouchDB|Mango', 'couchdb'),
        (r'SSI|ESI', 'ssi-esi'),
        (r'SSRF|Cloud|IP Bypass|Protocol|URL Tricks', 'ssrf'),
        (r'Traversal|Encoding Bypass|Null Byte|Target Files|PHP Wrappers|Path Traversal', 'path-traversal'),
        (r'NoSQL', 'nosql'),
        (r'EL Injection', 'el-injection'),
        (r'Prototype', 'prototype-pollution'),
        (r'CRLF', 'crlf'),
        (r'Format String', 'code-injection'),
        # Deserialization
        (r'Python Pickle', 'deser-python'),
        (r'Python YAML', 'deser-python-yaml'),
        (r'Python jsonpickle', 'deser-python-jsonpickle'),
        (r'Node node-serialize', 'deser-node'),
        (r'Node js-yaml', 'deser-node-yaml'),
        (r'Node funcster', 'deser-node-funcster'),
        (r'Node cryo', 'deser-node'),
        (r'PHP Unserialize|PHP Phar', 'deser-php'),
        (r'Ruby YAML', 'deser-ruby-yaml'),
        (r'Ruby Marshal', 'deser-ruby-marshal'),
        (r'Ruby Oj', 'deser-ruby-oj'),
        (r'Java JNDI', 'deser-jndi'),
        (r'Java Jackson', 'deser-java-jackson'),
        (r'Java Fastjson|Fastjson', 'deser-java-fastjson'),
        (r'Java XStream|XStream', 'deser-java-xstream'),
        (r'SnakeYAML', 'deser-java-yaml'),
        (r'XMLDecoder', 'deser-java-xmldecoder'),
        (r'Java Hessian', 'deser-java-hessian'),
        (r'Java Serialized|ysoserial', 'deser-java'),
        (r'\.NET', 'deser-dotnet'),
        (r'Perl Storable', 'deser-perl-storable'),
        (r'Perl YAML', 'deser-perl-yaml'),
        # Polyglot routing
        (r'POLYGLOT.*SQLi', 'sqli'),
        (r'POLYGLOT.*SSTI', 'ssti'),
        (r'POLYGLOT.*OS Command', 'os-cmd'),
        (r'POLYGLOT.*Code Injection', 'code-injection'),
        (r'POLYGLOT.*XSS', 'xss'),
        (r'POLYGLOT.*XXE', 'xxe'),
        (r'POLYGLOT.*SSRF', 'ssrf'),
        (r'POLYGLOT.*Path Traversal', 'path-traversal'),
        (r'POLYGLOT.*NoSQL', 'nosql'),
        (r'POLYGLOT.*EL Injection', 'el-injection'),
        (r'POLYGLOT.*Prototype', 'prototype-pollution'),
        (r'POLYGLOT.*Header|POLYGLOT.*CRLF', 'crlf'),
        (r'POLYGLOT.*Deserialization', 'edge-cases'),
        (r'POLYGLOT.*Format', 'code-injection'),
        (r'POLYGLOT', 'edge-cases'),
    ]
    for pattern, cat in ROUTES:
        if re.search(pattern, clean):
            return ENDPOINTS.get(cat, ENDPOINTS['edge-cases']), cat

    return ENDPOINTS['edge-cases'], 'unknown'


def _clear_oob():
    try: requests.post(f'{OOB_URL}/clear', timeout=1)
    except: pass

def _check_oob():
    try: return len(requests.get(f'{OOB_URL}/callbacks', timeout=1).json()) > 0
    except: return False


def _check_fire(data, payload=''):
    """Check if a response indicates the payload fired."""
    pillars = []
    output = str(data.get('output', '') or '')
    error = data.get('error')
    time_ms = data.get('time_ms', 0) or 0

    if '1337' in output:
        pillars.append('math')
    if error is not None and error != '':
        pillars.append('error')
    if any(x in output for x in ['Warning', 'Error', 'Exception', 'Fatal', 'error', 'Traceback']):
        if 'error' not in pillars:
            pillars.append('error')
    if time_ms > 4500:
        pillars.append('timing')
    if data.get('_oob'):
        pillars.append('oob')
    if any(sig in output for sig in ['root:', '[extensions]', '[fonts]', 'daemon:', 'nobody:']):
        pillars.append('file-read')

    # Reflection detection
    if not pillars and payload:
        clean_payload = payload.strip()
        if output and len(clean_payload) >= 1 and clean_payload in output:
            pillars.append('reflected')
        if not pillars:
            try:
                evaluated = str(eval(clean_payload, {"__builtins__": {}}))
                if evaluated and evaluated in output:
                    pillars.append('reflected')
                elif clean_payload == '-0' and '0' in output:
                    pillars.append('reflected')
            except:
                pass
        if not pillars and clean_payload in ('""', "''", '``') and error is None:
            pillars.append('reflected')

    return pillars


def _fire_one(url, payload):
    """Send payload to one endpoint."""
    payload_sub = payload.replace('{domain}', 'oob:9999').replace('{DOMAIN}', 'oob:9999')
    if '/yaml' in url:
        payload_sub = payload_sub.replace('\\n', '\n')
    try:
        resp = requests.post(url, data={'input': payload_sub}, timeout=8)
        try: data = resp.json()
        except: data = {'output': resp.text[:500], 'error': None, 'time_ms': 0}
        return data
    except requests.exceptions.Timeout:
        return {'output': None, 'error': 'TIMEOUT', 'time_ms': 8000}
    except:
        return {'output': None, 'error': 'CONNECTION_ERROR', 'time_ms': 0}


def _fire_payload(endpoints, payload):
    """Fire payload at multiple endpoints, return first that fires."""
    _clear_oob()
    data = {}
    for url in endpoints:
        data = _fire_one(url, payload)
        if data.get('error') == 'CONNECTION_ERROR':
            continue
        time.sleep(0.05)
        if _check_oob():
            data['_oob'] = True
        pillars = _check_fire(data, payload)
        if pillars:
            return data, pillars
    return data, []


def run_validate(root, wordlist=None):
    """Validate payloads against running testbed endpoints."""
    full_path = wordlist or os.path.join(root, 'payloads', 'full.txt')
    with open(full_path) as f:
        lines = f.read().splitlines()

    fire = no_fire = skip = total = 0
    no_fires = []

    current_header = None
    current_endpoints = None
    current_cat = None

    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith('##'):
            current_header = line
            current_endpoints, current_cat = _get_endpoints(line)
            i += 1
            continue
        if not line.strip():
            i += 1
            continue

        # Multi-line YAML detection
        payload = line
        if current_cat and 'yaml' in current_cat:
            j = i + 1
            while j < len(lines) and not lines[j].startswith('##') and lines[j].strip():
                if lines[j].startswith('  ') or lines[j].startswith('\t'):
                    payload += '\n' + lines[j]
                    j += 1
                elif line.startswith('---') or line.startswith('!!'):
                    if ':' in lines[j] or '!' in lines[j]:
                        payload += '\n' + lines[j]
                        j += 1
                    else:
                        break
                else:
                    break
            i = j
        else:
            i += 1

        total += 1

        if current_endpoints is None:
            skip += 1
            continue

        data, pillars = _fire_payload(current_endpoints, payload)

        if pillars:
            fire += 1
        else:
            no_fire += 1
            h = (current_header or '').strip('#').strip()[:50]
            p = line[:60]
            no_fires.append((h, p, data))
            out = str(data.get('output', ''))[:60]
            err = str(data.get('error', ''))[:40]
            print(f"  NO-FIRE {h}: {p}")
            print(f"    out={out} err={err} t={data.get('time_ms',0)}")

    print(f"\n{'='*70}")
    print(f"RESULTS: {fire} FIRE / {no_fire} NO-FIRE / {skip} SKIPPED / {total} TOTAL")
    print(f"{'='*70}")

    if no_fires:
        print(f"\nNO-FIRE summary ({len(no_fires)} payloads):")
        cats = {}
        for h, p, d in no_fires:
            cat = h.split(' - ')[0] if ' - ' in h else h
            cats[cat] = cats.get(cat, 0) + 1
        for cat, count in sorted(cats.items(), key=lambda x: -x[1]):
            print(f"  {count:3d}  {cat}")
