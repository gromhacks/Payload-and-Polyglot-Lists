"""Generate distribution directory: full/ and minimal/ with matching structure."""

import os
import re
import shutil
import base64
import urllib.parse
import json as jsonlib

from cmd_build import SOURCE_FILES

# Pillar keywords in section headers
PILLAR_MAP = {
    'error': [r'Error', r'error'],
    'math': [r'Math.*1337|Canary.*1337'],
    'timing': [r'Timing|Time-Based|Time Based'],
    'oob': [r'OOB|Out-of-Band|Blind'],
}

# Category source files (relative paths)
CATEGORY_SOURCES = {
    'sqli': 'payloads/sources/sqli.txt',
    'ssti': 'payloads/sources/ssti.txt',
    'os-cmd-injection': 'payloads/sources/os-cmd-injection.txt',
    'code-injection': 'payloads/sources/code-injection.txt',
    'xss': 'payloads/sources/xss.txt',
    'xxe': 'payloads/sources/xxe.txt',
    'ssrf': 'payloads/sources/ssrf.txt',
    'path-traversal': 'payloads/sources/path-traversal.txt',
    'nosql': 'payloads/sources/nosql.txt',
    'el-injection': 'payloads/sources/el-injection.txt',
    'prototype-pollution': 'payloads/sources/prototype-pollution.txt',
    'header-crlf': 'payloads/sources/header-crlf.txt',
    'format-string': 'payloads/sources/format-string.txt',
    'deserialization': 'payloads/sources/deserialization.txt',
    'ldap-injection': 'payloads/sources/ldap-injection.txt',
    'xslt-injection': 'payloads/sources/xslt-injection.txt',
    'elasticsearch-injection': 'payloads/sources/elasticsearch-injection.txt',
    'cypher-injection': 'payloads/sources/cypher-injection.txt',
    'couchdb-injection': 'payloads/sources/couchdb-injection.txt',
    'polyglots': 'payloads/sources/polyglots-condensed.txt',
}

# Header-to-category mapping for minimal list (matches on header substrings)
HEADER_CATEGORY_MAP = {
    'sqli': [r'SQLi'],
    'ssti': [r'SSTI'],
    'os-cmd-injection': [r'OS Command|Command Injection'],
    'code-injection': [r'Code Injection Cross-Language', r'Groovy Code Injection', r'SSI Injection'],
    'xss': [r'XSS'],
    'xxe': [r'XXE'],
    'ssrf': [r'SSRF'],
    'path-traversal': [r'Path Traversal'],
    'nosql': [r'NoSQL'],
    'el-injection': [r'EL Injection'],
    'prototype-pollution': [r'Prototype Pollution'],
    'header-crlf': [r'CRLF|Header Injection'],
    'format-string': [r'Format String'],
    'ldap-injection': [r'LDAP'],
    'xslt-injection': [r'XSLT'],
    'elasticsearch-injection': [r'Elasticsearch'],
    'cypher-injection': [r'Cypher'],
    'couchdb-injection': [r'CouchDB'],
    'deserialization': [r'Pickle|YAML|yaml|jsonpickle|serialize|funcster|Unserialize|Marshal'
                        r'|Oj|Hessian|Storable|Serialized|SnakeYAML|Jackson|Fastjson'
                        r'|XStream|XMLDecoder|Json\.NET|JNDI|BinaryFormatter|SoapFormatter'
                        r'|ViewState|ObjectStateFormatter|LosFormatter|XmlSerializer'
                        r'|JavaScriptSerializer|ysoserial|cryo'],
    'polyglots': [r'POLYGLOT'],
}

# Encoders
def _b64(p): return base64.b64encode(p.encode()).decode()
def _url(p): return urllib.parse.quote(p, safe='')
def _durl(p): return urllib.parse.quote(urllib.parse.quote(p, safe=''), safe='')
def _html(p): return ''.join(f'&#{ord(c)};' for c in p)
def _hex(p): return ''.join(f'\\x{ord(c):02x}' for c in p)
def _uni(p): return ''.join(f'\\u{ord(c):04x}' for c in p)
def _json(p): return jsonlib.dumps(p)[1:-1]

ENCODERS = {
    'base64': _b64, 'url-encoded': _url, 'double-url-encoded': _durl,
    'html-entity': _html, 'hex-escaped': _hex, 'unicode-escaped': _uni,
    'json-safe': _json,
}


def _read_sections(path):
    """Read file into (header, [payloads]) tuples."""
    sections = []
    hdr, plds = None, []
    with open(path) as f:
        for line in f:
            line = line.rstrip('\n')
            if line.startswith('##'):
                if hdr and plds:
                    sections.append((hdr, plds))
                hdr, plds = line, []
            elif line.strip():
                plds.append(line)
    if hdr and plds:
        sections.append((hdr, plds))
    return sections


def _write(path, lines):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write('\n'.join(lines) + '\n')
    return len(lines)


def _build_pillar_lists(sections, out_dir, label):
    """Build by-pillar breakdown from sections. Returns stats."""
    pil_dir = os.path.join(out_dir, 'by-pillar')
    os.makedirs(pil_dir, exist_ok=True)

    pillar_payloads_set = set()
    for pillar, patterns in PILLAR_MAP.items():
        plines, ponly = [], []
        for h, ps in sections:
            clean = h.strip('#').strip()
            if any(re.search(p, clean) for p in patterns):
                plines.append(h)
                plines.extend(ps)
                ponly.extend(ps)
                pillar_payloads_set.update(ps)
        _write(os.path.join(pil_dir, f'{pillar}.txt'), plines)
        _write(os.path.join(pil_dir, f'{pillar}-payloads-only.txt'), ponly)
        print(f'dist: {label}/by-pillar/{pillar}.txt — {len(ponly)} payloads')

    # Reflected (everything not in a named pillar)
    rlines, ronly = [], []
    for h, ps in sections:
        remaining = [p for p in ps if p not in pillar_payloads_set]
        if remaining:
            rlines.append(h)
            rlines.extend(remaining)
            ronly.extend(remaining)
    _write(os.path.join(pil_dir, 'reflected.txt'), rlines)
    _write(os.path.join(pil_dir, 'reflected-payloads-only.txt'), ronly)
    print(f'dist: {label}/by-pillar/reflected.txt — {len(ronly)} payloads')


def _build_category_from_sections(sections, out_dir, label):
    """Build by-category breakdown from parsed sections using header matching."""
    cat_dir = os.path.join(out_dir, 'by-category')
    os.makedirs(cat_dir, exist_ok=True)

    # Bucket sections into categories
    buckets = {cat: [] for cat in HEADER_CATEGORY_MAP}
    for h, ps in sections:
        clean = h.strip('#').strip()
        matched = False
        for cat, patterns in HEADER_CATEGORY_MAP.items():
            if any(re.search(p, clean) for p in patterns):
                buckets[cat].append((h, ps))
                matched = True
                break
        if not matched:
            # Fallback: try to match against category source names
            buckets.setdefault('other', []).append((h, ps))

    # Also collect polyglots across all categories
    polyglot_sections = []
    for h, ps in sections:
        clean = h.strip('#').strip()
        if re.search(r'POLYGLOT', clean):
            polyglot_sections.append((h, ps))

    for cat, cat_sections in buckets.items():
        if not cat_sections:
            continue
        lines = []
        for h2, ps2 in cat_sections:
            lines.append(h2)
            lines.extend(ps2)
        _write(os.path.join(cat_dir, f'{cat}.txt'), lines)
        pc = sum(len(p) for _, p in cat_sections)
        print(f'dist: {label}/by-category/{cat}.txt — {pc} payloads')

    # Write polyglots file (all POLYGLOT-prefixed sections)
    if polyglot_sections:
        plines = []
        for h2, ps2 in polyglot_sections:
            plines.append(h2)
            plines.extend(ps2)
        _write(os.path.join(cat_dir, 'polyglots.txt'), plines)
        pc = sum(len(p) for _, p in polyglot_sections)
        print(f'dist: {label}/by-category/polyglots.txt — {pc} payloads')


def _build_encoded(payloads_only, out_dir, label):
    """Build encoded variants of a payload list."""
    for enc_name, encoder in ENCODERS.items():
        enc_dir = os.path.join(out_dir, 'encoded', enc_name)
        os.makedirs(enc_dir, exist_ok=True)
        encoded = []
        for p in payloads_only:
            try:
                encoded.append(encoder(p))
            except Exception:
                encoded.append(p)
        _write(os.path.join(enc_dir, 'payloads.txt'), encoded)
        print(f'dist: {label}/encoded/{enc_name}/payloads.txt — {len(encoded)} payloads')


def run_dist(root):
    """Generate full and minimal distributions with matching structure."""
    dist = os.path.join(root, 'payloads', 'lists')
    # Clean previous output to avoid stale files
    if os.path.exists(dist):
        shutil.rmtree(dist)
    os.makedirs(dist)

    # --- FULL distribution ---
    full_dir = os.path.join(dist, 'full')
    full_path = os.path.join(root, 'payloads', 'full.txt')
    with open(full_path) as f:
        full_lines = [l.rstrip('\n') for l in f.readlines()]

    # Master list and payloads-only
    _write(os.path.join(full_dir, 'master.txt'), full_lines)
    payloads_only = [l for l in full_lines if not l.startswith('##') and l.strip()]
    _write(os.path.join(full_dir, 'payloads-only.txt'), payloads_only)
    print(f'dist: full/master.txt — {len(payloads_only)} payloads')

    # By category (from source files)
    cat_dir = os.path.join(full_dir, 'by-category')
    os.makedirs(cat_dir, exist_ok=True)
    for cat, rel in CATEGORY_SOURCES.items():
        sections = _read_sections(os.path.join(root, rel))
        lines = []
        for h, ps in sections:
            lines.append(h)
            lines.extend(ps)
        _write(os.path.join(cat_dir, f'{cat}.txt'), lines)
        pc = sum(len(p) for _, p in sections)
        print(f'dist: full/by-category/{cat}.txt — {pc} payloads')

    # By pillar
    all_sections = _read_sections(full_path)
    _build_pillar_lists(all_sections, full_dir, 'full')

    # Encoded
    _build_encoded(payloads_only, full_dir, 'full')

    # --- MINIMAL distribution ---
    min_dir = os.path.join(dist, 'minimal')
    min_path = os.path.join(root, 'payloads', 'sources', 'minimum.txt')
    min_sections = _read_sections(min_path)

    # Master list and payloads-only
    min_lines = []
    min_payloads = []
    for h, ps in min_sections:
        min_lines.append(h)
        min_lines.extend(ps)
        min_payloads.extend(ps)
    _write(os.path.join(min_dir, 'master.txt'), min_lines)
    _write(os.path.join(min_dir, 'payloads-only.txt'), min_payloads)
    print(f'dist: minimal/master.txt — {len(min_payloads)} payloads')

    # By category (from header matching)
    _build_category_from_sections(min_sections, min_dir, 'minimal')

    # By pillar
    _build_pillar_lists(min_sections, min_dir, 'minimal')

    # Encoded
    _build_encoded(min_payloads, min_dir, 'minimal')

    print(f'dist: complete -> payloads/lists/full/ + payloads/lists/minimal/')
