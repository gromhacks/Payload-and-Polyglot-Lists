"""Generate distribution directory: by-category, by-pillar, encoded variants."""

import os
import re
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


def run_dist(root):
    """Generate full distribution from payloads/full.txt and source files."""
    dist = os.path.join(root, 'payloads', 'lists')
    os.makedirs(dist, exist_ok=True)

    # Read master list
    full_path = os.path.join(root, 'payloads', 'full.txt')
    with open(full_path) as f:
        full_lines = [l.rstrip('\n') for l in f.readlines()]

    # 1. Copy full.txt
    _write(os.path.join(dist, 'full.txt'), full_lines)
    payloads_only = [l for l in full_lines if not l.startswith('##') and l.strip()]
    _write(os.path.join(dist, 'payloads-only.txt'), payloads_only)
    print(f'dist: payloads-only.txt -{len(payloads_only)} payloads')

    # 2. By category
    cat_dir = os.path.join(dist, 'by-category')
    os.makedirs(cat_dir, exist_ok=True)
    for cat, rel in CATEGORY_SOURCES.items():
        sections = _read_sections(os.path.join(root, rel))
        lines = []
        for h, ps in sections:
            lines.append(h)
            lines.extend(ps)
        _write(os.path.join(cat_dir, f'{cat}.txt'), lines)
        pc = sum(len(p) for _, p in sections)
        print(f'dist: by-category/{cat}.txt -{pc} payloads')

    # 3. By pillar
    pil_dir = os.path.join(dist, 'by-pillar')
    os.makedirs(pil_dir, exist_ok=True)
    all_sections = _read_sections(full_path)

    pillar_payloads_set = set()
    for pillar, patterns in PILLAR_MAP.items():
        plines, ponly = [], []
        for h, ps in all_sections:
            clean = h.strip('#').strip()
            if any(re.search(p, clean) for p in patterns):
                plines.append(h)
                plines.extend(ps)
                ponly.extend(ps)
                pillar_payloads_set.update(ps)
        _write(os.path.join(pil_dir, f'{pillar}.txt'), plines)
        _write(os.path.join(pil_dir, f'{pillar}-payloads-only.txt'), ponly)
        print(f'dist: by-pillar/{pillar}.txt -{len(ponly)} payloads')

    # Reflected (everything not in a named pillar)
    rlines, ronly = [], []
    for h, ps in all_sections:
        remaining = [p for p in ps if p not in pillar_payloads_set]
        if remaining:
            rlines.append(h)
            rlines.extend(remaining)
            ronly.extend(remaining)
    _write(os.path.join(pil_dir, 'reflected.txt'), rlines)
    _write(os.path.join(pil_dir, 'reflected-payloads-only.txt'), ronly)
    print(f'dist: by-pillar/reflected.txt -{len(ronly)} payloads')

    # 4. Standalone lists (not part of full.txt)
    STANDALONE = {
        'minimum': 'payloads/sources/minimum.txt',
    }
    for name, rel_path in STANDALONE.items():
        src = os.path.join(root, rel_path)
        if not os.path.exists(src):
            continue
        sections = _read_sections(src)
        lines, only = [], []
        for h, ps in sections:
            lines.append(h)
            lines.extend(ps)
            only.extend(ps)
        _write(os.path.join(dist, f'{name}.txt'), lines)
        _write(os.path.join(dist, f'{name}-payloads-only.txt'), only)
        print(f'dist: {name}.txt -{len(only)} payloads')

        # Encoded variants
        for enc_name, encoder in ENCODERS.items():
            enc_dir = os.path.join(dist, 'encoded', enc_name)
            os.makedirs(enc_dir, exist_ok=True)
            encoded = []
            for p in only:
                try:
                    encoded.append(encoder(p))
                except:
                    encoded.append(p)
            _write(os.path.join(enc_dir, f'{name}.txt'), encoded)

    # 5. Encoded variants
    for enc_name, encoder in ENCODERS.items():
        enc_dir = os.path.join(dist, 'encoded', enc_name)
        os.makedirs(enc_dir, exist_ok=True)
        encoded = []
        for p in payloads_only:
            try:
                encoded.append(encoder(p))
            except:
                encoded.append(p)
        _write(os.path.join(enc_dir, 'full.txt'), encoded)
        print(f'dist: encoded/{enc_name}/full.txt -{len(encoded)} payloads')

    print(f'dist: complete -> payloads/lists/')
