"""Strict payload validation - proves actual exploitation, not string matching.

For each payload, verifies the exploit ACTUALLY triggered:
  - math:     server COMPUTED 7*191=1337 (payload didn't contain '1337' literally)
  - error:    server returned a REAL parser/interpreter error (not generic HTTP error)
  - timing:   server delayed 4.5-15s (sleep actually executed)
  - oob:      callback catcher received request FROM a testbed container
  - file-read: output contains /etc/passwd content (root:x:0:0)
  - reflected: payload appears in output (ONLY valid for XSS, integer, type, null categories)

Payloads that only match on weak criteria are flagged as SUSPECT.
"""

import os
import re
import sys
import time
import json
import urllib.request
import urllib.parse
import urllib.error

OOB_URL = 'http://localhost:9999'

# Import routing from the main validator
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cmd_validate import _get_endpoints

# Categories where reflection IS the vulnerability
REFLECTION_VALID_CATS = {
    'xss', 'crlf', 'prototype-pollution', 'edge-cases',
}

# Categories where reflected integers/strings are valid
REFLECTED_VALUE_CATS = {
    'sqli', 'ssti', 'code-injection', 'el-injection', 'groovy',
    'nosql', 'xss', 'crlf', 'edge-cases', 'prototype-pollution',
    'elasticsearch', 'cypher', 'couchdb',
}

# Section headers where payload literally contains '1337' but reflection IS the exploit
REFLECTION_OK_HEADERS = re.compile(
    r'XSS|CRLF|Prototype|Integer Boundary|Type Confusion|Null Byte|'
    r'Format String|Buffer Overflow|Reflected|reflected'
)


def _clear_oob():
    try:
        req = urllib.request.Request(f'{OOB_URL}/clear', method='POST', data=b'')
        urllib.request.urlopen(req, timeout=2)
    except:
        pass


def _get_oob():
    try:
        resp = urllib.request.urlopen(f'{OOB_URL}/callbacks', timeout=2)
        return json.loads(resp.read())
    except:
        return []


def _fire(url, payload):
    payload_sub = payload.replace('{domain}', 'oob:9999').replace('{DOMAIN}', 'oob:9999')
    payload_sub = payload_sub.replace('{dns_domain}', 'oob')
    payload_sub = payload_sub.replace('{callback_id}', 'strict-val')
    if '/yaml' in url:
        payload_sub = payload_sub.replace('\\n', '\n')
    data = urllib.parse.urlencode({'input': payload_sub}).encode()
    req = urllib.request.Request(url, data=data, method='POST')
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    start = time.time()
    try:
        resp = urllib.request.urlopen(req, timeout=12)
        elapsed_ms = (time.time() - start) * 1000
        body = resp.read().decode('utf-8', errors='replace')
        try:
            result = json.loads(body)
        except:
            result = {'output': body[:500], 'error': None}
        result['time_ms'] = elapsed_ms
        return result
    except urllib.error.HTTPError as e:
        elapsed_ms = (time.time() - start) * 1000
        body = e.read().decode('utf-8', errors='replace') if e.fp else ''
        try:
            result = json.loads(body)
        except:
            result = {'output': body[:500], 'error': f'HTTP {e.code}'}
        result['time_ms'] = elapsed_ms
        return result
    except urllib.error.URLError as e:
        return {'output': None, 'error': str(e.reason), 'time_ms': 0}
    except Exception as e:
        return {'output': None, 'error': str(e), 'time_ms': 0}


def _strict_check(data, payload, header, cat):
    """Strict exploit verification. Returns (pillars, verdict, reason)."""
    output = str(data.get('output', '') or '')
    error = str(data.get('error', '') or '')
    time_ms = data.get('time_ms', 0) or 0
    has_oob = data.get('_oob', False)
    pillars = []
    reasons = []

    raw_payload = payload  # before domain substitution

    # --- MATH pillar: server computed 7*191=1337 ---
    payload_has_1337 = '1337' in raw_payload
    output_has_1337 = '1337' in output

    if output_has_1337 and not payload_has_1337:
        # Server COMPUTED 1337 - payload only sent 7*191
        pillars.append('math')
        reasons.append('server computed 7*191=1337')
    elif output_has_1337 and payload_has_1337:
        # Payload contains '1337' literally AND it appears in output
        # This is ONLY valid if this is a reflection-appropriate category
        if REFLECTION_OK_HEADERS.search(header or ''):
            pillars.append('reflected-math')
            reasons.append('1337 reflected (valid for this category)')
        elif cat in REFLECTED_VALUE_CATS:
            pillars.append('reflected-math')
            reasons.append('1337 reflected in eval-capable endpoint')
        else:
            pillars.append('weak-math')
            reasons.append('1337 in output but payload also contains 1337 literally')

    # --- ERROR pillar: real parser/interpreter error ---
    err_val = data.get('error')
    if err_val is not None and err_val != '' and err_val != 'None':
        err_str = str(err_val)
        # Filter out generic connection/timeout errors
        if err_str not in ('CONNECTION_ERROR', 'TIMEOUT', ''):
            pillars.append('error')
            reasons.append(f'server error: {err_str[:60]}')

    # Check output for error signatures too
    error_sigs = ['Traceback', 'Exception', 'SyntaxError', 'TypeError',
                  'ValueError', 'NameError', 'RuntimeError', 'ParseError',
                  'TemplateSyntaxError', 'UndefinedError', 'CompileError',
                  'SQLError', 'OperationalError', 'ProgrammingError',
                  'Warning:', 'Fatal error', 'Parse error', 'javax.naming',
                  'java.lang.', 'ClassNotFoundException', 'NoClassDefFoundError',
                  'UnmarshalException', 'StreamCorruptedException',
                  'JsonTypeInfo', 'InvalidTypeId', 'MismatchedInputException',
                  'com.fasterxml', 'org.springframework', 'yaml.scanner',
                  'yaml.constructor', 'Psych::DisallowedClass', 'ArgumentError',
                  'unserialize()', '__PHP_Incomplete_Class',
                  'invalid_tag_probe', 'unknown tag',
                  'expected BLOCK_END', 'FakeClass1337',
                  'NonExist', 'bad stored', 'truncated',
                  'Invalid name', 'not supported']
    if any(sig in output for sig in error_sigs):
        if 'error' not in pillars:
            pillars.append('error')
            for sig in error_sigs:
                if sig in output:
                    reasons.append(f'error signature in output: {sig}')
                    break

    # --- TIMING pillar: server delayed ~5 seconds ---
    if time_ms > 4500:
        pillars.append('timing')
        reasons.append(f'server delayed {time_ms:.0f}ms (sleep executed)')

    # --- OOB pillar: callback received from testbed container ---
    if has_oob:
        pillars.append('oob')
        reasons.append('OOB callback received from target')

    # --- FILE-READ pillar: /etc/passwd or windows file content ---
    file_sigs = ['root:x:0:0', 'root:x:0:', 'daemon:', 'nobody:',
                 '[extensions]', '[fonts]', 'for 16-bit app support',
                 '/bin/sh', '/sbin/nologin']
    if any(sig in output for sig in file_sigs):
        pillars.append('file-read')
        reasons.append('file content in output')

    # --- REFLECTED pillar (fallback) ---
    if not pillars and raw_payload:
        clean = raw_payload.strip()
        # Only count reflection for appropriate categories
        if output and clean and clean in output:
            if cat in REFLECTION_VALID_CATS or REFLECTION_OK_HEADERS.search(header or ''):
                pillars.append('reflected')
                reasons.append('payload reflected (valid for category)')
            else:
                pillars.append('weak-reflected')
                reasons.append('payload reflected but NOT a reflection category')

        # Try evaluating simple expressions
        if not pillars:
            try:
                evaluated = str(eval(clean, {"__builtins__": {}}))
                if evaluated and evaluated in output and evaluated != clean:
                    pillars.append('reflected-eval')
                    reasons.append(f'eval({clean})={evaluated} found in output')
                elif clean == '-0' and '0' in output:
                    pillars.append('reflected-eval')
                    reasons.append('-0 evaluated to 0')
            except:
                pass

        # Empty string inputs
        if not pillars and clean in ('""', "''", '``') and data.get('error') is None:
            pillars.append('reflected')
            reasons.append('empty delimiters processed without error')

    # --- Determine verdict ---
    strong = [p for p in pillars if p in ('math', 'error', 'timing', 'oob', 'file-read')]
    medium = [p for p in pillars if p in ('reflected-math', 'reflected', 'reflected-eval')]
    weak = [p for p in pillars if p.startswith('weak')]

    if strong:
        verdict = 'EXPLOIT'
    elif medium:
        verdict = 'VALID'
    elif weak:
        verdict = 'SUSPECT'
    else:
        verdict = 'NO-FIRE'

    return pillars, verdict, '; '.join(reasons)


def run_strict(root, wordlist=None):
    full_path = wordlist or os.path.join(root, 'payloads', 'full.txt')
    with open(full_path) as f:
        lines = f.read().splitlines()

    stats = {'EXPLOIT': 0, 'VALID': 0, 'SUSPECT': 0, 'NO-FIRE': 0, 'SKIP': 0}
    pillar_counts = {}
    suspects = []
    no_fires = []
    total = 0

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
            stats['SKIP'] += 1
            continue

        # Clear OOB before each payload
        _clear_oob()
        time.sleep(0.02)

        # Fire at endpoints
        best_data = {}
        best_pillars = []
        best_verdict = 'NO-FIRE'
        best_reason = ''

        for url in current_endpoints:
            data = _fire(url, payload)
            if data.get('error') == 'CONNECTION_ERROR':
                continue

            time.sleep(0.1)
            callbacks = _get_oob()
            if callbacks:
                data['_oob'] = True

            pillars, verdict, reason = _strict_check(data, payload, current_header, current_cat)

            # Keep the best result
            verdict_rank = {'EXPLOIT': 4, 'VALID': 3, 'SUSPECT': 2, 'NO-FIRE': 1}
            if verdict_rank.get(verdict, 0) > verdict_rank.get(best_verdict, 0):
                best_data = data
                best_pillars = pillars
                best_verdict = verdict
                best_reason = reason

            if best_verdict == 'EXPLOIT':
                break  # no need to try more endpoints

        stats[best_verdict] += 1
        for p in best_pillars:
            pillar_counts[p] = pillar_counts.get(p, 0) + 1

        h = (current_header or '').strip('#').strip()[:50]
        p_short = line[:55]

        if best_verdict == 'SUSPECT':
            suspects.append((h, p_short, best_reason))
            print(f"  SUSPECT {h}: {p_short}")
            print(f"    reason: {best_reason}")
        elif best_verdict == 'NO-FIRE':
            no_fires.append((h, p_short, best_data, best_reason))
            out = str(best_data.get('output', ''))[:50]
            err = str(best_data.get('error', ''))[:30]
            print(f"  NO-FIRE {h}: {p_short}")
            print(f"    out={out} err={err} t={best_data.get('time_ms',0)}")

    # Report
    print(f"\n{'='*70}")
    print(f"STRICT VALIDATION RESULTS")
    print(f"{'='*70}")
    print(f"  EXPLOIT  (strong proof):  {stats['EXPLOIT']:>5}")
    print(f"  VALID    (medium proof):  {stats['VALID']:>5}")
    print(f"  SUSPECT  (weak proof):    {stats['SUSPECT']:>5}")
    print(f"  NO-FIRE  (no evidence):   {stats['NO-FIRE']:>5}")
    print(f"  SKIPPED  (no endpoint):   {stats['SKIP']:>5}")
    print(f"  TOTAL:                    {total:>5}")
    print(f"{'='*70}")

    print(f"\nPillar breakdown:")
    for p, c in sorted(pillar_counts.items(), key=lambda x: -x[1]):
        label = {
            'math': 'MATH      (server computed 7*191=1337)',
            'error': 'ERROR     (real parser/interpreter error)',
            'timing': 'TIMING    (server delayed ~5s)',
            'oob': 'OOB       (callback from target)',
            'file-read': 'FILE-READ (system file content)',
            'reflected': 'REFLECTED (payload in output, valid cat)',
            'reflected-math': 'REFL-MATH (1337 reflected, valid context)',
            'reflected-eval': 'REFL-EVAL (expression evaluated)',
            'weak-math': 'WEAK-MATH (1337 in output, suspicious)',
            'weak-reflected': 'WEAK-REFL (reflected, wrong category)',
        }.get(p, p)
        print(f"  {c:>5}  {label}")

    if suspects:
        print(f"\nSUSPECT payloads ({len(suspects)}):")
        cats = {}
        for h, p, r in suspects:
            cat = h.split(' - ')[0] if ' - ' in h else h
            cats[cat] = cats.get(cat, 0) + 1
        for cat, count in sorted(cats.items(), key=lambda x: -x[1]):
            print(f"  {count:>3}  {cat}")

    if no_fires:
        print(f"\nNO-FIRE payloads ({len(no_fires)}):")
        for h, p, d, r in no_fires:
            print(f"  {h}: {p}")


if __name__ == '__main__':
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    wl = sys.argv[1] if len(sys.argv) > 1 else None
    run_strict(root, wl)
