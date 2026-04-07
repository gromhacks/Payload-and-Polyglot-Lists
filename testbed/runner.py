#!/usr/bin/env python3
"""
Test Runner - fires payloads at testbed endpoints and checks four detection pillars.

Usage:
    ./runner.py --stack sqli-sqlite --wordlist ../payloads/full.txt
    ./runner.py --stack ssti-python --wordlist ../payloads/math.txt --endpoint jinja2
"""

import argparse
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

TIMING_THRESHOLD_MS = 4500
OOB_HOST = os.environ.get('OOB_HOST', 'localhost')
OOB_PORT = os.environ.get('OOB_PORT', '9999')
OOB_URL = f'http://{OOB_HOST}:{OOB_PORT}'
TIMEOUT = 15
CANARIES = ('1337', '7331')

# Colors
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
CYAN = '\033[0;36m'
NC = '\033[0m'
BOLD = '\033[1m'


def load_config(config_path):
    """Load runner-config.yml (simple YAML-like parser, no dependency)."""
    config = {}
    if not os.path.exists(config_path):
        return config

    current_stack = None
    with open(config_path, 'r') as f:
        for line in f:
            line = line.rstrip()
            if not line or line.startswith('#'):
                continue
            if not line.startswith(' ') and line.endswith(':'):
                current_stack = line[:-1].strip()
                config[current_stack] = {}
            elif current_stack and ':' in line:
                key, _, value = line.strip().partition(':')
                key = key.strip()
                value = value.strip()
                if key == 'endpoints':
                    config[current_stack]['endpoints'] = {}
                elif '/' in value and current_stack:
                    parent = config[current_stack]
                    if 'endpoints' in parent and isinstance(parent['endpoints'], dict):
                        parent['endpoints'][key] = value
                    else:
                        parent[key] = value
                else:
                    config[current_stack][key] = value
    return config


def load_config_yaml(config_path):
    """Load config with proper YAML if available, fallback to simple parser."""
    try:
        import yaml
        with open(config_path, 'r') as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        return load_config(config_path)


def clear_oob():
    """Clear OOB callback log."""
    try:
        req = urllib.request.Request(f'{OOB_URL}/clear', method='POST', data=b'')
        urllib.request.urlopen(req, timeout=3)
    except Exception:
        pass


def get_oob_callbacks():
    """Get callbacks received since last clear."""
    try:
        resp = urllib.request.urlopen(f'{OOB_URL}/callbacks', timeout=3)
        return json.loads(resp.read())
    except Exception:
        return []


def fire_payload(url, payload):
    """Send payload to testbed endpoint, return parsed response."""
    data = urllib.parse.urlencode({'input': payload}).encode()
    req = urllib.request.Request(url, data=data, method='POST')
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')

    start = time.time()
    try:
        resp = urllib.request.urlopen(req, timeout=TIMEOUT)
        elapsed_ms = (time.time() - start) * 1000
        body = resp.read().decode('utf-8', errors='replace')
        try:
            result = json.loads(body)
        except json.JSONDecodeError:
            result = {'output': body, 'error': None, 'time_ms': elapsed_ms}
        return result
    except urllib.error.HTTPError as e:
        elapsed_ms = (time.time() - start) * 1000
        body = e.read().decode('utf-8', errors='replace') if e.fp else ''
        try:
            result = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            result = {'output': body, 'error': f'HTTP {e.code}', 'time_ms': elapsed_ms}
        return result
    except urllib.error.URLError as e:
        elapsed_ms = (time.time() - start) * 1000
        return {'output': None, 'error': str(e.reason), 'time_ms': elapsed_ms}
    except Exception as e:
        elapsed_ms = (time.time() - start) * 1000
        return {'output': None, 'error': str(e), 'time_ms': elapsed_ms}


def check_pillars(result, pre_callbacks, post_callbacks):
    """Check which of the four pillars fired."""
    pillars = {
        'error': False,
        'math': False,
        'timing': False,
        'oob': False,
    }

    # Error pillar
    if result.get('error'):
        pillars['error'] = True

    # Math pillar - check for canary values in output
    output = str(result.get('output', '') or '')
    error_str = str(result.get('error', '') or '')
    combined = output + error_str
    for canary in CANARIES:
        if canary in combined:
            pillars['math'] = True
            break

    # Timing pillar
    time_ms = result.get('time_ms', 0) or 0
    if time_ms > TIMING_THRESHOLD_MS:
        pillars['timing'] = True

    # OOB pillar
    if len(post_callbacks) > len(pre_callbacks):
        pillars['oob'] = True

    return pillars


def substitute_domain(payload, domain):
    """Replace {domain} placeholder and all encoded variants with OOB catcher address."""
    result = payload
    # Raw placeholder
    result = result.replace('{domain}', domain)
    # URL-encoded variants
    result = result.replace('%7Bdomain%7D', domain)
    result = result.replace('%7bdomain%7d', domain)
    # Double-encoded
    result = result.replace('%257Bdomain%257D', domain)
    # Whitelisted domain placeholder
    result = result.replace('{white-listed-domain}', domain)
    # DNS-specific (just hostname, no port)
    dns_host = domain.split(':')[0]
    result = result.replace('{dns_domain}', dns_host)
    # Callback ID for correlation
    result = result.replace('{callback_id}', f'cb-{hash(payload) & 0xFFFF:04x}')
    return result


def run(url, wordlist_path, oob_domain, output_file=None):
    """Run all payloads from wordlist against the target URL."""
    if not os.path.exists(wordlist_path):
        print(f"{RED}[!] Wordlist not found: {wordlist_path}{NC}", file=sys.stderr)
        return

    with open(wordlist_path, 'r', encoding='utf-8', errors='surrogateescape') as f:
        lines = [l.rstrip('\n') for l in f.readlines()]

    # Filter out headers and blank lines
    payloads = []
    for line in lines:
        if line.startswith('##') or line.strip() == '':
            continue
        payloads.append(line)

    total = len(payloads)
    print(f"{CYAN}[*] Target:   {url}{NC}")
    print(f"{CYAN}[*] Payloads: {total}{NC}")
    print(f"{CYAN}[*] OOB:      {oob_domain}{NC}")
    print()

    results = []
    hits = {'error': 0, 'math': 0, 'timing': 0, 'oob': 0}

    header = f"{'#':>5}  {'ERROR':>5}  {'MATH':>5}  {'TIME':>5}  {'OOB':>5}  PAYLOAD"
    print(f"{BOLD}{header}{NC}")
    print("-" * 80)

    for i, raw_payload in enumerate(payloads, 1):
        payload = substitute_domain(raw_payload, oob_domain)

        # Clear OOB, get pre-state
        clear_oob()
        time.sleep(0.05)  # Brief settle
        pre_callbacks = get_oob_callbacks()

        # Fire
        result = fire_payload(url, payload)

        # Brief wait for OOB callbacks to arrive
        time.sleep(0.3)
        post_callbacks = get_oob_callbacks()

        # Check pillars
        pillars = check_pillars(result, pre_callbacks, post_callbacks)

        # Format output
        def flag(val):
            return f"{GREEN}  YES{NC}" if val else f"    -"

        any_hit = any(pillars.values())
        line_color = GREEN if any_hit else ''
        line_reset = NC if any_hit else ''

        truncated = raw_payload[:60] + ('...' if len(raw_payload) > 60 else '')
        print(f"{line_color}{i:>5}  {flag(pillars['error'])}  {flag(pillars['math'])}  {flag(pillars['timing'])}  {flag(pillars['oob'])}  {truncated}{line_reset}")

        for k, v in pillars.items():
            if v:
                hits[k] += 1

        results.append({
            'payload': raw_payload,
            'error': pillars['error'],
            'math': pillars['math'],
            'timing': pillars['timing'],
            'oob': pillars['oob'],
            'time_ms': result.get('time_ms', 0),
            'error_msg': result.get('error', ''),
            'output_preview': str(result.get('output', ''))[:200],
        })

    # Summary
    print()
    print(f"{BOLD}Summary:{NC}")
    print(f"  Total payloads: {total}")
    print(f"  Error hits:     {GREEN}{hits['error']}{NC}")
    print(f"  Math hits:      {GREEN}{hits['math']}{NC}")
    print(f"  Timing hits:    {GREEN}{hits['timing']}{NC}")
    print(f"  OOB hits:       {GREEN}{hits['oob']}{NC}")
    any_total = sum(1 for r in results if any(r[k] for k in ('error', 'math', 'timing', 'oob')))
    print(f"  Any pillar:     {GREEN}{any_total}{NC} / {total}")

    # Write CSV report
    if output_file:
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['payload', 'error', 'math', 'timing', 'oob', 'time_ms', 'error_msg', 'output_preview'])
            writer.writeheader()
            writer.writerows(results)
        print(f"\n{CYAN}[*] Report saved: {output_file}{NC}")

    return results


def main():
    parser = argparse.ArgumentParser(description='Payload test runner')
    parser.add_argument('--stack', required=True, help='Stack name (e.g., sqli-sqlite)')
    parser.add_argument('--wordlist', '-w', required=True, help='Path to wordlist file')
    parser.add_argument('--config', '-c', default=None, help='Path to runner-config.yml')
    parser.add_argument('--endpoint', '-e', default=None, help='Specific endpoint within stack (for multi-endpoint stacks)')
    parser.add_argument('--url', default=None, help='Override target URL directly')
    parser.add_argument('--oob-domain', default=None, help='OOB callback domain (default: oob:9999 in Docker, localhost:9999 on host)')
    parser.add_argument('--output', '-o', default=None, help='Output CSV report file')
    parser.add_argument('--timeout', '-t', type=int, default=15, help='Request timeout in seconds')
    parser.add_argument('--timing-threshold', type=int, default=4500, help='Timing threshold in ms')
    args = parser.parse_args()

    global TIMEOUT, TIMING_THRESHOLD_MS
    TIMEOUT = args.timeout
    TIMING_THRESHOLD_MS = args.timing_threshold

    # Determine target URL
    target_url = args.url
    if not target_url:
        config_path = args.config
        if not config_path:
            config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'runner-config.yml')
        config = load_config_yaml(config_path)
        stack_config = config.get(args.stack, {})

        if args.endpoint and 'endpoints' in stack_config:
            target_url = stack_config['endpoints'].get(args.endpoint)
        elif 'url' in stack_config:
            target_url = stack_config['url']
        elif 'endpoints' in stack_config:
            endpoints = stack_config['endpoints']
            if args.endpoint:
                target_url = endpoints.get(args.endpoint)
            else:
                # Run against all endpoints
                print(f"{CYAN}[*] Multi-endpoint stack. Available: {', '.join(endpoints.keys())}{NC}")
                print(f"{CYAN}[*] Use --endpoint <name> to test a specific one, or running all...{NC}")
                print()
                oob_domain = args.oob_domain or 'localhost:9999'
                for ep_name, ep_url in endpoints.items():
                    print(f"\n{'='*80}")
                    print(f"{BOLD} Endpoint: {ep_name} -> {ep_url}{NC}")
                    print(f"{'='*80}\n")
                    output = f"{args.output}.{ep_name}.csv" if args.output else None
                    run(ep_url, args.wordlist, oob_domain, output)
                return

        if not target_url:
            print(f"{RED}[!] Could not determine URL for stack: {args.stack}{NC}", file=sys.stderr)
            print(f"    Use --url to specify directly, or check runner-config.yml", file=sys.stderr)
            sys.exit(1)

    oob_domain = args.oob_domain or 'localhost:9999'
    run(target_url, args.wordlist, oob_domain, args.output)


if __name__ == '__main__':
    main()
