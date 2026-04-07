"""Prepare payload lists for use - replace {domain} with your callback server
and output ready-to-use files to a custom directory."""

import os
import shutil


def run_prepare(root, domain, output_dir=None):
    """Replace {domain} in all payload files and write to output directory."""
    dist = os.path.join(root, 'payloads', 'dist')
    out = output_dir or os.path.join(root, 'ready')

    if os.path.exists(out):
        shutil.rmtree(out)

    # Walk the entire dist/ tree and copy with substitution
    file_count = 0
    payload_count = 0

    for dirpath, dirnames, filenames in os.walk(dist):
        for fname in filenames:
            if not fname.endswith('.txt'):
                continue

            src = os.path.join(dirpath, fname)
            rel = os.path.relpath(src, dist)
            dst = os.path.join(out, rel)

            os.makedirs(os.path.dirname(dst), exist_ok=True)

            with open(src) as f:
                content = f.read()

            replaced = content.replace('{domain}', domain).replace('{DOMAIN}', domain)

            with open(dst, 'w') as f:
                f.write(replaced)

            file_count += 1
            payload_count = sum(1 for line in replaced.splitlines()
                                if line.strip() and not line.startswith('##'))

    # Also create a flat payloads-only with no headers
    src_flat = os.path.join(dist, 'payloads-only.txt')
    if os.path.exists(src_flat):
        with open(src_flat) as f:
            content = f.read()
        replaced = content.replace('{domain}', domain).replace('{DOMAIN}', domain)
        dst_flat = os.path.join(out, 'payloads-only.txt')
        with open(dst_flat, 'w') as f:
            f.write(replaced)

    print(f'prepare: {domain} substituted across {file_count} files')
    print(f'prepare: output -> {out}/')
    print(f'')
    print(f'Ready to use:')
    print(f'  {out}/payloads-only.txt          - full list for Burp Intruder')
    print(f'  {out}/by-category/<type>.txt      - per vulnerability class')
    print(f'  {out}/by-pillar/<pillar>.txt       - per detection method')
    print(f'  {out}/encoded/<format>/full.txt   - pre-encoded variants')
