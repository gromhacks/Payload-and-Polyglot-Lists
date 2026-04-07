"""Build full.txt master list from source files."""

import os


# Source file order: polyglots first, then per-category, then verified deser
SOURCE_FILES = [
    'payloads/sources/polyglots-condensed.txt',
    'payloads/sources/sqli.txt',
    'payloads/sources/ssti.txt',
    'payloads/sources/os-cmd-injection.txt',
    'payloads/sources/code-injection.txt',
    'payloads/sources/xss.txt',
    'payloads/sources/xxe.txt',
    'payloads/sources/ssrf.txt',
    'payloads/sources/path-traversal.txt',
    'payloads/sources/nosql.txt',
    'payloads/sources/el-injection.txt',
    'payloads/sources/prototype-pollution.txt',
    'payloads/sources/header-crlf.txt',
    'payloads/sources/format-string.txt',
    'payloads/sources/deserialization.txt',
]


def run_build(root):
    """Build full.txt from source payload files."""
    master = []

    for rel in SOURCE_FILES:
        path = os.path.join(root, rel)
        with open(path) as f:
            lines = [l.rstrip('\n') for l in f.readlines()]
        if master and master[-1] != '':
            master.append('')
        for line in lines:
            if line.strip():
                master.append(line)

    # Deduplicate payloads (preserve headers)
    seen = set()
    deduped = []
    for line in master:
        if line.startswith('##') or line == '':
            deduped.append(line)
            continue
        if line not in seen:
            seen.add(line)
            deduped.append(line)

    # Remove consecutive blank lines
    final = []
    prev_blank = False
    for line in deduped:
        if line == '':
            if not prev_blank:
                final.append(line)
            prev_blank = True
        else:
            prev_blank = False
            final.append(line)

    # Remove empty sections
    result = []
    i = 0
    while i < len(final):
        if final[i].startswith('##'):
            j = i + 1
            while j < len(final) and final[j] == '':
                j += 1
            if j >= len(final) or final[j].startswith('##'):
                i = j
                continue
        result.append(final[i])
        i += 1

    out_path = os.path.join(root, 'payloads', 'full.txt')
    with open(out_path, 'w') as f:
        f.write('\n'.join(result) + '\n')

    payload_count = len([l for l in result if not l.startswith('##') and l.strip()])
    section_count = len([l for l in result if l.startswith('##')])
    print(f'build: {payload_count} payloads across {section_count} sections -> payloads/full.txt')
    return result
