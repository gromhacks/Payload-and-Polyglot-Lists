"""Regenerate computed payloads (deserialization, SSTI, SQLi, misc).

These generators produce payloads that are written to source files,
then included in full.txt via the build step.
"""

import os
import subprocess
import sys


def run_generate(root, target='all'):
    """Run payload generators."""
    generators = {
        'deser': ('generate-deser-final.py', 'payloads/sources/deserialization.txt'),
        'ssti': ('generate-ssti-missing.py', None),
        'sqli': ('generate-sqli-code-missing.py', None),
        'misc': ('generate-misc-missing.py', None),
    }

    if target == 'all':
        targets = list(generators.keys())
    else:
        targets = [target]

    for t in targets:
        script, output_file = generators[t]
        script_path = os.path.join(root, 'tools', script)

        if not os.path.exists(script_path):
            print(f'generate: SKIP {t} - {script} not found')
            continue

        print(f'generate: running {script}...')
        result = subprocess.run(
            [sys.executable, script_path],
            cwd=root,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            print(f'generate: ERROR in {script}:')
            print(result.stderr[:500])
            continue

        if output_file:
            out_path = os.path.join(root, output_file)
            with open(out_path, 'w') as f:
                f.write(result.stdout)
            line_count = result.stdout.count('\n')
            print(f'generate: {t} -> {output_file} ({line_count} lines)')
        else:
            # These generators print to stdout for review
            lines = result.stdout.strip().split('\n')
            print(f'generate: {t} produced {len(lines)} lines (review output below)')
            print(result.stdout[:500])
            if len(result.stdout) > 500:
                print('...(truncated)')

    print('generate: done. Run "payloadctl build" to rebuild full.txt.')
