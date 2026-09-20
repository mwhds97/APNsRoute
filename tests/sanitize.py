#!/usr/bin/env python3
"""Run the ownership/callback fixtures under ASan and UBSan on an x86_64 Linux host."""
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--clang', default=os.environ.get('BLOCKS_CC', 'clang'))
args = parser.parse_args()
cc = shlex.split(os.environ.get('CC', 'cc'))
env = dict(os.environ, ASAN_OPTIONS='detect_leaks=0', UBSAN_OPTIONS='halt_on_error=1')
flags = ['-std=c11', '-O1', '-g', '-fPIE', '-fsanitize=address,undefined',
         '-Itests/include', '-Itests/vendor/BlocksRuntime']
def run(command):
    subprocess.run(command, cwd=root, env=env, check=True)

with tempfile.TemporaryDirectory(prefix='apnsroute-sanitize-') as temp:
    temp = Path(temp)
    runtime = []
    for name in ('runtime', 'data'):
        output = temp / (name + '.o')
        run(cc + flags + ['-c', f'tests/vendor/BlocksRuntime/{name}.c', '-o', str(output)])
        runtime.append(str(output))
    connections = temp / 'connections.o'
    run(cc + flags + ['-c', 'src/Connections.c', '-o', str(connections)])
    for name in ('retirement', 'nw_observer'):
        obj, exe = temp / (name + '.o'), temp / name
        run([args.clang, '-target', 'x86_64-linux-gnu', '-fblocks'] + flags +
            ['-c', f'tests/test_{name}.c', '-o', str(obj)])
        objects = [str(obj)] + runtime + ([str(connections)] if name == 'nw_observer' else [])
        run(cc + ['-pie', '-fsanitize=address,undefined'] + objects + ['-pthread', '-o', str(exe)])
        cases = [(s,) for s in ('main', 'vpn', 'unknown', 'recovery', 'opening', 'preflight',
                 'vpn-notify-failure', 'vpn-baseline', 'lifetimes', 'clock-failure', 'physical-overflow',
                 'vpn-overflow', 'quiet-overflow', 'disabled', 'missing', 'queue-failure', 'monitor-failure')] if name == 'retirement' else [()]
        for case in cases:
            run([str(exe), *case])
print('PASS: lifecycle ASan/UBSan fixtures (explicit reference checks; leak detection disabled)')
