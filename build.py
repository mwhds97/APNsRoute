#!/usr/bin/env python3
"""Build the rootful APNsRoute package with an existing iOS toolchain.

Dependencies: Python 3, iOS clang/ld/lipo/ldid, an iPhoneOS SDK, dpkg-deb.
No downloads or device writes are performed by this script.
"""
import argparse
import hashlib
import os
import re
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
metadata = dict(line.split(': ', 1) for line in (ROOT / 'control').read_text().splitlines() if ': ' in line)
version = metadata['Version']
version_header = (ROOT / 'src/Version.h').read_text()
if f'#define APR_VERSION "{version}"' not in version_header:
    raise SystemExit('control and src/Version.h disagree on the package version')

# Theos and this builder share the same literal source lists. No make code runs.
def source_paths(variable):
    match = re.search(r'^' + re.escape(variable) + r' = ([^\n]+)$',
                      (ROOT / 'Makefile').read_text(), re.MULTILINE)
    if not match:
        raise SystemExit('Missing literal Makefile source list: ' + variable)
    paths = [ROOT / name for name in match.group(1).split()]
    if not paths or any(path.suffix != '.c' or not path.is_file() for path in paths):
        raise SystemExit('Invalid source list: ' + variable)
    return [str(path) for path in paths]

tweak_sources = source_paths('APNsRoute_FILES')
doctor_sources = source_paths('apnsroute-diag_FILES')

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--toolchain', default=os.environ.get('APNSROUTE_IOS_TOOLCHAIN'),
                    help='iOS toolchain bin directory (clang, ld, lipo, ldid)')
parser.add_argument('--sdk', default=os.environ.get('APNSROUTE_IOS_SDK'), help='iPhoneOS SDK directory')
args = parser.parse_args()
if not args.toolchain or not args.sdk:
    parser.error('--toolchain and --sdk are required (or their APNSROUTE_ environment variables)')
toolchain = Path(args.toolchain).resolve()
sdk = Path(args.sdk).resolve()
if not sdk.is_dir():
    parser.error('SDK directory does not exist')

def tool(name):
    path = toolchain / name
    if not path.exists():
        raise SystemExit(f'Missing tool: {path}')
    return str(path)

report = [
    f'APNsRoute {version} build report',
    'Target: rootful iOS 14.x; intended device includes iPhone SE (2020), A13.',
    'Release 1.2.0 promotes the user-confirmed experimental6 behavior with lifecycle readability/ownership cleanup and a distinct release build ID. All 13 rules, endpoint retirement, native callbacks and kernel results, automatic installation enablement and doctor protocol 22 remain. The device test kept apsd PID 10284 through cellular/Wi-Fi/cellular with fresh ready couriers and no reported crash. No automatic apsd handover restart, runtime logging or probes. Installation requests one apsd reload. Normal recovery can still create init traffic.',
    '',
]

def run(command):
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
    if result.stdout.strip():
        print(result.stdout.strip())
    if result.stderr.strip():
        print(result.stderr.strip())
    if result.returncode:
        raise SystemExit(f'Command failed ({result.returncode}): {command[0]}\n{result.stderr}')
    return result

report.append(run([tool('clang'), '--version']).stdout.strip())
report.append('SDK: ' + sdk.name)

def inspect_slice(path, arch):
    data = path.read_bytes()
    magic, cpu, subtype, filetype, ncmds, _, _, _ = struct.unpack_from('<8I', data)
    assert magic == 0xfeedfacf and cpu == 0x100000c and filetype == 6
    assert (subtype & 0xffffff) == (2 if arch == 'arm64e' else 0)
    sections = []
    dependencies = []
    cursor = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', data, cursor)
        assert size >= 8 and cursor + size <= len(data)
        if cmd == 0x19:  # LC_SEGMENT_64
            count = struct.unpack_from('<I', data, cursor + 64)[0]
            for index in range(count):
                offset = cursor + 72 + index * 80
                sections.append(data[offset:offset + 16].split(b'\0')[0].decode())
        if cmd == 0xc:  # LC_LOAD_DYLIB
            offset = struct.unpack_from('<I', data, cursor + 8)[0]
            dependencies.append(data[cursor + offset:cursor + size].split(b'\0')[0].decode())
        cursor += size
    legacy = arch == 'arm64e' and (subtype & 0x80000000) == 0
    if legacy and any(s.startswith('__objc') or s == '__cfstring' for s in sections):
        raise SystemExit('Legacy arm64e with Obj-C/CFString metadata needs a compatible native Xcode build.')
    assert '/usr/lib/libSystem.B.dylib' in dependencies
    assert all(d.startswith(('/usr/lib/', '/System/Library/')) for d in dependencies)
    report.append(f'{arch}: Mach-O dylib; CPU subtype=0x{subtype:08x}; dependencies={dependencies}')
    if legacy:
        report.extend([
            'ARM64E LIMITATION: This Linux compiler emits the legacy arm64e ABI.',
            'The linker emits its known incompatible-arm64e-ABI warning; it is retained here.',
            'This C-only dylib has no Obj-C or CFString metadata. That reduces ABI conversion issues',
            'but does NOT prove that this binary loads on the target jailbreak.',
            'This build uses the same legacy ABI family as 0.1.2, but a different clang 13 revision; device validation is required.',
            'A native Xcode/Theos build is the alternative if legacy ABI loading fails.',
        ])
    return legacy

packages = ROOT / 'packages'
packages.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix='apnsroute-build-') as temporary:
    temporary = Path(temporary)
    slices = []
    for arch in ('arm64', 'arm64e'):
        output = temporary / f'APNsRoute.{arch}.dylib'
        result = run([
            tool('clang'), '-target', f'{arch}-apple-ios14.0', '-isysroot', str(sdk),
            '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', '-fPIC', '-fblocks',
            '-fvisibility=hidden', '-dynamiclib', *tweak_sources,
            '-framework', 'Network',
            '-install_name', '/Library/MobileSubstrate/DynamicLibraries/APNsRoute.dylib',
            '-o', str(output),
        ])
        legacy = inspect_slice(output, arch)
        warnings = [line for line in result.stderr.splitlines() if 'warning:' in line]
        for warning in warnings:
            if not (legacy and 'incompatible arm64e ABI compiler' in warning):
                raise SystemExit('Unreviewed linker warning: ' + warning)
        if warnings:
            report.append(f'{arch}: known legacy ABI linker warnings: {len(warnings)}')
        slices.append(str(output))

    stage = temporary / 'stage'
    shutil.copytree(ROOT / 'layout', stage)
    helper=stage / 'usr/libexec/apnsroute-diag'
    helper.parent.mkdir(parents=True,exist_ok=True)
    run([tool('clang'), '-target','arm64-apple-ios14.0','-isysroot',str(sdk),
         '-std=c11','-Wall','-Wextra','-Werror','-O2','-I'+str(ROOT/'src/vendor'),
         *doctor_sources,'-o',str(helper)])
    run([tool('ldid'),'-S','-Cadhoc',str(helper)])
    report.append('Doctor: standalone arm64, no added entitlements, read-only socket inspection.')
    dylib_dir = stage / 'Library/MobileSubstrate/DynamicLibraries'
    dylib_dir.mkdir(parents=True)
    final = dylib_dir / 'APNsRoute.dylib'
    run([tool('lipo'), '-create', *slices, '-output', str(final)])
    run([tool('ldid'), '-S', '-Cadhoc', str(final)])
    report.append('Fat dylib assembled with arm64 and arm64e slices; ad-hoc signed with ldid.')
    report.append('File/unified logging absent. Doctor uses fixed-size Darwin notification state, not log files.')
    report.append('Dylib SHA-256: ' + hashlib.sha256(final.read_bytes()).hexdigest())
    shutil.copy2(ROOT / 'APNsRoute.plist', dylib_dir)
    shutil.copy2(ROOT / 'control', stage / 'DEBIAN/control')
    for path in stage.rglob('*'):
        path.chmod(0o755 if path.is_dir() else 0o644)
    for relative in ('DEBIAN/postinst', 'DEBIAN/postrm', 'usr/bin/apnsroutectl',
                     'usr/libexec/apnsroute-diag',
                     'Library/MobileSubstrate/DynamicLibraries/APNsRoute.dylib'):
        (stage / relative).chmod(0o755)
    deb = packages / f"{metadata['Package']}_{version}_{metadata['Architecture']}.deb"
    run(['dpkg-deb', '--root-owner-group', '-Zgzip', '--build', str(stage), str(deb)])
    report.append('Package SHA-256: ' + hashlib.sha256(deb.read_bytes()).hexdigest())
    report.append('On configure, the package saves enabled mode and requests one apsd restart. The legacy conffile payload is retained to avoid a content-change prompt; postinst performs activation on fresh install, reinstall and upgrade.')
    run(['dpkg-deb', '--info', str(deb)])

(ROOT / 'BUILD-REPORT.txt').write_text('\n'.join(report) + '\n')
print('Created ' + str(deb))
