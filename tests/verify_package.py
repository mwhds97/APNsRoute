#!/usr/bin/env python3
"""Check release contents, absence of runtime logging, and signature hashes."""
import hashlib
from pathlib import Path
import plistlib
import struct
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
expected_metadata = dict(line.split(': ', 1) for line in (root / 'control').read_text().splitlines() if ': ' in line)
version = expected_metadata['Version']
assert expected_metadata['Name'] == 'APNsRoute' and version == '1.1.0'
subprocess.run(['dpkg', '--compare-versions', version, 'gt', '1.1.0~experimental17'], check=True)
assert f'#define APR_VERSION "{version}"' in (root / 'src/Version.h').read_text()
deb = root / 'packages' / f"{expected_metadata['Package']}_{version}_{expected_metadata['Architecture']}.deb"

def verify_slice(blob, filetype=6):
    header = struct.unpack_from('<8I', blob)
    assert header[0] == 0xfeedfacf and header[1] == 0x100000c and header[3] == filetype
    cursor = 32
    signature = None
    symbols = None
    for _ in range(header[4]):
        command, length = struct.unpack_from('<II', blob, cursor)
        assert length >= 8
        if command == 0x1d:
            offset, size = struct.unpack_from('<II', blob, cursor + 8)
            signature = blob[offset:offset + size]
        if command == 0x2:
            symbols = struct.unpack_from('<4I', blob, cursor + 8)
        cursor += length
    assert signature is not None
    assert symbols is not None
    symoff, nsyms, stroff, strsize = symbols
    assert symoff + nsyms * 16 <= len(blob) and stroff + strsize <= len(blob)
    imports = set()
    strings = blob[stroff:stroff + strsize]
    for index in range(nsyms):
        string_index, symbol_type, _, _, _ = struct.unpack_from('<IBBHQ', blob, symoff + index * 16)
        if string_index and (symbol_type & 0x0e) == 0:
            imports.add(strings[string_index:].split(b'\0', 1)[0].decode())
    assert not any(name.startswith(('_os_log', '__os_log')) for name in imports), imports
    if filetype == 6:
        assert not imports.intersection({'_write', '_fwrite', '_fprintf', '_printf', '_syslog'})
        assert '_notify_set_state' in imports
        assert '_inet_pton' in imports
        assert not imports.intersection({'_getaddrinfo', '_gethostbyname', '_getnameinfo', '_nw_endpoint_get_port'})
        for rule in (b'identity.apple.com', b'push.apple.com', b'akadns.net', b'apple.com.edgekey.net'):
            assert rule in blob, rule
        assert b'_apr_courier_host' not in blob and b'_apr_endpoint_target' not in blob
        assert {'__Block_object_assign', '__Block_object_dispose',
                '_nw_connection_copy_endpoint',
                '_nw_error_get_error_domain', '_nw_error_get_error_code',
                '_nw_connection_access_establishment_report',
                '_nw_establishment_report_get_proxy_configured',
                '_nw_establishment_report_get_used_proxy',
                '_nw_connection_copy_current_path',
                '_nw_path_get_status', '_nw_path_uses_interface_type'} <= imports
        assert b'nw_path_get_unsatisfied_reason' in blob
        assert b'requiredAddressFamily' not in blob
        assert not any(name.startswith(('_objc_', '_CF', '_sel_')) for name in imports)
        assert not imports.intersection({'_nw_parameters_copy', '_nw_connection_copy_parameters', '_nw_establishment_report_copy_proxy_endpoint'})
        # Observers never initiate cancellation or change a callback queue.
        assert not imports.intersection({'_nw_connection_cancel', '_nw_connection_force_cancel', '_nw_connection_set_queue'})
        assert not imports.intersection({'_CFReadStreamSetProperty', '_CFWriteStreamSetProperty',
            '_nw_parameters_require_interface', '_nw_parameters_clear_prohibited_interfaces',
            '_nw_parameters_set_prohibit_expensive', '_send', '_recv', '_connect', '_connectx'})
        assert b'setProxyConfiguration:' not in blob and b'setNoProxy:' not in blob
        assert b'necp-binding-result-index' in blob
        assert b'necp-constraints-first' in blob
        assert b'necp-agent-name-15' in blob
        assert b'necp-prohibited-types-7' in blob
    for forbidden in (b'APNsRoute.log', b'local.apnsroute.v1.', b'_apr_note', b'_apr_open_log', b'NWParameters', b'setInternalParameters:', b'socks-probe', b'nw-family', b'nw-route-before', b'nw-handler-parameters'):
        assert forbidden not in blob, forbidden
    magic, size, count = struct.unpack_from('>III', signature)
    assert magic == 0xfade0cc0 and size <= len(signature)
    directories = 0
    for index in range(count):
        slot, offset = struct.unpack_from('>II', signature, 12 + index * 8)
        if slot != 0 and not (0x1000 <= slot <= 0x1005):
            continue
        directory = signature[offset:]
        fields = struct.unpack_from('>9I', directory)
        assert fields[0] == 0xfade0c02
        _, size, _, flags, hashes, _, _, pages, code_limit = fields
        hash_size, hash_type, _, page_bits = struct.unpack_from('4B', directory, 36)
        assert flags & 2  # CS_ADHOC
        assert hash_type in (1, 2)
        algorithm = hashlib.sha1 if hash_type == 1 else hashlib.sha256
        page_size = 1 << page_bits
        assert pages == (code_limit + page_size - 1) // page_size
        for page in range(pages):
            start, end = page * page_size, min((page + 1) * page_size, code_limit)
            expected = algorithm(blob[start:end]).digest()[:hash_size]
            position = hashes + page * hash_size
            assert position + hash_size <= size
            assert expected == directory[position:position + hash_size]
        directories += 1
    assert directories
    return header[2]

with tempfile.TemporaryDirectory(prefix='apnsroute-verify-') as temp:
    stage = Path(temp)
    subprocess.run(['dpkg-deb', '--raw-extract', str(deb), temp], check=True)
    # Retain the prior conffile payload to avoid upgrade prompts; postinst
    # writes enabled mode and restarts apsd. Test that actual script below.
    assert (stage / 'Library/Application Support/APNsRoute/mode').read_text() == 'observe\n'
    plist_path = stage / 'Library/MobileSubstrate/DynamicLibraries/APNsRoute.plist'
    assert plistlib.loads(plist_path.read_bytes()) == {'Filter': {'Executables': ['apsd']}}
    metadata = (stage / 'DEBIAN/control').read_text()
    assert 'Package: local.apnsroute\n' in metadata
    assert metadata == (root / 'control').read_text()
    assert 'firmware (<< 15.0)' in metadata
    assert 'mobilesubstrate | com.ex.substitute' in metadata
    assert (stage / 'DEBIAN/conffiles').read_text() == '/Library/Application Support/APNsRoute/mode\n'
    for path in ('DEBIAN/postinst', 'DEBIAN/postrm', 'usr/bin/apnsroutectl'):
        assert (stage / path).stat().st_mode & 0o111
        subprocess.run(['sh', '-n', str(stage / path)], check=True)
    data = (stage / 'Library/MobileSubstrate/DynamicLibraries/APNsRoute.dylib').read_bytes()
    magic, count = struct.unpack_from('>II', data)
    assert magic == 0xcafebabe and count == 2
    subtypes = set()
    for index in range(count):
        cpu, subtype, offset, size, _ = struct.unpack_from('>5I', data, 8 + 20 * index)
        assert cpu == 0x100000c
        assert subtype == verify_slice(data[offset:offset + size])
        subtypes.add(subtype & 0xffffff)
    assert subtypes == {0, 2}
    helper = stage / 'usr/libexec/apnsroute-diag'
    assert helper.stat().st_mode & 0o111
    assert verify_slice(helper.read_bytes(),filetype=2) & 0xffffff == 0
    controller = (stage / 'usr/bin/apnsroutectl').read_text()
    assert 'exec /usr/libexec/apnsroute-diag' in controller and 'APNsRoute.log' not in controller
    assert 'local.apnsroute.v1' not in controller
    assert version.encode() in helper.read_bytes()
    assert 'experimental' not in metadata
    assert 'experimental' not in controller
    assert 'experimental' not in (stage / 'DEBIAN/postinst').read_text()
    assert 'APNsRoute doctor 1.' not in controller
    subprocess.run(['python3', str(root / 'tests/test_activation.py'), str(stage)], check=True)
    for retired in ('logs', 'observe'):
        result = subprocess.run(['sh', str(stage / 'usr/bin/apnsroutectl'), retired],
                                capture_output=True, text=True)
        assert result.returncode == 2

print('PASS: release metadata/configuration, apsd-only filter, doctor helper, rejected log command, no runtime logging imports, both signed dylib slices and signed helper page hashes')
