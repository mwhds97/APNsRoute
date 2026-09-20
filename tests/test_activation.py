#!/usr/bin/env python3
"""Exercise the real installer/controller with staged paths and fake process calls.

Accept an extracted package root to verify packaged scripts, or use layout/.
Only fixed install paths are remapped; routing and shell logic are not replaced.
"""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
stage = Path(sys.argv[1]) if len(sys.argv) > 1 else root / 'layout'
controller_source = (stage / 'usr/bin/apnsroutectl').read_text()
postinst_source = (stage / 'DEBIAN/postinst').read_text()
shell = shutil.which('sh')
assert shell

with tempfile.TemporaryDirectory(prefix='apnsroute-activation-') as directory:
    work = Path(directory)
    bins = work / 'bin'
    bins.mkdir()
    mode = work / 'settings/mode'
    mode.parent.mkdir()
    term_calls = work / 'term-calls'
    doctor_calls = work / 'doctor-calls'
    controller = work / 'apnsroutectl'
    postinst = work / 'postinst'
    doctor = work / 'doctor'

    def executable(path, text):
        path.write_text(text)
        path.chmod(0o755)

    # The only external process-control command available records its arguments.
    executable(bins / 'killall', '''#!/bin/sh
[ "$#" -eq 2 ] && [ "$1" = -TERM ] && [ "$2" = apsd ] || exit 77
printf '%s %s\\n' "$1" "$2" >> "$APNSROUTE_TEST_TERM_CALLS"
exit "${APNSROUTE_TEST_KILL_EXIT:-0}"
''')
    executable(bins / 'id', '''#!/bin/sh
[ "$#" -eq 1 ] && [ "$1" = -u ] || exit 77
printf '%s\\n' "${APNSROUTE_TEST_UID:-0}"
''')
    executable(doctor, '''#!/bin/sh
printf 'doctor\\n' >> "$APNSROUTE_TEST_DOCTOR_CALLS"
''')
    for name in ('chmod', 'rm'):
        target = shutil.which(name)
        assert target
        (bins / name).symlink_to(target)
    move = shutil.which('mv')
    assert move
    executable(bins / 'mv', '#!/bin/sh\n'
        'if [ "${APNSROUTE_TEST_WRITE_FAIL:-0}" = 1 ]; then exit 1; fi\n'
        'exec ' + shlex.quote(move) + ' "$@"\n')
    executable(controller, controller_source
        .replace("mode_path='/Library/Application Support/APNsRoute/mode'",
                 'mode_path=' + shlex.quote(str(mode)))
        .replace('/usr/libexec/apnsroute-diag', shlex.quote(str(doctor))))
    executable(postinst, postinst_source
        .replace('/usr/bin/apnsroutectl', shlex.quote(str(controller)))
        .replace("mode_path='/Library/Application Support/APNsRoute/mode'",
                 'mode_path=' + shlex.quote(str(mode))))
    environment = dict(os.environ, PATH=str(bins),
        APNSROUTE_TEST_TERM_CALLS=str(term_calls),
        APNSROUTE_TEST_DOCTOR_CALLS=str(doctor_calls))

    def reset(saved):
        if saved is None:
            mode.unlink(missing_ok=True)
        else:
            mode.write_text(saved)
        term_calls.write_text('')
        doctor_calls.write_text('')

    def run(script, *args, **settings):
        return subprocess.run([shell, str(script), *args],
            env=dict(environment, **settings), capture_output=True, text=True)

    def terms():
        return term_calls.read_text().splitlines()

    # Fresh install, missing setting, enabled/disabled experimental upgrade,
    # invalid legacy value, and release reinstall all save enabled mode.
    for saved in ('observe\n', None, 'unbind\n', 'disabled\n', 'invalid\n'):
        for prior in ((), ('1.1.0~experimental17',), ('1.1.0',), ('1.2.0',),
                      ('1.2.1~experimental1',), ('1.2.1~experimental2',), ('1.2.1',)):
            reset(saved)
            result = run(postinst, 'configure', *prior)
            assert result.returncode == 0, result.stderr
            assert mode.read_text() == 'unbind\n'
            assert mode.stat().st_mode & 0o777 == 0o644
            assert terms() == ['-TERM apsd']
            assert 'apnsroutectl doctor' in result.stdout
            assert not list(mode.parent.glob('mode.tmp.*'))

    # Non-configure maintainer-script actions have no activation side effects.
    reset('disabled\n')
    for action in ((), ('abort-upgrade',), ('triggered',)):
        result = run(postinst, *action)
        assert result.returncode == 0 and mode.read_text() == 'disabled\n' and not terms()

    # A failed process restart leaves a configured package and enabled setting,
    # with explicit recovery guidance rather than an extra TERM attempt.
    reset('observe\n')
    result = run(postinst, 'configure', APNSROUTE_TEST_KILL_EXIT='1')
    assert result.returncode == 0 and mode.read_text() == 'unbind\n'
    assert terms() == ['-TERM apsd']
    assert 'automatic activation did not complete' in result.stderr
    assert 'apnsroutectl restart' in result.stderr
    reset('observe\n')
    (bins / 'killall').rename(bins / 'unavailable-killall')
    result = run(postinst, 'configure')
    assert result.returncode == 0 and mode.read_text() == 'unbind\n' and not terms()
    assert 'automatic activation did not complete' in result.stderr
    (bins / 'unavailable-killall').rename(bins / 'killall')

    # Failed settings writes or non-root activation must not claim success.
    for settings in ({'APNSROUTE_TEST_WRITE_FAIL': '1'}, {'APNSROUTE_TEST_UID': '501'}):
        reset('disabled\n')
        result = run(postinst, 'configure', **settings)
        assert result.returncode == 1 and mode.read_text() == 'disabled\n' and not terms()
        assert 'Automatic enablement failed' in result.stderr
        assert not list(mode.parent.glob('mode.tmp.*'))

    # Manual controls remain available after automatic activation.
    reset('unbind\n')
    result = run(controller, 'disable')
    assert result.returncode == 0 and mode.read_text() == 'disabled\n'
    assert terms() == ['-TERM apsd']
    term_calls.write_text('')
    assert run(controller, 'status').returncode == 0
    assert run(controller, 'doctor').returncode == 0
    assert doctor_calls.read_text() == 'doctor\n'
    assert mode.read_text() == 'disabled\n' and not terms()
    for retired in ('logs', 'observe'):
        assert run(controller, retired).returncode == 2
        assert mode.read_text() == 'disabled\n' and not terms()

print('PASS: automatic enable/restart on install, upgrade and reinstall; failures, manual disable and read-only doctor')
