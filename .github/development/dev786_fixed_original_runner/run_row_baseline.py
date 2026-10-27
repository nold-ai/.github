from pathlib import Path
import hashlib
import json
import os
import platform
import resource
import signal
import stat
import subprocess
import sys
import time

EXPECTED = {
    'preflight.py': {'bytes': 77699, 'sha256': 'e436751e548d4b18bbb41b6e71b70bca87faa68e665a84b6932aaf4fbb4f39a8'},
    'test_fixed_rows.py': {'bytes': 29916, 'sha256': '92047cd499cff47ad12f4d8e851f046fe16b40ced4ab3c17aac5ea2097140dc6'},
}
SELECTED = (
    'FixedRows.test_exact_four_vectors_are_passive_and_immutable',
    'FixedRows.test_literal_bootstrap_real_exit_environment_fd_and_session_PLANNER',
)
CAPS = ((resource.RLIMIT_CPU, 80), (resource.RLIMIT_AS, 2147483648),
        (resource.RLIMIT_FSIZE, 262144), (resource.RLIMIT_NPROC, 128),
        (resource.RLIMIT_CORE, 0))


def read_fixed(path, limit):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise ValueError('source kind or bound')
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    after = path.lstat()
    fields = lambda value: (value.st_dev, value.st_ino, value.st_size,
                            value.st_mtime_ns, value.st_ctime_ns)
    if fields(before) != fields(after) or len(raw) != before.st_size:
        raise ValueError('source changed or incomplete')
    return raw


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def main():
    end = time.monotonic() + 60
    if len(sys.argv) != 1 or sys.platform != 'linux' or sys.version_info[:2] != (3, 12):
        raise ValueError('operator platform or invocation')
    release = platform.freedesktop_os_release()
    if release.get('ID') != 'ubuntu' or release.get('VERSION_ID') != '24.04' or platform.machine() != 'x86_64':
        raise ValueError('operator host')
    expected_context = {
        'GITHUB_REPOSITORY': 'nold-ai/.github',
        'GITHUB_REPOSITORY_ID': '1110267669',
        'GITHUB_REPOSITORY_OWNER_ID': '225190663',
        'GITHUB_REF': 'refs/heads/codex/dev786-fixed-row-baseline-01',
        'GITHUB_EVENT_NAME': 'push', 'GITHUB_RUN_ATTEMPT': '1',
    }
    if any(os.environ.get(key) != value for key, value in expected_context.items()):
        raise ValueError('operator context')
    os.umask(0o077)
    root = Path(os.environ['RUNNER_TEMP']) / 'dev786-fixed-row-baseline-01'
    root.mkdir(mode=0o700)
    export = root / 'export'
    export.mkdir(mode=0o700)
    sources = export / 'sources'
    sources.mkdir(mode=0o700)
    source = Path(__file__).resolve().parent
    report = {'claim': 'UNCLASSIFIED DEVELOPMENT MISSING-NEW BASELINE ONLY',
              'native_red': False, 'readiness': False, 'cases': [],
              'context': {key: os.environ.get(key) for key in (*expected_context, 'GITHUB_SHA', 'GITHUB_RUN_ID')},
              'host': {'release': release, 'machine': platform.machine(), 'kernel': platform.release(),
                       'python': sys.executable, 'resolved_python': str(Path(sys.executable).resolve()),
                       'version': sys.version}}
    exit_code = 1
    try:
        operator = read_fixed(Path(__file__).resolve(), 131072)
        report['operator'] = identity(operator)
        (sources / 'run_row_baseline.py').write_bytes(operator)
        report['interpreter'] = identity(read_fixed(Path(sys.executable).resolve(), 67108864))
        for name, expected in EXPECTED.items():
            raw = read_fixed(source / name, 131072)
            if identity(raw) != expected:
                raise ValueError('reviewed source identity')
            target = sources / name
            target.write_bytes(raw)
            target.chmod(0o400)
        if set(EXPECTED) != {'preflight.py', 'test_fixed_rows.py'}:
            raise ValueError('source membership')
        report['sources'] = EXPECTED
        for number, selected in enumerate(SELECTED):
            case = root / str(number)
            case.mkdir(mode=0o700)
            for name in ('home', 'tmp', 'cwd'):
                (case / name).mkdir(mode=0o700)
            limits_path = export / f'{number}-limits.json'
            def apply_limits():
                signal.signal(signal.SIGALRM, signal.SIG_DFL)
                signal.pthread_sigmask(signal.SIG_SETMASK, set())
                limits = []
                for kind, cap in CAPS:
                    inherited = resource.getrlimit(kind)
                    bound = min([cap] + [value for value in inherited if value != resource.RLIM_INFINITY])
                    resource.setrlimit(kind, (bound, bound))
                    limits.append({'resource': kind, 'inherited': inherited,
                                   'applied': resource.getrlimit(kind)})
                limits_path.write_text(json.dumps(limits))
            env = {'HOME': str(case / 'home'), 'TMPDIR': str(case / 'tmp'),
                   'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8',
                   'FIXED_PREFLIGHT_PATH': str(sources / 'preflight.py')}
            paths = [export / f'{number}.stdout', export / f'{number}.stderr']
            argv = [sys.executable, '-I', '-S', str(sources / 'test_fixed_rows.py'), selected, '-v']
            case_record = {'selected': selected, 'argv': argv, 'cwd': str(case / 'cwd'),
                           'environment': env, 'invocation_kind': 'direct Popen request'}
            report['cases'].append(case_record)
            with paths[0].open('xb') as out, paths[1].open('xb') as err:
                child = subprocess.Popen(argv, cwd=case / 'cwd', env=env,
                                         stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                         close_fds=True, pass_fds=(), start_new_session=True,
                                         preexec_fn=apply_limits)
                timed_out = False
                try:
                    status = child.wait(timeout=max(0.001, min(50, end - time.monotonic() - 5)))
                except subprocess.TimeoutExpired:
                    timed_out = True
                    os.killpg(child.pid, signal.SIGKILL)
                    status = child.wait(timeout=3)
            case_record.update(exit_code=status, timed_out=timed_out,
                               streams=[identity(read_fixed(path, 262144)) for path in paths])
            if timed_out or time.monotonic() >= end - 1:
                raise ValueError('operator deadline')
        for name, expected in EXPECTED.items():
            if identity(read_fixed(source / name, 131072)) != expected or identity(read_fixed(sources / name, 131072)) != expected:
                raise ValueError('source drift')
        if time.monotonic() >= end:
            raise ValueError('operator deadline')
        report['source_unchanged'] = True
        exit_code = 0 if all(case['exit_code'] == 0 for case in report['cases']) else 1
    except BaseException as error:
        report['operator_error'] = type(error).__name__
    finally:
        report['elapsed_seconds'] = 60 - (end - time.monotonic())
        raw = json.dumps(report, sort_keys=True).encode()
        if len(raw) > 65536:
            raise ValueError('receipt bound')
        (export / 'receipt.json').write_bytes(raw)
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
