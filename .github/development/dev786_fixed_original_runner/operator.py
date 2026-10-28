from pathlib import Path
import hashlib
import json
import os
import platform
import resource
import selectors
import signal
import stat
import subprocess
import sys
import time

EXPECTED = {'preflight.py': {'bytes': 123782, 'sha256': '8527d05ae5bd268c83f17489050fa95e43f7f05cea299f092a3838bbcdc645df'}, 'test_prepare_original_r.py': {'bytes': 41453, 'sha256': '8b8a5ebc0ddcbfd545d868d34771abc1698fb87f44b30e7b1d3207e6459c340f'}, 'late_cycle_admission.py': {'bytes': 41624, 'sha256': '57d0149537c0d69078b4aa490510da434ede292e71de9d55abd2743f9ba78b64'}, 'original-r-api.json': {'bytes': 2784, 'sha256': 'fc6c12457844561262a9a8e92382ae53afe6c163214f77c9ae2e2cc4746f11fb'}}

CAPS = ((resource.RLIMIT_CPU, 240), (resource.RLIMIT_AS, 2147483648),
        (resource.RLIMIT_FSIZE, 268435456), (resource.RLIMIT_NPROC, 128),
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


def kill_control(child):
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        observed = os.waitid(os.P_PID, child.pid, os.WEXITED|os.WNOHANG|os.WNOWAIT)
        if observed is None or observed.si_pid != child.pid:
            raise ValueError('operator missing live control group')


def capture(child, paths, deadline):
    used = [0, 0]
    timed_out, overflow, fact = False, False, None
    owned, reaped = True, False
    selector = None
    files = []
    try:
        selector = selectors.DefaultSelector()
        for path in paths:
            files.append(path.open('xb'))
        for index, stream in enumerate((child.stdout, child.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, index)
        while True:
            if time.monotonic() >= deadline:
                timed_out = True
                break
            for key, unused in selector.select(min(.05, max(0, deadline-time.monotonic()))):
                index = key.data
                data = os.read(key.fd, min(65536, 524288-used[index]+1))
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                if used[index]+len(data) > 524288:
                    overflow = True
                    break
                files[index].write(data)
                used[index] += len(data)
            if overflow:
                break
            try:
                observed = os.waitid(os.P_PID, child.pid, os.WEXITED|os.WNOHANG|os.WNOWAIT)
            except ChildProcessError:
                owned = False
                raise ValueError('operator child ownership lost')
            if observed is not None and observed.si_pid:
                fact = observed
                if not selector.get_map():
                    break
        if timed_out or overflow:
            kill_control(child)
        cleanup_end = time.monotonic()+3
        while fact is None and time.monotonic() < cleanup_end:
            observed = os.waitid(os.P_PID, child.pid, os.WEXITED|os.WNOHANG|os.WNOWAIT)
            if observed is not None and observed.si_pid:
                fact = observed
                break
            time.sleep(.01)
        if fact is None:
            raise ValueError('operator child cleanup deadline')
        pid, status = os.waitpid(child.pid, os.WNOHANG)
        if pid != child.pid:
            raise ValueError('operator child reap')
        reaped, owned = True, False
        child.returncode = os.waitstatus_to_exitcode(status)
        if overflow:
            raise ValueError('operator output limit')
        return child.returncode, timed_out
    finally:
        primary = sys.exception()
        try:
            if owned and not reaped:
                try:
                    os.waitid(os.P_PID, child.pid, os.WEXITED|os.WNOHANG|os.WNOWAIT)
                except ChildProcessError:
                    owned = False
                if owned:
                    kill_control(child)
                    stop = time.monotonic()+3
                    while time.monotonic() < stop:
                        fact = os.waitid(os.P_PID, child.pid, os.WEXITED|os.WNOHANG|os.WNOWAIT)
                        if fact is not None and fact.si_pid:
                            pid, status = os.waitpid(child.pid, os.WNOHANG)
                            if pid != child.pid:
                                raise ValueError('operator final reap')
                            child.returncode = os.waitstatus_to_exitcode(status)
                            break
                        time.sleep(.01)
                    else:
                        raise ValueError('operator final cleanup deadline')
        except BaseException as error:
            if primary is None:
                raise
            primary.add_note('Operator cleanup failure: '+type(error).__name__)
        finally:
            errors = []
            for resource_owner in (selector, child.stdout, child.stderr, *files):
                if resource_owner is None:
                    continue
                try:
                    resource_owner.close()
                except BaseException as error:
                    errors.append(error)
            if child.returncode is None:
                # Prevent an implicit reap after explicit ownership has ended.
                child._child_created = False
            if errors:
                if primary is None:
                    raise errors[0]
                primary.add_note('Operator stream closure failed: '+type(errors[0]).__name__)


def main():
    end = time.monotonic() + 300
    if len(sys.argv) != 1 or sys.platform != 'linux' or sys.version_info[:2] != (3, 12):
        raise ValueError('operator platform or invocation')
    release = platform.freedesktop_os_release()
    if release.get('ID') != 'ubuntu' or release.get('VERSION_ID') != '24.04' or platform.machine() != 'x86_64':
        raise ValueError('operator host')
    expected_context = {
        'GITHUB_REPOSITORY': 'nold-ai/.github',
        'GITHUB_REPOSITORY_ID': '1110267669',
        'GITHUB_REPOSITORY_OWNER_ID': '225190663',
        'GITHUB_REF': 'refs/heads/codex/dev786-fixed-r-preparation-14',
        'GITHUB_EVENT_NAME': 'push', 'GITHUB_RUN_ATTEMPT': '1',
    }
    if any(os.environ.get(key) != value for key, value in expected_context.items()):
        raise ValueError('operator context')
    os.umask(0o077)
    root = Path(os.environ['RUNNER_TEMP']) / 'dev786-fixed-r-preparation-14'
    root.mkdir(mode=0o700)
    export = root / 'export'
    export.mkdir(mode=0o700)
    sources = export / 'sources'
    sources.mkdir(mode=0o700)
    source = Path(__file__).resolve().parent
    source_paths = {
        'preflight.py': source / 'preflight.py',
        'test_prepare_original_r.py': source / 'test_prepare_original_r.py',
        'late_cycle_admission.py': source.parents[1] / 'scripts' / 'late_cycle_admission.py',
        'original-r-api.json': source / 'original-r-api.json',
    }
    fixture_root = Path(os.environ['GITHUB_WORKSPACE']) / '.ci-core-fixture'
    runtime_helper = root / 'scripts' / 'late_cycle_admission.py'
    report = {'claim': 'UNCLASSIFIED DEVELOPMENT PREPARATION CONTROL RESULTS ONLY',
              'native_red': False, 'https_production_proof': False, 'readiness': False,
              'cases': [],
              'context': {key: os.environ.get(key) for key in
                          (*expected_context, 'GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_JOB',
                           'GITHUB_WORKSPACE', 'GITHUB_WORKFLOW_REF', 'GITHUB_WORKFLOW_SHA')},
              'host': {'release': release, 'machine': platform.machine(), 'kernel': platform.release(),
                       'python': sys.executable, 'resolved_python': str(Path(sys.executable).resolve()),
                       'version': sys.version},
              'fixture': {'path': str(fixture_root),
                          'repository': 'nold-ai/specfact-cli',
                          'ref': '4ae6175a4d337296d0347e73b66c9da1f0e43f7f',
                          'fetch_depth': 2, 'kind': 'trusted read-only checkout input',
                          'exported': False,
                          'candidate_postfetch_bound': {'entries': 20000, 'bytes': 268435456}},
              'metadata': 'Historical public JSON used only as Synthetic API test input',
              'envelope': {'wall_seconds': 300, 'reserved_seconds': 25,
                           'per_log_bytes': 524288, 'aggregate_log_bytes': 2097152,
                           'control_storage_bytes': 8388608, 'footer_bytes': 65536,
                           'resource_caps': list(CAPS)}}
    exit_code = 1
    try:
        operator = read_fixed(Path(__file__).resolve(), 131072)
        report['operator'] = identity(operator)
        (sources / 'operator.py').write_bytes(operator)
        (sources / 'operator.py').chmod(0o400)
        report['interpreter'] = identity(read_fixed(Path(sys.executable).resolve(), 67108864))
        if set(EXPECTED) != set(source_paths):
            raise ValueError('source membership')
        for name, expected in EXPECTED.items():
            raw = read_fixed(source_paths[name], 131072)
            if identity(raw) != expected:
                raise ValueError('reviewed source identity')
            target = sources / name
            target.write_bytes(raw)
            target.chmod(0o400)
        report['sources'] = {name: {'path': str(source_paths[name]), **expected}
                             for name, expected in EXPECTED.items()}
        runtime_helper.parent.mkdir(mode=0o700)
        runtime_helper.write_bytes(read_fixed(sources / 'late_cycle_admission.py', 131072))
        runtime_helper.chmod(0o400)
        helper_identity = identity(read_fixed(runtime_helper, 131072))
        if helper_identity != EXPECTED['late_cycle_admission.py']:
            raise ValueError('runtime helper identity')
        if 2 * helper_identity['bytes'] > 262144:
            raise ValueError('helper storage bound')
        python_bytes = len(operator) + sum(expected['bytes'] for name, expected in EXPECTED.items()
                                          if name.endswith('.py'))
        if python_bytes >= 393216:
            raise ValueError('unique executed source bound')
        report['runtime_helper'] = {'used_path': str(runtime_helper),
                                    'retained_path': str(sources / 'late_cycle_admission.py'),
                                    **helper_identity, 'copies': 2,
                                    'charged_bytes': 2 * helper_identity['bytes'],
                                    'before_equal': True}
        report['unique_executed_python_bytes'] = python_bytes
        if not fixture_root.is_absolute() or not (fixture_root / 'original.git' / '.git').is_dir():
            raise ValueError('fixed checkout fixture')
        case = root / '0'
        case.mkdir(mode=0o700)
        for name in ('home', 'tmp', 'cwd'):
            (case / name).mkdir(mode=0o700)
        limits_path = export / '0-limits.json'
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
               'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8'}
        paths = [export / '0.stdout', export / '0.stderr']
        argv = [sys.executable, '-I', '-S', str(sources / 'test_prepare_original_r.py'),
                '--candidate', str(sources / 'preflight.py'), '--full',
                '--fixture-root', str(fixture_root),
                '--r-metadata', str(sources / 'original-r-api.json')]
        case_record = {'selected': 'RealGitSyntheticAPI', 'expected_tests': 21,
                       'argv': argv, 'cwd': str(case / 'cwd'), 'environment': env,
                       'invocation_kind': 'direct Popen request'}
        report['cases'].append(case_record)
        if time.monotonic() >= end - 25:
            raise ValueError('operator setup deadline')
        child = subprocess.Popen(argv, cwd=case / 'cwd', env=env,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 close_fds=True, pass_fds=(), start_new_session=True,
                                 preexec_fn=apply_limits)
        status, timed_out = capture(child, paths, end - 25)
        case_record.update(exit_code=status, timed_out=timed_out,
                           streams=[identity(read_fixed(path, 524288)) for path in paths])
        if timed_out or time.monotonic() >= end - 1:
            raise ValueError('operator deadline')
        for name, expected in EXPECTED.items():
            if identity(read_fixed(source_paths[name], 131072)) != expected or identity(read_fixed(sources / name, 131072)) != expected:
                raise ValueError('source drift')
        if identity(read_fixed(runtime_helper, 131072)) != helper_identity:
            raise ValueError('runtime helper drift')
        if identity(read_fixed(Path(__file__).resolve(), 131072)) != report['operator'] or identity(read_fixed(sources / 'operator.py', 131072)) != report['operator']:
            raise ValueError('operator source drift')
        report['runtime_helper']['after_equal'] = True
        storage = sum(path.stat().st_size for path in export.rglob('*') if path.is_file()) + runtime_helper.stat().st_size
        if storage > 8*1048576-65536:
            raise ValueError('control storage bound')
        report['charged_control_bytes_before_footer'] = storage
        if time.monotonic() >= end:
            raise ValueError('operator deadline')
        report['source_unchanged'] = True
        exit_code = 0 if status == 0 else 1
    except BaseException as error:
        report['operator_error'] = type(error).__name__
    finally:
        report['elapsed_seconds'] = 300 - (end - time.monotonic())
        raw = json.dumps(report, sort_keys=True).encode()
        if len(raw) > 65536:
            raise ValueError('receipt bound')
        (export / 'receipt.json').write_bytes(raw)
    return exit_code


if __name__ == '__main__':
    raise SystemExit(main())
