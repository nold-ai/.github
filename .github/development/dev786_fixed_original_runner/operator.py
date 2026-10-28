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

EXPECTED = {'preflight.py': {'bytes': 229889, 'sha256': 'c53176bfaf223be69eaf33648943abc1798692ec6087fdea6b12df4f0b672793'}, 'test_fixed_rows.py': {'bytes': 36812, 'sha256': '3e73ab95883f43c8dac7953e8e963195016eaf8d542d27c2e3a7e4cbb0e913c1'}, 'test_row_boundaries.py': {'bytes': 40806, 'sha256': 'a7628b094fa993b147cbd500f55eabb3a9de848ed17ba63364c3ce2000c861a8'}, 'fixed-r-preparation.yml': {'bytes': 15939, 'sha256': '68831c84a84280545ace87461469350b59faeb82e76a9dffaaa96486786e6594'}, 'Dockerfile.shared-git-after': {'bytes': 401, 'sha256': 'f317e7b4a3a9a7352b698a2fefb89f8498a7d894ae2ee0be5f72026d03c33f81'}}
SELECTED = ('base.FixedRows.test_literal_bootstrap_real_exit_environment_fd_and_session_PLANNER', 'base.FixedRows.test_literal_bootstrap_real_exit_environment_fd_and_session_EXECUTOR', 'base.FixedRows.test_literal_bootstrap_real_exit_environment_fd_and_session_RECONCILER', 'base.FixedRows.test_literal_bootstrap_real_exit_environment_fd_and_session_BINDER', 'base.FixedRows.test_real_repeated_wnowait_precedes_reap_and_no_later_group_signal', 'base.FixedRows.test_leader_exits_before_same_group_child_is_cleaned', 'base.FixedRows.test_real_elapsed_alarm_preserves_owner_deadline', 'base.FixedRows.test_echild_is_not_a_success_or_group_kill_permission', 'RowBoundaries.test_row_specific_echild_forbids_later_group_signal', 'RowBoundaries.test_tighter_soft_and_hard_limits_in_disposable_parent')
RETAINED = {'preflight.py': '.github/development/dev786_fixed_original_runner/preflight.py', 'test_fixed_rows.py': 'test_fixed_rows.py', 'test_row_boundaries.py': 'test_row_boundaries.py', 'fixed-r-preparation.yml': 'fixed-r-preparation.yml', 'Dockerfile.shared-git-after': 'Dockerfile.shared-git-after'}

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
        'GITHUB_REF': 'refs/heads/codex/dev786-process-controls-after-19',
        'GITHUB_EVENT_NAME': 'push', 'GITHUB_RUN_ATTEMPT': '1',
    }
    if any(os.environ.get(key) != value for key, value in expected_context.items()):
        raise ValueError('operator context')
    os.umask(0o077)
    root = Path(os.environ['RUNNER_TEMP']) / 'dev786-process-controls-after-19'
    root.mkdir(mode=0o700)
    export = root.parent.parent / 'export'
    export_stat = export.lstat()
    if not stat.S_ISDIR(export_stat.st_mode) or export_stat.st_uid != os.getuid() or stat.S_IMODE(export_stat.st_mode) != 0o700:
        raise ValueError('fresh host export ownership')
    sources = export / 'sources'
    sources.mkdir(mode=0o700)
    source = Path(__file__).resolve().parent
    source_paths = {
        'preflight.py': source / 'preflight.py',
        'test_fixed_rows.py': source / 'test_fixed_rows.py',
        'test_row_boundaries.py': source / 'test_row_boundaries.py',
        'fixed-r-preparation.yml': source.parents[1] / 'workflows' / 'fixed-r-preparation.yml',
        'Dockerfile.shared-git-after': source / 'Dockerfile.shared-git-after',
    }
    report = {'claim': 'AFTER_PROCESS_COMPONENT_EVIDENCE_ONLY',
              'native_red': False, 'https_production_proof': False, 'readiness': False,
              'cases': [], 'fixed_group': 'process-after10', 'selected': SELECTED,
              'context': {key: os.environ.get(key) for key in
                          (*expected_context, 'GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_JOB',
                           'GITHUB_WORKSPACE', 'GITHUB_WORKFLOW_REF', 'GITHUB_WORKFLOW_SHA')},
              'host': {'release': release, 'machine': platform.machine(), 'kernel': platform.release(),
                       'python': sys.executable, 'resolved_python': str(Path(sys.executable).resolve()),
                       'version': sys.version},
              'fixture': 'Unchanged W2 stdlib synthetic children; no public R checkout',
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
        if set(EXPECTED) != set(source_paths) or set(RETAINED) != set(EXPECTED):
            raise ValueError('source membership')
        for name, expected in EXPECTED.items():
            raw = read_fixed(source_paths[name], expected['bytes'])
            if identity(raw) != expected:
                raise ValueError('reviewed source identity')
            target = sources / RETAINED[name]
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(raw)
            target.chmod(0o400)
        report['sources'] = {name: {'path': str(source_paths[name]), **expected}
                             for name, expected in EXPECTED.items()}
        host_raw = read_fixed(export / 'environment-host.json', 4096)
        host_facts = json.loads(host_raw)
        packages = read_fixed(Path('/dev786-image-packages.txt'), 8192)
        (export / 'environment-packages.txt').write_bytes(packages)
        python_bytes = len(operator) + sum(item['bytes'] for name, item in EXPECTED.items() if name.endswith('.py'))
        package_bytes = len(operator) + sum(item['bytes'] for item in EXPECTED.values()) + len(host_raw) + len(packages) + 3072 + 1024 + 1024 + 1024 + 72
        helper_bytes = package_bytes - EXPECTED['preflight.py']['bytes']
        if python_bytes >= 393216 or package_bytes >= 393216 or helper_bytes > 262144:
            raise ValueError('complete source or helper bound')
        report['package_bytes_with_future_environment_reservations'] = package_bytes
        report['helper_bytes_all_non_candidate_members'] = helper_bytes
        report['unique_executed_python_bytes'] = python_bytes
        report['environment_host'] = {'identity': identity(host_raw), 'facts': host_facts}
        report['packages'] = identity(packages)
        if os.getuid() == 0 or os.getuid() != os.geteuid() or os.getuid() != host_facts['host']['uid'] or os.getgid() != host_facts['host']['gid'] or set(os.getgroups()) - {os.getgid()}:
            raise ValueError('same host nonroot identity')
        status_fields = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
        if any(int(status_fields[k].strip(), 16) for k in ('CapEff', 'CapPrm', 'CapAmb')) or status_fields['Seccomp'].strip() != '2':
            raise ValueError('container capabilities or seccomp')
        uid_map = Path('/proc/self/uid_map').read_text().split()
        if uid_map != ['0', '0', '4294967295']:
            raise ValueError('unsupported user namespace')
        apparmor = Path('/proc/self/attr/current').read_text().strip()
        if apparmor != 'docker-default (enforce)':
            raise ValueError('container default AppArmor')
        init_argv = Path('/proc/1/cmdline').read_bytes().split(b'\0')
        expected_init = [b'/sbin/docker-init', b'--', b'/usr/bin/python3', b'-I', b'-S', os.fsencode(Path(__file__).resolve()), b'']
        if init_argv != expected_init or os.getppid() != 1:
            raise ValueError('ordinary ambient PID1 init')
        inherited_pairs = []
        for kind, cap in CAPS:
            pair = resource.getrlimit(kind)
            if kind != resource.RLIMIT_AS and pair != (cap, cap):
                raise ValueError('container fixed inherited limits')
            inherited_pairs.append({'resource': kind, 'inherited': pair})
        report['container_as_inherited'] = resource.getrlimit(resource.RLIMIT_AS)
        report['container'] = {'uid': os.getuid(), 'euid': os.geteuid(), 'gid': os.getgid(),
                               'groups': os.getgroups(), 'uid_map': uid_map, 'apparmor': apparmor,
                               'caps': {k: status_fields[k].strip() for k in ('CapEff','CapPrm','CapAmb','Seccomp')},
                               'init_argv': [os.fsdecode(x) for x in init_argv], 'inherited_limits': inherited_pairs,
                               'init': identity(read_fixed(Path('/proc/1/exe').resolve(), 16777216)),
                               'git': identity(read_fixed(Path('/usr/bin/git').resolve(), 67108864)),
                               'git_https': identity(read_fixed(Path('/usr/lib/git-core/git-remote-https').resolve(), 67108864))}
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
               'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8',
               'FIXED_PREFLIGHT_PATH': str(sources / RETAINED['preflight.py']),
               'FIXED_ROWS_HELPER_PATH': str(sources / 'test_fixed_rows.py')}
        paths = [export / '0.stdout', export / '0.stderr']
        argv = [sys.executable, '-I', '-S', str(sources / 'test_row_boundaries.py'), '-v', *SELECTED]
        case_record = {'selected': SELECTED, 'expected_tests': len(SELECTED),
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
            if identity(read_fixed(source_paths[name], expected['bytes'])) != expected or identity(read_fixed(sources / RETAINED[name], expected['bytes'])) != expected:
                raise ValueError('source drift')
        if identity(read_fixed(Path(__file__).resolve(), 131072)) != report['operator'] or identity(read_fixed(sources / 'operator.py', 131072)) != report['operator']:
            raise ValueError('operator source drift')
        if {p.relative_to(sources).as_posix() for p in sources.rglob('*') if p.is_file()} != set(RETAINED.values()) | {'operator.py'}:
            raise ValueError('closed retained source membership')
        if identity(read_fixed(export / 'environment-host.json', 4096)) != identity(host_raw):
            raise ValueError('host facts drift')
        storage = sum(path.stat().st_size for path in export.rglob('*') if path.is_file()) + 3072 + 1024 + 1024 + 1024 + 72
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
