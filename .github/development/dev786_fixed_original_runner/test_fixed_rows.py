from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import tempfile
import unittest
from contextlib import ExitStack, contextmanager
from unittest import mock

FIXED_PREFLIGHT_PATH = Path(os.environ['FIXED_PREFLIGHT_PATH'])
if not FIXED_PREFLIGHT_PATH.is_absolute():
    raise ValueError('FIXED_PREFLIGHT_PATH must be explicit and absolute')
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location('fixed_row_candidate', FIXED_PREFLIGHT_PATH)
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)

CLI = b'import sys; site_packages, trusted_core = sys.argv[1:3]; del sys.argv[1:3]; sys.path.append(site_packages); sys.path.insert(0, trusted_core); from specfact_cli.cli import cli_main; cli_main()'
SCRIPT = b'import runpy, sys; sys.path.append(sys.argv.pop(1)); script = sys.argv.pop(1); runpy.run_path(script, run_name="__main__")'
BASE = b'9b5ad1e78430cc0b061cb16de42f73de96f4f312'
SOURCE = b'4ae6175a4d337296d0347e73b66c9da1f0e43f7f'
CHANGE = b'openspec/changes/security-dependencies-0-55-11-dev'



def missing_body(target, message, *args):
    try:
        return target(*args)
    except NotImplementedError as error:
        terminal = error.__traceback__
        while terminal.tb_next is not None:
            terminal = terminal.tb_next
        if (type(error) is NotImplementedError and error.args == (message,)
                and terminal.tb_frame.f_code is target.__code__):
            raise AssertionError(message) from error
        raise


def expected(tool, paths):
    py, site, core, modules, uv, root, out, home, tmp = map(os.fsencode, (
        tool.python, tool.site_packages, tool.core_root, tool.modules_root, tool.uv,
        paths.root, paths.out, paths.home, paths.tmp))
    cli = (py, b'-I', b'-S', b'-c', CLI, site, core + b'/src')
    script = (py, b'-I', b'-S', b'-c', SCRIPT, site)
    argv = (
        cli + (b'requirements', b'evidence', b'--repo-root', root, b'--base-ref', BASE,
               b'--required-maturity', b'test-authored', b'--review-evidence',
               root + b'/' + CHANGE + b'/requirements-proof/review-evidence.json',
               b'--plan-output', out + b'/plan.json', b'--output', out + b'/planning-report.json',
               b'--summary', out + b'/planning-summary.md'),
        script + (core + b'/scripts/requirements_proof_executor.py', b'--plan', out + b'/plan.json',
                  b'--repo-root', root, b'--junit', out + b'/requirements-proof.xml'),
        cli + (b'requirements', b'reconcile', b'--plan', out + b'/plan.json', b'--junit',
               out + b'/requirements-proof.xml', b'--run-stage', b'red', b'--source-ref', SOURCE,
               b'--output', out + b'/local-red-report.json', b'--summary', out + b'/local-red-summary.md'),
        script + (core + b'/scripts/requirements_proof_provenance.py', b'--bind-red-proof',
                  out + b'/local-red-report.json', b'--junit', out + b'/requirements-proof.xml',
                  b'--repo-root', root, b'--base-ref', BASE),
    )
    env = ((b'HOME', home), (b'TMPDIR', tmp), (b'PATH', os.fsencode(tool.uv.parent) + b':/usr/bin:/bin'),
           (b'LC_ALL', b'C.UTF-8'), (b'VIRTUAL_ENV', os.fsencode(tool.python.parent.parent)),
           (b'SPECFACT_MODULES_REPO', modules), (b'SPECFACT_MODULES_ROOTS', modules + b'/packages'), (b'GIT_CONFIG_NOSYSTEM', b'1'))
    return tuple(runner._OriginalVector(stage, args, env, root, code, seconds)
                 for stage, args, code, seconds in zip(runner._OriginalStage, argv, (0, 1, 0, 0), (120, 660, 120, 120)))


def test_exact_four_vectors_are_passive_and_immutable():
    tool = SimpleNamespace(python=Path('/v/bin/python'), site_packages=Path('/v/site'),
                           core_root=Path('/C'), modules_root=Path('/M'), uv=Path('/u/uv'))
    paths = runner._PreparedPaths(*(Path(p) for p in ('/R', '/OUT', '/HOME', '/TMP')))
    rows = missing_body(runner._original_vectors, 'NEW original vectors missing', tool, paths)
    assert tuple(member.name for member in runner._OriginalStage) == ('PLANNER', 'EXECUTOR', 'RECONCILER', 'BINDER')
    assert rows == expected(tool, paths)
    assert sum(row.seconds for row in rows) == 1020
    with unittest.TestCase().assertRaises(FrozenInstanceError):
        rows[0].seconds = 1
    with unittest.TestCase().assertRaises(FrozenInstanceError):
        paths.root = Path('/elsewhere')


def test_bad_path_refuses_vector_construction(bad):
    tool = SimpleNamespace(python=Path('/v/bin/python'), site_packages=Path('/v/site'),
                           core_root=Path('/C'), modules_root=Path('/M'), uv=Path('/u/uv'))
    with unittest.TestCase().assertRaises(ValueError):
        missing_body(runner._original_vectors, 'NEW original vectors missing', tool, runner._PreparedPaths(bad, Path('/OUT'), Path('/HOME'), Path('/TMP')))


CHILD = '''
import json, os, resource, signal, sys, time
from pathlib import Path

def cli_main():
    work()

def work():
    signal.alarm(20)
    mode = Path(os.environ['HOME'], 'mode').read_text()
    if mode == 'sleep':
        time.sleep(20)
    if mode == 'group':
        child = os.fork()
        if child == 0:
            signal.alarm(20)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            Path(os.environ['HOME'], 'descendant').write_text(str(os.getpid()))
            time.sleep(20)
            os._exit(0)
        deadline = time.monotonic() + 2
        while not Path(os.environ['HOME'], 'descendant').exists():
            assert time.monotonic() < deadline
            time.sleep(.005)
    if mode == 'overflow':
        for unused in range(129):
            os.write(1, b'x' * 65536)
    if mode == 'signal':
        os.kill(os.getpid(), signal.SIGHUP)
    if mode == 'wrong-exit':
        raise SystemExit(7)
    canary = int(Path(os.environ['HOME'], 'fd').read_text())
    try:
        os.fstat(canary)
        fd_closed = False
    except OSError:
        fd_closed = True
    limits = {name: resource.getrlimit(getattr(resource, name)) for name in
              ('RLIMIT_CPU', 'RLIMIT_AS', 'RLIMIT_FSIZE', 'RLIMIT_NPROC', 'RLIMIT_CORE')}
    print(json.dumps(dict(env=dict(os.environ), cwd=os.getcwd(), pid=os.getpid(),
                          pgrp=os.getpgrp(), sid=os.getsid(0), fd_closed=fd_closed,
                          mask=sorted(signal.pthread_sigmask(signal.SIG_BLOCK, [])),
                          alarm=int(signal.getsignal(signal.SIGALRM)), limits=limits)))
    sys.stdout.flush()
    raise SystemExit(1 if Path(sys.argv[0]).name == 'requirements_proof_executor.py' else 0)

if __name__ == '__main__':
    work()
'''


@contextmanager
def owned_fixture():
    with ExitStack() as resources:
        tmp_path = Path(resources.enter_context(tempfile.TemporaryDirectory(prefix="fixed-rows-")))
        yield from _fixture_resources(tmp_path, resources)


def _fixture_resources(tmp_path, resources):
    if sys.platform != 'linux':
        raise unittest.SkipTest('Actual Linux required')
    root = tmp_path / 'owned'
    root.mkdir(mode=0o700)
    paths = runner._PreparedPaths(*(root / n for n in ('R', 'OUT', 'HOME', 'TMP')))
    for path in (paths.root, paths.out, paths.home, paths.tmp):
        path.mkdir(mode=0o700)
    core, modules, site = root / 'C', root / 'M', root / 'site'
    (core / 'src/specfact_cli').mkdir(parents=True)
    (core / 'scripts').mkdir()
    modules.mkdir()
    site.mkdir()
    (core / 'src/specfact_cli/__init__.py').write_text('')
    (core / 'src/specfact_cli/cli.py').write_text(CHILD)
    for filename in ('requirements_proof_executor.py', 'requirements_proof_provenance.py'):
        (core / 'scripts' / filename).write_text(CHILD)
    (paths.home / 'mode').write_text('ordinary')
    canary = os.open(root / 'canary', os.O_CREAT | os.O_RDWR, 0o600)
    resources.callback(os.close, canary)
    os.set_inheritable(canary, True)
    (paths.home / 'fd').write_text(str(canary))
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    resources.callback(os.close, fd)
    st = os.fstat(fd)
    owned = runner._OwnedRoot(root, fd, st.st_dev, st.st_ino, st.st_uid, st.st_mode)
    account = runner._AttemptAccount(owned, time.monotonic_ns() + 60_000_000_000, ())
    tool = SimpleNamespace(python=Path(sys.executable), site_packages=site, core_root=core,
                           modules_root=modules, uv=Path('/usr/bin/uv'))
    yield account, tool, paths


def run(setup, stage=None, seconds=10):
    account, tool, paths = setup
    with runner.Timer(seconds) as timer:
        saved, end = signal.getsignal(signal.SIGALRM), timer.end
        try:
            return missing_body(runner._run_original_stage, 'NEW original row lifetime missing', account, tool, paths, timer, stage or runner._OriginalStage.PLANNER)
        finally:
            assert signal.getsignal(signal.SIGALRM) is saved
            assert timer.end == end


def test_literal_bootstrap_real_exit_environment_fd_and_session(setup, stage):
    account, tool, paths = setup
    result = run(setup, getattr(runner._OriginalStage, stage))
    assert result is account.last_direct
    assert result.reason == 'complete' and result.cleanup_complete and not result.deadline_seen
    assert result.vector == expected(tool, paths)[list(runner._OriginalStage).index(result.stage)]
    assert result.waitid == (result.pid, os.CLD_EXITED, result.vector.expected_exit)
    assert os.WIFEXITED(result.wait_status)
    assert os.WEXITSTATUS(result.wait_status) == result.vector.expected_exit
    facts = json.loads(result.stdout)
    assert facts['env'] == {os.fsdecode(k): os.fsdecode(v) for k, v in result.vector.environment}
    assert facts['cwd'] == str(paths.root)
    assert facts['pid'] == facts['pgrp'] == facts['sid'] == result.pid > 1
    assert facts['mask'] == [] and facts['alarm'] == signal.SIG_DFL and facts['fd_closed']
    for name, cap in [('RLIMIT_CPU', 240), ('RLIMIT_AS', 2147483648), ('RLIMIT_FSIZE', 268435456),
                      ('RLIMIT_NPROC', 128), ('RLIMIT_CORE', 0)]:
        assert 0 <= facts['limits'][name][0] <= cap
    assert result.started < result.deadline <= result.started + result.vector.seconds
    assert account.row_seconds > 0
    assert account.stream_bytes == account.retained_stream_bytes == len(result.stdout) + len(result.stderr)
    assert account.read_bytes >= account.stream_bytes and account.spent_bytes >= 2 * account.stream_bytes
    with unittest.TestCase().assertRaises(ChildProcessError):
        os.waitpid(result.pid, os.WNOHANG)


def test_refusal_keeps_direct_facts_and_blocks_next_launch(setup, mode, reason, patches):
    account, tool, paths = setup
    (paths.home / 'mode').write_text(mode)
    with unittest.TestCase().assertRaises(runner._OriginalStageError) as refused:
        run(setup)
    result = refused.exception.result
    assert result is account.last_direct and account.stopped
    assert result.reason == reason and result.cleanup_complete
    if mode == 'signal':
        assert result.waitid[1:] == (os.CLD_KILLED, signal.SIGHUP)
        assert os.WIFSIGNALED(result.wait_status)
        assert os.WTERMSIG(result.wait_status) == signal.SIGHUP
    assert len(result.stdout) <= 8 * 1024 * 1024
    calls = []
    real = subprocess.Popen
    def record(*args, **kwargs):
        calls.append(args)
        return real(*args, **kwargs)
    patches.enter_context(mock.patch.object(subprocess, 'Popen', record))
    with unittest.TestCase().assertRaises(runner._OriginalStageError):
        run(setup, runner._OriginalStage.EXECUTOR)
    assert calls == []


def test_real_repeated_wnowait_precedes_reap_and_no_later_group_signal(setup, patches):
    observed, reaped, signaled = [], [], []
    real_id, real_pid, real_kill = os.waitid, os.waitpid, os.killpg
    def waitid(kind, pid, options):
        result = real_id(kind, pid, options)
        if result is not None and result.si_pid:
            again = real_id(kind, pid, options)
            assert again == result
            assert options & os.WNOWAIT
            observed.append((pid, result.si_code, result.si_status))
        return result
    def waitpid(pid, options):
        result = real_pid(pid, options)
        if result[0]:
            reaped.append(pid)
        return result
    def killpg(pid, sig):
        assert pid not in reaped
        signaled.append((pid, sig))
        return real_kill(pid, sig)
    patches.enter_context(mock.patch.object(os, 'waitid', waitid))
    patches.enter_context(mock.patch.object(os, 'waitpid', waitpid))
    patches.enter_context(mock.patch.object(os, 'killpg', killpg))
    result = run(setup)
    assert result.waitid in observed
    assert result.pid in reaped
    assert result.cleanup_complete


def test_leader_exits_before_same_group_child_is_cleaned(setup):
    account, tool, paths = setup
    (paths.home / 'mode').write_text('group')
    started = time.monotonic()
    result = run(setup, seconds=15)
    child = int((paths.home / 'descendant').read_text())
    assert result.cleanup_complete and result.reason == 'complete'
    assert not Path('/proc', str(child)).exists()
    assert time.monotonic() - started < 16


def test_preexisting_sticky_or_elapsed_deadline_never_launches(setup, patches, state):
    account, tool, paths = setup
    calls = []
    real = subprocess.Popen
    def record(*args, **kwargs):
        calls.append(args)
        return real(*args, **kwargs)
    patches.enter_context(mock.patch.object(subprocess, 'Popen', record))
    with runner.Timer(10) as timer:
        if state == 'elapsed':
            timer.end = time.monotonic() - 1
        elif state == 'aggregate':
            account.row_seconds = 1020.0
        else:
            setattr(timer, state, True)
            signal.setitimer(signal.ITIMER_REAL, 0)
        with unittest.TestCase().assertRaises(runner._OriginalStageError):
            missing_body(runner._run_original_stage, 'NEW original row lifetime missing', account, tool, paths, timer, runner._OriginalStage.PLANNER)
        assert account.stopped
        assert calls == []
        timer.pending = False


def test_real_elapsed_alarm_preserves_owner_deadline(setup):
    account, tool, paths = setup
    (paths.home / 'mode').write_text('sleep')
    started = time.monotonic()
    with unittest.TestCase().assertRaises(runner._OriginalStageError) as refused:
        run(setup, seconds=.15)
    assert refused.exception.result.deadline_seen and account.stopped
    assert refused.exception.result.cleanup_complete
    assert time.monotonic() - started < 16


def test_real_alarm_at_ownership_boundary(setup, patches, boundary):
    account, tool, paths = setup
    (paths.home / 'mode').write_text('sleep' if boundary in ('wait', 'term') else 'ordinary')
    fired, targets = [], []
    real_popen, real_id, real_pid = subprocess.Popen, os.waitid, os.waitpid
    real_kill, real_signal = os.killpg, signal.signal
    with runner.Timer(.3 if boundary == 'term' else 10) as timer:
        saved = signal.getsignal(signal.SIGALRM)
        def fire():
            if not fired:
                fired.append(boundary)
                os.kill(os.getpid(), signal.SIGALRM)
        def popen(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            if args and b'requirements' in args[0]:
                targets.append(child.pid)
                if boundary == 'registration':
                    fire()
            return child
        def waitid(kind, pid, options):
            result = real_id(kind, pid, options)
            if boundary == 'wait' and pid in targets:
                fire()
            return result
        def waitpid(pid, options):
            if boundary == 'reap' and pid in targets:
                fire()
            return real_pid(pid, options)
        def killpg(pid, sig):
            if boundary == 'term' and pid in targets and sig == signal.SIGTERM:
                fire()
            return real_kill(pid, sig)
        def install(sig, handler):
            if boundary == 'restore' and sig == signal.SIGALRM and handler is saved:
                fire()
            return real_signal(sig, handler)
        patches.enter_context(mock.patch.object(subprocess, 'Popen', popen))
        patches.enter_context(mock.patch.object(os, 'waitid', waitid))
        patches.enter_context(mock.patch.object(os, 'waitpid', waitpid))
        patches.enter_context(mock.patch.object(os, 'killpg', killpg))
        patches.enter_context(mock.patch.object(signal, 'signal', install))
        with unittest.TestCase().assertRaises(runner._OriginalStageError):
            missing_body(runner._run_original_stage, 'NEW original row lifetime missing', account, tool, paths, timer, runner._OriginalStage.PLANNER)
        assert fired == [boundary]
        assert account.stopped and account.last_direct.deadline_seen
        assert signal.getsignal(signal.SIGALRM) is saved
        timer.pending = False


def test_echild_is_not_a_success_or_group_kill_permission(setup, patches):
    account, tool, paths = setup
    real = os.waitid
    lost = []
    def waitid(kind, pid, options):
        result = real(kind, pid, options)
        if result is not None and result.si_pid and not lost:
            os.waitpid(pid, 0)
            lost.append(pid)
            raise ChildProcessError('synthetic competing reaper after real terminal observation')
        return result
    real_kill = os.killpg
    def killpg(pid, sig):
        assert pid not in lost
        return real_kill(pid, sig)
    patches.enter_context(mock.patch.object(os, 'waitid', waitid))
    patches.enter_context(mock.patch.object(os, 'killpg', killpg))
    with unittest.TestCase().assertRaises(runner._OriginalStageError):
        run(setup)
    assert lost and account.stopped
    assert not account.last_direct.cleanup_complete


def test_non_deadline_exception_survives_cleanup_and_handler_restore(setup, patches):
    account, tool, paths = setup
    primary = RuntimeError('synthetic direct wait failure')
    real_popen, real_wait = subprocess.Popen, os.waitid
    target, fired = [], []
    def popen(*args, **kwargs):
        child = real_popen(*args, **kwargs)
        if args and b'requirements' in args[0]:
            target.append(child.pid)
        return child
    def waitid(kind, pid, options):
        if pid in target and not fired:
            fired.append(pid)
            raise primary
        return real_wait(kind, pid, options)
    patches.enter_context(mock.patch.object(subprocess, 'Popen', popen))
    patches.enter_context(mock.patch.object(os, 'waitid', waitid))
    with unittest.TestCase().assertRaises(RuntimeError) as caught:
        run(setup)
    assert caught.exception is primary
    assert fired and account.stopped
    assert account.last_direct.cleanup_complete


def test_exhausted_shared_allowance_refuses_without_launch(setup, patches, field, value):
    account, tool, paths = setup
    setattr(account, field, value)
    calls = []
    real = subprocess.Popen
    def popen(*args, **kwargs):
        calls.append(args)
        return real(*args, **kwargs)
    patches.enter_context(mock.patch.object(subprocess, 'Popen', popen))
    with unittest.TestCase().assertRaises(runner._OriginalStageError):
        run(setup)
    assert account.stopped and calls == []


def test_nondefault_sigchld_refuses_before_child_creation(setup, patches):
    calls = []
    real = subprocess.Popen
    def popen(*args, **kwargs):
        calls.append(args)
        return real(*args, **kwargs)
    patches.enter_context(mock.patch.object(subprocess, 'Popen', popen))
    previous = signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    try:
        with unittest.TestCase().assertRaises(runner._OriginalStageError):
            run(setup)
        assert calls == [] and setup[0].stopped
    finally:
        signal.signal(signal.SIGCHLD, previous)


REAL_POPEN = subprocess.Popen
REAL_WAITID, REAL_WAITPID = getattr(os, 'waitid', None), os.waitpid
REAL_KILLPG, REAL_KILL = os.killpg, os.kill
REAL_GETPGID, REAL_GETSID = os.getpgid, os.getsid


def cleanup_direct_children(children, setup):
    issues = []
    end = time.monotonic() + 3
    for child in children:
        pid = child.pid
        if time.monotonic() >= end:
            issues.append('outer cleanup deadline before ownership check')
            break
        try:
            REAL_WAITID(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError:
            # ECHILD gives no outer cleanup credit and no numeric signal authority.
            print(json.dumps({'outer_cleanup': 'incomplete-echild', 'pid': pid}))
            continue
        except OSError as error:
            issues.append('outer waitid failed ' + type(error).__name__)
            continue
        try:
            if pid > 1 and REAL_GETPGID(pid) == pid and REAL_GETSID(pid) == pid:
                REAL_KILLPG(pid, signal.SIGKILL)
            else:
                issues.append('owned direct child has nonmatching group/session')
                # Only the still-owned unreaped direct child pins this PID.
                REAL_KILL(pid, signal.SIGKILL)
        except OSError as error:
            issues.append('outer signal failed ' + type(error).__name__)
        # No group operation is permitted below this point for this child.
        while time.monotonic() < end:
            try:
                reaped, status = REAL_WAITPID(pid, os.WNOHANG)
            except ChildProcessError:
                issues.append('ownership lost before outer reap')
                break
            if reaped:
                child.returncode = os.waitstatus_to_exitcode(status)
                break
            time.sleep(.01)
        else:
            issues.append('outer direct reap deadline')
        for pipe in (child.stdout, child.stderr, child.stdin):
            if pipe is not None:
                pipe.close()
    descendant = setup[2].home / 'descendant'
    if descendant.exists():
        pid_text = descendant.read_text()
        if pid_text.isdecimal() and Path('/proc', pid_text).exists():
            issues.append('descendant remains; no owned PID or group signal authority')
    return issues


def _row_diagnostic(setup, case_id):
    account, unused, paths = setup
    result = account.last_direct
    record = {'claim': 'UNCLASSIFIED CONTROL SNAPSHOT BEFORE OUTER CLEANUP', 'case': case_id,
              'account': {name: getattr(account, name) for name in (
                  'metadata_visits', 'read_bytes', 'spent_bytes', 'retained_bytes',
                  'retained_members', 'stream_bytes', 'retained_stream_bytes', 'row_seconds', 'stopped')}}
    if result is not None:
        record['direct'] = {name: getattr(result, name) for name in (
            'pid', 'reason', 'cleanup_complete', 'deadline_seen', 'waitid', 'wait_status')}
        record['direct'].update(stage=result.stage.value, elapsed=result.ended-result.started,
                                stdout_bytes=len(result.stdout), stderr_bytes=len(result.stderr))
    marker = paths.home / 'descendant'
    if marker.exists():
        descriptor = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            number = os.read(descriptor, 33)
        finally:
            os.close(descriptor)
        if len(number) > 32 or not number.isdigit() or not 1 < int(number) < 2**31:
            raise ValueError('diagnostic descendant marker')
        try:
            descriptor = os.open('/proc/' + number.decode('ascii') + '/stat',
                                 os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            record['descendant'] = {'pid': int(number), 'observation': 'absent'}
        else:
            try:
                raw = os.read(descriptor, 8193)
            finally:
                os.close(descriptor)
            opening, closing = raw.find(b' ('), raw.rfind(b')')
            if len(raw) > 8192 or opening < 1 or closing <= opening:
                raise ValueError('diagnostic stat shape')
            fields = raw[closing+2:].split()
            if len(fields) < 20 or int(raw[:opening]) != int(number):
                raise ValueError('diagnostic stat fields')
            record['descendant'] = {'pid': int(number), 'state': fields[0].decode('ascii'),
                                    'parent': int(fields[1]), 'group': int(fields[2]),
                                    'session': int(fields[3]), 'starttime': int(fields[19])}
    raw = json.dumps(record, sort_keys=True)
    if len(raw.encode()) > 4096:
        raise ValueError('diagnostic record bound')
    print(raw)



def _diagnostic_integer(value):
    return value if type(value) is int and -(2**63) < value < 2**63 else None


def _diagnostic_class(error):
    allowed = (OSError, FileNotFoundError, PermissionError, ProcessLookupError,
               ChildProcessError, InterruptedError, BlockingIOError, IsADirectoryError,
               NotADirectoryError, FileExistsError, TimeoutError, ValueError, IndexError,
               TypeError, AttributeError, KeyError, RuntimeError, AssertionError)
    for kind in allowed:
        if type(error) is kind:
            return kind.__name__
    return 'OtherException'


@contextmanager
def _leader_exception_observer(account):
    previous = sys.gettrace()
    if previous is not None:
        raise RuntimeError('diagnostic requires no preexisting tracer')
    codes = [value for value in runner._run_original_stage.__code__.co_consts
             if type(value) is type(runner._run_original_stage.__code__)
             and value.co_name == 'group_empty']
    if len(codes) != 1:
        raise RuntimeError('diagnostic group code identity')
    target = codes[0]
    event_record = None
    observer_failed = False
    def observe(frame, event, argument):
        nonlocal event_record, observer_failed
        try:
            if frame.f_code is not target:
                return None
            frame.f_trace_lines = False
            frame.f_trace_opcodes = False
            if event != 'exception' or event_record is not None or observer_failed:
                return observe
            error = argument[1]
            proc = type(error) is runner._OriginalRowRefusal and error.args == ('proc',)
            if not isinstance(error, (OSError, ValueError, IndexError)) and not proc:
                return observe
            local = frame.f_locals
            entry = local.get('entry')
            name = entry.name if entry is not None else None
            numeric = (int(name) if type(name) is str and len(name) <= 10
                       and name.isascii() and name.isdecimal() else None)
            leader = _diagnostic_integer(local.get('pid'))
            event_record = {
                'line': frame.f_lineno,
                'class': 'ProcRefusal' if proc else _diagnostic_class(error),
                'errno': _diagnostic_integer(error.errno) if isinstance(error, OSError) else None,
                'entry_pid': numeric, 'owned_leader_match': numeric == leader if numeric is not None and leader is not None else None,
                'owned': local.get('owned') is True, 'probing': None,
                'terminal_present': local.get('terminal') is not None,
                'metadata_visits': _diagnostic_integer(account.metadata_visits),
                'read_bytes': _diagnostic_integer(account.read_bytes),
                'spent_bytes': _diagnostic_integer(account.spent_bytes)}
        except runner.Deadline:
            observer_failed = True
            raise
        except Exception:
            observer_failed = True
            return None
        return observe
    try:
        sys.settrace(observe)
        yield
    finally:
        primary = sys.exception()
        try:
            sys.settrace(previous)
        except BaseException:
            if primary is None:
                raise
        try:
            raw = json.dumps({'leader_exception': event_record,
                              'observer_failed': observer_failed}, sort_keys=True).encode()
            if len(raw) > 4096:
                raw = b'{"leader_exception":null,"overflow":true}'
            sys.stdout.write(raw.decode() + '\n')
            sys.stdout.flush()
        except BaseException:
            if primary is None:
                raise


class FixedRows(unittest.TestCase):
    def invoke_linux(self, body):
        if sys.platform != 'linux':
            self.skipTest('Actual Linux waitid/proc/group control required')
        children = []
        def record(*args, **kwargs):
            child = REAL_POPEN(*args, **kwargs)
            children.append(child)
            for pipe in (child.stdout, child.stderr, child.stdin):
                if pipe is not None:
                    pipes.callback(pipe.close)
            return child
        with owned_fixture() as setup, ExitStack() as pipes:
            primary = None
            try:
                with mock.patch.object(subprocess, 'Popen', record):
                    with ExitStack() as patches:
                        if self.id().endswith('.FixedRows.test_leader_exits_before_same_group_child_is_cleaned'):
                            with _leader_exception_observer(setup[0]):
                                body(setup, patches)
                        else:
                            body(setup, patches)
            except BaseException as error:
                primary = error
                raise
            finally:
                diagnostic_error = None
                try:
                    _row_diagnostic(setup, self.id())
                except BaseException as error:
                    if primary is None:
                        primary = diagnostic_error = error
                    else:
                        primary.add_note('bounded diagnostic failed: ' + type(error).__name__)
                old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
                try:
                    try:
                        issues = cleanup_direct_children(children, setup)
                    except BaseException as cleanup_error:
                        if primary is None:
                            raise
                        primary.add_note('outer cleanup incomplete: ' + type(cleanup_error).__name__)
                        issues = []
                    if issues:
                        note = '; '.join(issues)
                        if primary is None:
                            raise AssertionError(note)
                        primary.add_note(note)
                finally:
                    try:
                        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
                    except BaseException as restoration_error:
                        if primary is None:
                            raise
                        primary.add_note('outer mask restoration failed: ' + type(restoration_error).__name__)
                if diagnostic_error is not None:
                    raise diagnostic_error

    def test_exact_four_vectors_are_passive_and_immutable(self):
        test_exact_four_vectors_are_passive_and_immutable()

    def test_bad_path_refuses_vector_construction_0(self):
        test_bad_path_refuses_vector_construction(Path('relative'))

    def test_bad_path_refuses_vector_construction_1(self):
        test_bad_path_refuses_vector_construction(Path('/x/../R'))

    def test_bad_path_refuses_vector_construction_2(self):
        test_bad_path_refuses_vector_construction(Path('/' + 'x' * 4096))

    def test_literal_bootstrap_real_exit_environment_fd_and_session_PLANNER(self):
        self.invoke_linux(lambda setup, patches: test_literal_bootstrap_real_exit_environment_fd_and_session(setup, 'PLANNER'))

    def test_literal_bootstrap_real_exit_environment_fd_and_session_EXECUTOR(self):
        self.invoke_linux(lambda setup, patches: test_literal_bootstrap_real_exit_environment_fd_and_session(setup, 'EXECUTOR'))

    def test_literal_bootstrap_real_exit_environment_fd_and_session_RECONCILER(self):
        self.invoke_linux(lambda setup, patches: test_literal_bootstrap_real_exit_environment_fd_and_session(setup, 'RECONCILER'))

    def test_literal_bootstrap_real_exit_environment_fd_and_session_BINDER(self):
        self.invoke_linux(lambda setup, patches: test_literal_bootstrap_real_exit_environment_fd_and_session(setup, 'BINDER'))

    def test_refusal_keeps_direct_facts_and_blocks_next_launch_0(self):
        self.invoke_linux(lambda setup, patches: test_refusal_keeps_direct_facts_and_blocks_next_launch(setup, 'wrong-exit', 'exit', patches))

    def test_refusal_keeps_direct_facts_and_blocks_next_launch_1(self):
        self.invoke_linux(lambda setup, patches: test_refusal_keeps_direct_facts_and_blocks_next_launch(setup, 'signal', 'exit', patches))

    def test_refusal_keeps_direct_facts_and_blocks_next_launch_2(self):
        self.invoke_linux(lambda setup, patches: test_refusal_keeps_direct_facts_and_blocks_next_launch(setup, 'overflow', 'stream-limit', patches))

    def test_real_repeated_wnowait_precedes_reap_and_no_later_group_signal(self):
        self.invoke_linux(lambda setup, patches: test_real_repeated_wnowait_precedes_reap_and_no_later_group_signal(setup, patches))

    def test_leader_exits_before_same_group_child_is_cleaned(self):
        self.invoke_linux(lambda setup, patches: test_leader_exits_before_same_group_child_is_cleaned(setup))

    def test_preexisting_sticky_or_elapsed_deadline_never_launches_0(self):
        self.invoke_linux(lambda setup, patches: test_preexisting_sticky_or_elapsed_deadline_never_launches(setup, patches, 'pending'))

    def test_preexisting_sticky_or_elapsed_deadline_never_launches_1(self):
        self.invoke_linux(lambda setup, patches: test_preexisting_sticky_or_elapsed_deadline_never_launches(setup, patches, 'expired'))

    def test_preexisting_sticky_or_elapsed_deadline_never_launches_2(self):
        self.invoke_linux(lambda setup, patches: test_preexisting_sticky_or_elapsed_deadline_never_launches(setup, patches, 'elapsed'))

    def test_preexisting_sticky_or_elapsed_deadline_never_launches_3(self):
        self.invoke_linux(lambda setup, patches: test_preexisting_sticky_or_elapsed_deadline_never_launches(setup, patches, 'aggregate'))

    def test_real_elapsed_alarm_preserves_owner_deadline(self):
        self.invoke_linux(lambda setup, patches: test_real_elapsed_alarm_preserves_owner_deadline(setup))

    def test_real_alarm_at_ownership_boundary_0(self):
        self.invoke_linux(lambda setup, patches: test_real_alarm_at_ownership_boundary(setup, patches, 'registration'))

    def test_real_alarm_at_ownership_boundary_1(self):
        self.invoke_linux(lambda setup, patches: test_real_alarm_at_ownership_boundary(setup, patches, 'wait'))

    def test_real_alarm_at_ownership_boundary_2(self):
        self.invoke_linux(lambda setup, patches: test_real_alarm_at_ownership_boundary(setup, patches, 'term'))

    def test_real_alarm_at_ownership_boundary_3(self):
        self.invoke_linux(lambda setup, patches: test_real_alarm_at_ownership_boundary(setup, patches, 'reap'))

    def test_real_alarm_at_ownership_boundary_4(self):
        self.invoke_linux(lambda setup, patches: test_real_alarm_at_ownership_boundary(setup, patches, 'restore'))

    def test_echild_is_not_a_success_or_group_kill_permission(self):
        self.invoke_linux(lambda setup, patches: test_echild_is_not_a_success_or_group_kill_permission(setup, patches))

    def test_non_deadline_exception_survives_cleanup_and_handler_restore(self):
        self.invoke_linux(lambda setup, patches: test_non_deadline_exception_survives_cleanup_and_handler_restore(setup, patches))

    def test_exhausted_shared_allowance_refuses_without_launch_0(self):
        self.invoke_linux(lambda setup, patches: test_exhausted_shared_allowance_refuses_without_launch(setup, patches, 'stream_bytes', 16 * 1024 * 1024))

    def test_exhausted_shared_allowance_refuses_without_launch_1(self):
        self.invoke_linux(lambda setup, patches: test_exhausted_shared_allowance_refuses_without_launch(setup, patches, 'spent_bytes', 255 * 1024 * 1024))

    def test_exhausted_shared_allowance_refuses_without_launch_2(self):
        self.invoke_linux(lambda setup, patches: test_exhausted_shared_allowance_refuses_without_launch(setup, patches, 'metadata_visits', 64000))

    def test_nondefault_sigchld_refuses_before_child_creation(self):
        self.invoke_linux(lambda setup, patches: test_nondefault_sigchld_refuses_before_child_creation(setup, patches))


if __name__ == "__main__":
    unittest.main()
