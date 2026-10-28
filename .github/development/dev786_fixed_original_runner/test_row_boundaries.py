from __future__ import annotations

import errno
import importlib.util
import json
import os
from pathlib import Path
import resource
import re
import signal
import subprocess
import sys
import time
import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest import mock

FIXED_PREFLIGHT_PATH = Path(os.environ['FIXED_PREFLIGHT_PATH'])
FIXED_ROWS_HELPER_PATH = Path(os.environ['FIXED_ROWS_HELPER_PATH'])
if not FIXED_PREFLIGHT_PATH.is_absolute() or not FIXED_ROWS_HELPER_PATH.is_absolute():
    raise ValueError('Both reviewed source paths must be explicit and absolute')
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('fixed_rows_reviewed_helper', FIXED_ROWS_HELPER_PATH)
base = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = base
spec.loader.exec_module(base)
runner = base.runner
MIB = 1048576
CAP = 255 * MIB


def row(setup, timer):
    return base.missing_body(runner._run_original_stage, 'NEW original row lifetime missing',
                             *setup, timer, runner._OriginalStage.PLANNER)


def write_child(setup, body):
    source = 'import os, signal, time\n\ndef cli_main():\n    signal.alarm(20)\n' + ''.join(
        '    ' + line + '\n' for line in body.splitlines())
    (setup[1].core_root / 'src/specfact_cli/cli.py').write_text(source)


def assert_reaped(case, result):
    case.assertIsNotNone(result.pid)
    case.assertTrue(result.cleanup_complete)
    case.assertIsNotNone(result.waitid)
    case.assertIsNotNone(result.wait_status)
    with case.assertRaises(ChildProcessError):
        base.REAL_WAITPID(result.pid, os.WNOHANG)


class RowBoundaries(unittest.TestCase):
    invoke_linux = base.FixedRows.invoke_linux

    def test_all_nine_paths_and_encoded_boundary(self):
        names = ('python', 'site_packages', 'core_root', 'modules_root', 'uv',
                 'root', 'out', 'home', 'tmp')
        for name in names:
            for value, good in ((Path('relative'), False), (Path('/x/../R'), False),
                                (Path('/x\x00R'), False),
                                (Path('/' + 'é' * 2047 + 'x'), True),
                                (Path('/' + 'é' * 2048), False)):
                with self.subTest(field=name, bytes=len(os.fsencode(value)), good=good):
                    tool = SimpleNamespace(python=Path('/v/bin/python'), site_packages=Path('/v/site'),
                                           core_root=Path('/C'), modules_root=Path('/M'), uv=Path('/u/uv'))
                    paths = runner._PreparedPaths(*(Path(p) for p in ('/R', '/OUT', '/HOME', '/TMP')))
                    if name in names[:5]:
                        setattr(tool, name, value)
                    else:
                        paths = replace(paths, **{name: value})
                    if good:
                        self.assertEqual(len(os.fsencode(value)), 4096)
                        rows = base.missing_body(runner._original_vectors, 'NEW original vectors missing', tool, paths)
                        self.assertEqual(rows, base.expected(tool, paths))
                    else:
                        with self.assertRaises(ValueError):
                            base.missing_body(runner._original_vectors, 'NEW original vectors missing', tool, paths)

    def test_prerequisite_echild_is_separate_from_row_loss(self):
        def body(setup, patches):
            targets, lost = [], []
            real_popen, real_wait = subprocess.Popen, os.waitid
            def popen(*args, **kwargs):
                if args and b'requirements' in args[0]:
                    targets.append(True)
                return real_popen(*args, **kwargs)
            def waitid(kind, pid, options):
                fact = real_wait(kind, pid, options)
                if fact is not None and fact.si_pid and not lost:
                    base.REAL_WAITPID(pid, 0)
                    lost.append(pid)
                    raise ChildProcessError(errno.ECHILD, 'Synthetic prerequisite competing reap')
                return fact
            patches.enter_context(mock.patch.object(subprocess, 'Popen', popen))
            patches.enter_context(mock.patch.object(os, 'waitid', waitid))
            with self.assertRaises(runner._OriginalStageError) as caught:
                base.run(setup)
            self.assertTrue(lost)
            self.assertEqual(targets, [])
            self.assertTrue(setup[0].stopped)
            self.assertEqual(caught.exception.result.reason, 'prerequisite')
            self.assertFalse(caught.exception.result.cleanup_complete)
        self.invoke_linux(body)

    def test_row_specific_echild_forbids_later_group_signal(self):
        def body(setup, patches):
            targets, lost = [], []
            real_popen, real_wait, real_kill = subprocess.Popen, os.waitid, os.killpg
            def popen(*args, **kwargs):
                child = real_popen(*args, **kwargs)
                if args and b'requirements' in args[0]:
                    targets.append(child.pid)
                return child
            def waitid(kind, pid, options):
                fact = real_wait(kind, pid, options)
                if pid in targets and fact is not None and fact.si_pid and not lost:
                    base.REAL_WAITPID(pid, 0)
                    lost.append(pid)
                    raise ChildProcessError(errno.ECHILD, 'Synthetic row competing reap')
                return fact
            def killpg(pid, sig):
                self.assertNotIn(pid, lost)
                return real_kill(pid, sig)
            patches.enter_context(mock.patch.object(subprocess, 'Popen', popen))
            patches.enter_context(mock.patch.object(os, 'waitid', waitid))
            patches.enter_context(mock.patch.object(os, 'killpg', killpg))
            with self.assertRaises(runner._OriginalStageError) as caught:
                base.run(setup)
            self.assertEqual(lost, targets)
            self.assertEqual(len(lost), 1)
            self.assertEqual(caught.exception.result.pid, lost[0])
            self.assertEqual(caught.exception.result.reason, 'ownership')
            self.assertFalse(caught.exception.result.cleanup_complete)
            self.assertTrue(setup[0].stopped)
        self.invoke_linux(body)

    def test_blocked_alarm_and_unsupported_waitability_refuse(self):
        for fault in ('blocked-alarm', 'waitid-unavailable'):
            with self.subTest(fault=fault):
                def body(setup, patches):
                    rows = []
                    real = subprocess.Popen
                    def popen(*args, **kwargs):
                        if args and b'requirements' in args[0]:
                            rows.append(True)
                        return real(*args, **kwargs)
                    patches.enter_context(mock.patch.object(subprocess, 'Popen', popen))
                    old = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM} if fault == 'blocked-alarm' else set())
                    try:
                        if fault == 'waitid-unavailable':
                            patches.enter_context(mock.patch.object(os, 'waitid', side_effect=OSError(errno.ENOSYS, 'Synthetic unavailable waitid')))
                        with self.assertRaises(runner._OriginalStageError) as caught:
                            base.run(setup)
                        self.assertEqual(caught.exception.result.reason, 'prerequisite')
                        self.assertTrue(setup[0].stopped)
                        self.assertEqual(rows, [])
                    finally:
                        signal.pthread_sigmask(signal.SIG_SETMASK, old)
                self.invoke_linux(body)

    def test_exact_signal_and_frame_reach_original_alarm(self):
        def body(setup, patches):
            delivered, observed = [], []
            real = subprocess.Popen
            previous_trace = sys.gettrace()
            def trace(frame, event, arg):
                if event == 'call' and frame.f_code is runner.Timer.alarm.__code__:
                    observed.append((frame.f_locals['number'], frame.f_locals['frame']))
                return trace
            def fire():
                delivered.append((signal.SIGALRM, sys._getframe()))
                os.kill(os.getpid(), signal.SIGALRM)
            def popen(*args, **kwargs):
                child = real(*args, **kwargs)
                if args and b'requirements' in args[0]:
                    fire()
                return child
            patches.enter_context(mock.patch.object(subprocess, 'Popen', popen))
            sys.settrace(trace)
            try:
                with self.assertRaises(runner._OriginalStageError) as caught:
                    base.run(setup)
            finally:
                sys.settrace(previous_trace)
            self.assertEqual(len(delivered), 1)
            self.assertEqual(observed, delivered)
            self.assertTrue(caught.exception.result.deadline_seen)
            assert_reaped(self, caught.exception.result)
        self.invoke_linux(body)

    def test_real_private_frame_defers_and_cancels_without_recovery(self):
        def body(setup, patches):
            calls = []
            real = subprocess.Popen
            def popen(*args, **kwargs):
                calls.append(True)
                return real(*args, **kwargs)
            patches.enter_context(mock.patch.object(subprocess, 'Popen', popen))
            def private_frame():
                os.kill(os.getpid(), signal.SIGALRM)
            with runner.Timer(10) as timer:
                timer.private_code = private_frame.__code__
                private_frame()
                self.assertTrue(timer.pending and timer.expired)
                self.assertEqual(timer.deferred, 1)
                self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
                with self.assertRaises(runner._OriginalStageError) as caught:
                    row(setup, timer)
                self.assertTrue(setup[0].stopped)
                self.assertTrue(caught.exception.result.deadline_seen)
                self.assertEqual(calls, [])
                self.assertEqual(timer.deferred, 1)
                # Original Timer.check owns clearing pending, including this teardown.
                with self.assertRaises(runner.Deadline):
                    timer.check()
        self.invoke_linux(body)

    def test_preexec_first_reset_empty_mask_and_independent_expiry(self):
        for expire in (False, True):
            with self.subTest(expire=expire):
                def body(setup, patches):
                    old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1})
                    patches.callback(signal.pthread_sigmask, signal.SIG_SETMASK, old_mask)
                    note = setup[2].home / 'preexec.json'
                    real = subprocess.Popen
                    def popen(*args, **kwargs):
                        if args and b'requirements' in args[0]:
                            original = kwargs['preexec_fn']
                            def preexec():
                                events = []
                                returned = False
                                expired_before_original = False
                                real_signal, real_mask, real_limit = signal.signal, signal.pthread_sigmask, resource.setrlimit
                                def disposition(sig, handler):
                                    events.append(['signal', int(sig), int(handler) if not callable(handler) else 'callable'])
                                    return real_signal(sig, handler)
                                def mask(how, values):
                                    events.append(['mask', int(how), sorted(map(int, values))])
                                    return real_mask(how, values)
                                def limit(kind, values):
                                    events.append(['limit', kind, list(values)])
                                    return real_limit(kind, values)
                                signal.signal, signal.pthread_sigmask, resource.setrlimit = disposition, mask, limit
                                try:
                                    if expire:
                                        while time.monotonic_ns() <= setup[0].deadline_ns:
                                            time.sleep(min(.01, max(0, (setup[0].deadline_ns - time.monotonic_ns()) / 1e9)))
                                    expired_before_original = time.monotonic_ns() >= setup[0].deadline_ns
                                    original()
                                    returned = True
                                finally:
                                    signal.signal, signal.pthread_sigmask, resource.setrlimit = real_signal, real_mask, real_limit
                                    note.write_text(json.dumps({"events": events, "returned": returned,
                                                                "expired_before_original": expired_before_original}))
                            kwargs['preexec_fn'] = preexec
                        return real(*args, **kwargs)
                    patches.enter_context(mock.patch.object(subprocess, 'Popen', popen))
                    if expire:
                        setup[0].deadline_ns = time.monotonic_ns() + 2_000_000_000
                        with self.assertRaises(runner._OriginalStageError) as caught:
                            base.run(setup)
                        self.assertTrue(setup[0].stopped)
                        self.assertIn(caught.exception.result.reason, ('deadline', 'launch'))
                        self.assertEqual(caught.exception.result.stdout, b'')
                    else:
                        result = base.run(setup)
                        assert_reaped(self, result)
                    facts = json.loads(note.read_text())
                    events = facts["events"]
                    self.assertEqual(facts["returned"], not expire)
                    if expire:
                        self.assertTrue(facts["expired_before_original"])
                    self.assertEqual(events[:2], [['signal', int(signal.SIGALRM), int(signal.SIG_DFL)],
                                                 ['mask', int(signal.SIG_SETMASK), []]])
                    self.assertTrue(any(item[0] == 'limit' for item in events))
                self.invoke_linux(body)

    def test_tighter_soft_and_hard_limits_in_disposable_parent(self):
        def body(setup, patches):
            desired = {'RLIMIT_CPU': (20, 30), 'RLIMIT_AS': (512*MIB, 768*MIB),
                       'RLIMIT_FSIZE': (8*MIB, 16*MIB), 'RLIMIT_NPROC': (96, 112), 'RLIMIT_CORE': (0, 0)}
            inherited = {name: resource.getrlimit(getattr(resource, name)) for name in desired}
            for name, limits in desired.items():
                for current, wanted in zip(inherited[name], limits):
                    self.assertTrue(current == resource.RLIM_INFINITY or current >= wanted,
                                    'Unsupported host for tighter-limit positive control: ' + name)
            note = setup[2].home / 'tighter-result.json'
            pid = os.fork()
            if pid == 0:
                children = []
                real = subprocess.Popen
                def record(*args, **kwargs):
                    child = real(*args, **kwargs)
                    children.append(child)
                    return child
                code = 91
                try:
                    with mock.patch.object(subprocess, 'Popen', record), runner.Timer(20) as timer:
                        for name, values in desired.items():
                            resource.setrlimit(getattr(resource, name), values)
                        result = row(setup, timer)
                        facts = json.loads(result.stdout)
                        note.write_text(json.dumps({'limits': facts['limits'], 'cleanup': result.cleanup_complete}))
                        code = 0
                except BaseException:
                    pass
                finally:
                    signal.signal(signal.SIGALRM, signal.SIG_DFL)
                    signal.alarm(4)
                    try:
                        if base.cleanup_direct_children(children, setup):
                            code = 92
                    except BaseException:
                        code = 93
                    os._exit(code)
            end = time.monotonic() + 26
            status, reaped = None, False
            try:
                while time.monotonic() < end:
                    found, status = base.REAL_WAITPID(pid, os.WNOHANG)
                    if found:
                        reaped = True
                        break
                    time.sleep(.01)
                else:
                    self.fail('Disposable limit parent exceeded its independent deadline')
            finally:
                if not reaped:
                    try:
                        base.REAL_WAITID(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                        base.REAL_KILL(pid, signal.SIGKILL)
                        base.REAL_WAITPID(pid, 0)
                    except ChildProcessError:
                        pass
            self.assertEqual(status, 0, 'Tighter-limit child failed; this is not missing-body evidence')
            facts = json.loads(note.read_text())
            self.assertEqual(facts['limits'], {name: list(values) for name, values in desired.items()})
            self.assertTrue(facts['cleanup'])
            self.assertEqual({name: resource.getrlimit(getattr(resource, name)) for name in desired}, inherited)
        self.invoke_linux(body)

    def test_registration_and_reap_failures_keep_exception_identity(self):
        for fault in ('registration', 'reap'):
            with self.subTest(fault=fault):
                def body(setup, patches):
                    primary = RuntimeError('Synthetic ' + fault + ' failure')
                    targets, fired = [], []
                    real_popen, real_wait = subprocess.Popen, os.waitpid
                    def popen(*args, **kwargs):
                        child = real_popen(*args, **kwargs)
                        if args and b'requirements' in args[0]:
                            targets.append(child.pid)
                            if fault == 'registration':
                                fired.append(child.pid)
                                raise primary
                        return child
                    def waitpid(pid, options):
                        if pid in targets and not fired:
                            fired.append(pid)
                            raise primary
                        return real_wait(pid, options)
                    patches.enter_context(mock.patch.object(subprocess, 'Popen', popen))
                    patches.enter_context(mock.patch.object(os, 'waitpid', waitpid))
                    with self.assertRaises(RuntimeError) as caught:
                        base.run(setup)
                    self.assertIs(caught.exception, primary)
                    self.assertEqual(fired, targets)
                    self.assertEqual(len(targets), 1)
                    self.assertTrue(setup[0].stopped)
                    self.assertFalse(setup[0].last_direct.cleanup_complete)
                    if fault == 'registration':
                        self.assertIsNone(setup[0].last_direct.pid)
                self.invoke_linux(body)

    def test_kill_alarm_and_post_restore_alarm_never_succeed(self):
        for boundary in ('kill', 'post-restore'):
            with self.subTest(boundary=boundary):
                def body(setup, patches):
                    if boundary == 'kill':
                        write_child(setup, 'signal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(20)')
                    real_popen, real_kill, real_signal = subprocess.Popen, os.killpg, signal.signal
                    targets, fired = [], []
                    with runner.Timer(.3 if boundary == 'kill' else 10) as timer:
                        saved = signal.getsignal(signal.SIGALRM)
                        def popen(*args, **kwargs):
                            child = real_popen(*args, **kwargs)
                            if args and b'requirements' in args[0]:
                                targets.append(child.pid)
                            return child
                        def killpg(pid, sig):
                            if boundary == 'kill' and pid in targets and sig == signal.SIGKILL and not fired:
                                fired.append(boundary)
                                os.kill(os.getpid(), signal.SIGALRM)
                            return real_kill(pid, sig)
                        def install(sig, handler):
                            result = real_signal(sig, handler)
                            if boundary == 'post-restore' and targets and handler is saved and not fired:
                                fired.append(boundary)
                                os.kill(os.getpid(), signal.SIGALRM)
                            return result
                        patches.enter_context(mock.patch.object(subprocess, 'Popen', popen))
                        patches.enter_context(mock.patch.object(os, 'killpg', killpg))
                        patches.enter_context(mock.patch.object(signal, 'signal', install))
                        with self.assertRaises((runner._OriginalStageError, runner.Deadline)):
                            row(setup, timer)
                        self.assertEqual(fired, [boundary])
                        self.assertTrue(setup[0].stopped)
                        self.assertTrue(setup[0].last_direct.deadline_seen)
                        self.assertIs(signal.getsignal(signal.SIGALRM), saved)
                        assert_reaped(self, setup[0].last_direct)
                self.invoke_linux(body)

    def test_near_expiry_never_extends_absolute_deadline(self):
        def body(setup, patches):
            write_child(setup, 'time.sleep(20)')
            setup[0].row_seconds = 1019.9
            before = time.monotonic()
            with self.assertRaises(runner._OriginalStageError) as caught:
                base.run(setup)
            result = caught.exception.result
            self.assertEqual(result.reason, 'deadline')
            self.assertLessEqual(result.deadline, result.started + .101)
            self.assertLess(time.monotonic() - before, 16)
            self.assertGreater(setup[0].row_seconds, 1019.9)
            assert_reaped(self, result)
        self.invoke_linux(body)

    def test_synthetic_proc_faults_and_fixed_cleanup_endpoints(self):
        for fault in ('malformed', 'unavailable', '8193', 'visit-overflow', 'other-z'):
            with self.subTest(fault=fault):
                def body(setup, patches):
                    account = setup[0]
                    write_child(setup, 'pass')
                    targets, hits, scans, reads, opened = [], [], [], [], {}
                    real_popen, real_open, real_read, real_close, real_scan = subprocess.Popen, os.open, os.read, os.close, os.scandir
                    real_kill = os.killpg
                    signals = []
                    def popen(*args, **kwargs):
                        child = real_popen(*args, **kwargs)
                        if args and b'requirements' in args[0]:
                            targets.append(child.pid)
                        return child
                    def open_file(path, flags, *args, **kwargs):
                        text = os.fsdecode(path) if isinstance(path, (str, bytes, os.PathLike)) else ''
                        is_stat = text.startswith('/proc/') and text.endswith('/stat') and text[6:-5].isdigit()
                        if targets and is_stat and fault == 'unavailable':
                            hits.append(fault)
                            raise PermissionError(errno.EACCES, 'Synthetic proc stat refusal')
                        fd = real_open(path, flags, *args, **kwargs)
                        if targets and is_stat:
                            opened[fd] = text
                        return fd
                    def read(fd, n):
                        if fd not in opened:
                            return real_read(fd, n)
                        self.assertLessEqual(n, 8193)
                        before = (account.metadata_visits, account.spent_bytes)
                        raw = real_read(fd, n)
                        reads.append((len(raw), before))
                        if fault == 'malformed':
                            hits.append(fault)
                            return b'not a stat record'
                        if fault == '8193':
                            hits.append(fault)
                            self.assertEqual(n, 8193)
                            return b'x' * 8193
                        if fault == 'other-z' and raw:
                            end = raw.rfind(b')')
                            fields = raw[end + 2:].split()
                            if int(raw.split(b' ', 1)[0]) != targets[0]:
                                fields[0], fields[2], fields[3] = b'Z', str(targets[0]).encode(), str(targets[0]).encode()
                                hits.append(fault)
                                return raw[:end + 2] + b' '.join(fields)
                        return raw
                    def close(fd):
                        result = real_close(fd)
                        opened.pop(fd, None)
                        return result
                    class Scan:
                        def __init__(self, path):
                            self.source = real_scan(path)
                            self.iterator = self.entries()
                        def __enter__(self):
                            return self
                        def __exit__(self, *args):
                            self.source.close()
                        def __iter__(self):
                            return self
                        def __next__(self):
                            return next(self.iterator)
                        def entries(self):
                            for entry in self.source:
                                if fault == 'visit-overflow':
                                    for unused in range(20001):
                                        hits.append(fault)
                                        yield entry
                                    return
                                yield entry
                    def scan(path):
                        if os.fsdecode(path) == '/proc' and targets:
                            scans.append((time.monotonic(), account.metadata_visits, account.spent_bytes))
                            return Scan(path)
                        return real_scan(path)
                    def killpg(pid, sig):
                        signals.append((pid, sig, time.monotonic()))
                        return real_kill(pid, sig)
                    patches.enter_context(mock.patch.object(subprocess, 'Popen', popen))
                    patches.enter_context(mock.patch.object(os, 'open', open_file))
                    patches.enter_context(mock.patch.object(os, 'read', read))
                    patches.enter_context(mock.patch.object(os, 'close', close))
                    patches.enter_context(mock.patch.object(os, 'scandir', scan))
                    patches.enter_context(mock.patch.object(os, 'killpg', killpg))
                    try:
                        start = time.monotonic()
                        with self.assertRaises(runner._OriginalStageError) as caught:
                            base.run(setup, seconds=18)
                        self.assertTrue(hits, 'Synthetic proc fault must reach real row scan boundary')
                        self.assertTrue(account.stopped)
                        self.assertFalse(caught.exception.result.cleanup_complete)
                        self.assertIn(caught.exception.result.reason, ('proc', 'budget', 'cleanup'))
                        self.assertLess(time.monotonic() - start, 16)
                        self.assertLessEqual(account.metadata_visits, 64000)
                        self.assertLessEqual(account.spent_bytes, CAP)
                        self.assertGreater(account.metadata_visits, 0)
                        if fault in ('unavailable', 'malformed', '8193'):
                            self.assertGreaterEqual(account.spent_bytes, 8193)
                        self.assertIsNotNone(caught.exception.result.wait_status)
                        with self.assertRaises(ChildProcessError):
                            base.REAL_WAITPID(caught.exception.result.pid, os.WNOHANG)
                        if fault == '8193':
                            self.assertGreaterEqual(account.read_bytes, 8193)
                        for earlier, later in zip(scans, scans[1:]):
                            self.assertGreater(later[1], earlier[1])
                            self.assertGreaterEqual(later[2], earlier[2])
                        if fault == 'other-z':
                            self.assertGreaterEqual(len(scans), 2)
                            term = [at for pid, sig, at in signals if sig == signal.SIGTERM]
                            kill = [at for pid, sig, at in signals if sig == signal.SIGKILL]
                            self.assertTrue(term and kill)
                            self.assertLessEqual(kill[0] - term[0], 5.5)
                            self.assertLessEqual(time.monotonic() - kill[0], 10.5)
                        self.assertEqual(opened, {})
                    finally:
                        primary = sys.exception()
                        errors = []
                        for descriptor in tuple(opened):
                            try:
                                real_close(descriptor)
                            except OSError as error:
                                errors.append(error)
                            else:
                                opened.pop(descriptor)
                        if errors:
                            if primary is None:
                                raise errors[0]
                            primary.add_note('Independent proc descriptor cleanup failed: ' + repr(errors))
                self.invoke_linux(body)

    def test_exact_stream_and_aggregate_boundaries(self):
        for out, err, prior, accepted in ((8*MIB, 0, 0, True), (8*MIB+1, 0, 0, False),
                                         (0, 8*MIB, 0, True), (0, 8*MIB+1, 0, False),
                                         (16, 16, 16*MIB-32, True), (16, 17, 16*MIB-32, False)):
            with self.subTest(out=out, err=err, prior=prior):
                def body(setup, patches):
                    account = setup[0]
                    account.stream_bytes = account.retained_stream_bytes = prior
                    account.read_bytes = prior
                    account.spent_bytes = prior * 3
                    write_child(setup, f'for fd, total in ((1, {out}), (2, {err})):\n    while total:\n        count = os.write(fd, b"x" * min(total, 65536))\n        total -= count')
                    if accepted:
                        result = base.run(setup)
                        self.assertEqual((len(result.stdout), len(result.stderr)), (out, err))
                        self.assertEqual(account.stream_bytes, prior + out + err)
                        self.assertEqual(account.retained_stream_bytes, prior + out + err)
                        assert_reaped(self, result)
                    else:
                        with self.assertRaises(runner._OriginalStageError) as caught:
                            base.run(setup)
                        result = caught.exception.result
                        self.assertEqual(result.reason, 'stream-limit')
                        self.assertTrue(account.stopped)
                        self.assertLessEqual(len(result.stdout), 8*MIB)
                        self.assertLessEqual(len(result.stderr), 8*MIB)
                        self.assertLessEqual(account.retained_stream_bytes, 16*MIB)
                        self.assertEqual(account.stream_bytes, prior + out + err)
                        assert_reaped(self, result)
                    self.assertLessEqual(account.spent_bytes, CAP)
                self.invoke_linux(body)

    def test_stream_budget_reserve_and_categories_do_not_borrow(self):
        for field, value in (('spent_bytes', CAP), ('metadata_visits', 64000),
                             ('stream_bytes', 16*MIB), ('retained_stream_bytes', 16*MIB)):
            with self.subTest(field=field):
                def body(setup, patches):
                    account = setup[0]
                    setattr(account, field, value)
                    before = (account.spent_bytes, account.read_bytes, account.retained_bytes, account.retained_members,
                              account.metadata_visits, account.stream_bytes, account.retained_stream_bytes)
                    launches = []
                    real = subprocess.Popen
                    def popen(*args, **kwargs):
                        launches.append(True)
                        return real(*args, **kwargs)
                    patches.enter_context(mock.patch.object(subprocess, 'Popen', popen))
                    with self.assertRaises(runner._OriginalStageError):
                        base.run(setup)
                    self.assertEqual(launches, [])
                    self.assertTrue(account.stopped)
                    self.assertEqual((account.spent_bytes, account.read_bytes, account.retained_bytes, account.retained_members,
                                      account.metadata_visits, account.stream_bytes, account.retained_stream_bytes), before)
                self.invoke_linux(body)

    def test_exact_success_debit_from_real_reads_and_fixed_scan_passes(self):
        def body(setup, patches):
            account = setup[0]
            account.secrets = (b'absent-fixture-secret-one', b'absent-fixture-secret-two')
            account.retained_bytes, account.retained_members = 16*MIB, 64
            write_child(setup, 'os.write(1, b"abcdefgh")\nos.write(2, b"ijklmnop")')
            pipe_fds, proc_fds, stream, proc, scans = {}, set(), [], [], []
            real_popen, real_open, real_read, real_close, real_search = subprocess.Popen, os.open, os.read, os.close, re.search
            def popen(*args, **kwargs):
                child = real_popen(*args, **kwargs)
                if args and b'requirements' in args[0]:
                    pipe_fds.update({pipe.fileno(): os.fstat(pipe.fileno()).st_ino for pipe in (child.stdout, child.stderr)})
                return child
            def open_file(path, flags, *args, **kwargs):
                fd = real_open(path, flags, *args, **kwargs)
                text = os.fsdecode(path) if isinstance(path, (str, bytes, os.PathLike)) else ''
                if text.startswith('/proc/') and text.endswith('/stat'):
                    proc_fds.add(fd)
                return fd
            def read(fd, n):
                if fd in pipe_fds and os.fstat(fd).st_ino == pipe_fds[fd]:
                    self.assertLessEqual(n, 65536)
                    self.assertGreater(n, 0)
                    self.assertGreaterEqual(CAP - account.spent_bytes, (len(account.secrets)+3)*n)
                    data = real_read(fd, min(n, 4))
                    stream.append(len(data))
                else:
                    data = real_read(fd, n)
                    if fd in proc_fds:
                        proc.append(len(data))
                return data
            def close(fd):
                result = real_close(fd)
                proc_fds.discard(fd)
                pipe_fds.pop(fd, None)
                return result
            def search(pattern, data, *args, **kwargs):
                if isinstance(pattern, bytes) and b'authorization' in pattern.lower():
                    scans.append(len(data))
                return real_search(pattern, data, *args, **kwargs)
            patches.enter_context(mock.patch.object(subprocess, 'Popen', popen))
            patches.enter_context(mock.patch.object(os, 'open', open_file))
            patches.enter_context(mock.patch.object(os, 'read', read))
            patches.enter_context(mock.patch.object(os, 'close', close))
            patches.enter_context(mock.patch.object(re, 'search', search))
            try:
                result = base.run(setup)
                self.assertEqual(result.stdout, b'abcdefgh')
                self.assertEqual(result.stderr, b'ijklmnop')
                self.assertEqual(sum(stream), 16)
                self.assertGreaterEqual(sum(scans), 16)
                self.assertEqual(account.read_bytes, sum(stream) + sum(proc))
                self.assertEqual(account.stream_bytes, 16)
                self.assertEqual(account.retained_stream_bytes, 16)
                self.assertEqual(account.spent_bytes, sum(proc) + 2*sum(stream) + 3*sum(scans))
                self.assertEqual((account.retained_bytes, account.retained_members), (16*MIB, 64))
                assert_reaped(self, result)
                self.assertEqual(proc_fds, set())
            finally:
                primary = sys.exception()
                errors = []
                for descriptor in tuple(proc_fds):
                    try:
                        real_close(descriptor)
                    except OSError as error:
                        errors.append(error)
                    else:
                        proc_fds.discard(descriptor)
                if errors:
                    if primary is None:
                        raise errors[0]
                    primary.add_note('Independent proc descriptor cleanup failed: ' + repr(errors))
        self.invoke_linux(body)

    def test_sensitive_patterns_and_secret_split_between_actual_reads(self):
        tokens = (b'benign-fixture-secret', b'Authorization : bearer benign', b'github_pat_Benign123',
                  b'ghp_Benign123', b'gho_Benign123', b'ghu_Benign123', b'ghs_Benign123',
                  b'ghr_Benign123', b'X-Amz-Signature=benign', b'sig=benign')
        for token in tokens:
            for fd in (1, 2):
                with self.subTest(token=token, fd=fd):
                    def body(setup, patches):
                        account = setup[0]
                        account.secrets = (tokens[0],)
                        write_child(setup, f'os.write({fd}, {token!r})')
                        pipe_fds, chunks = {}, []
                        real_popen, real_read = subprocess.Popen, os.read
                        def popen(*args, **kwargs):
                            child = real_popen(*args, **kwargs)
                            if args and b'requirements' in args[0]:
                                pipe_fds.update({pipe.fileno(): os.fstat(pipe.fileno()).st_ino for pipe in (child.stdout, child.stderr)})
                            return child
                        def read(number, n):
                            is_stream = number in pipe_fds and os.fstat(number).st_ino == pipe_fds[number]
                            data = real_read(number, min(n, 1) if is_stream else n)
                            if is_stream and data:
                                chunks.append(data)
                            return data
                        patches.enter_context(mock.patch.object(subprocess, 'Popen', popen))
                        patches.enter_context(mock.patch.object(os, 'read', read))
                        with self.assertRaises(runner._OriginalStageError) as caught:
                            base.run(setup)
                        self.assertGreater(len(chunks), 1)
                        self.assertTrue(all(len(chunk) == 1 for chunk in chunks))
                        self.assertTrue(account.stopped)
                        result = caught.exception.result
                        self.assertEqual(result.stdout, b'')
                        self.assertEqual(result.stderr, b'')
                        self.assertIs(result, account.last_direct)
                        self.assertNotIn(token.decode(), repr(result))
                        self.assertGreaterEqual(account.read_bytes, sum(map(len, chunks)))
                        self.assertGreaterEqual(account.spent_bytes, 3 * sum(map(len, chunks)))
                        assert_reaped(self, result)
                    self.invoke_linux(body)


if __name__ == '__main__':
    unittest.main()
