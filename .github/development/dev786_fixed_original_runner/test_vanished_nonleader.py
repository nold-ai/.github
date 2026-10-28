"""Synthetic only. Root runs this file with an explicit preflight source path."""
import ast
import contextlib
import pathlib
import sys
import types
import unittest


SOURCE = pathlib.Path(sys.argv.pop(1))


class Refusal(Exception):
    pass


def extracted_factory():
    tree = ast.parse(SOURCE.read_text())
    owner = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                 and n.name == '_run_original_stage')
    selected = [next(n for n in owner.body if isinstance(n, ast.FunctionDef)
                     and n.name == name) for name in ('visit', 'group_empty')]
    wrapper = ast.parse('''
def factory(os, time, account, clock_check, refuse, remember, outstanding, terminal):
    pid = 2203
    leader_start = 99
    owned = True
    def state():
        return owned, leader_start
    return group_empty, state
''')
    wrapper.body[0].body[-1:-1] = selected
    namespace = {'sys': sys, 'MIB': 1024 * 1024}
    exec(compile(ast.fix_missing_locations(wrapper), str(SOURCE), 'exec'), namespace)
    return namespace['factory']


def stat(pid, state='Z', group=2203):
    fields = [state, '1', str(group), str(group)] + ['0'] * 15 + ['99']
    return (str(pid) + ' (fixture) ' + ' '.join(fields)).encode()


def scenario(entries, *, faults=None, visits=0, spent=0, now=0, terminal=(2203, 1, 0)):
    faults = faults or {}
    account = types.SimpleNamespace(metadata_visits=visits, spent_bytes=spent, read_bytes=0)
    calls = {'open': [], 'read': [], 'close': [], 'seen': [], 'clock': [], 'remember': []}
    descriptors = {}

    def refuse(reason):
        raise Refusal(reason)

    def enumeration():
        for entry in entries:
            if isinstance(entry, BaseException):
                raise entry
            calls['seen'].append(entry)
            yield types.SimpleNamespace(name=str(entry))

    def opened(path, flags):
        pid = int(path.split('/')[2])
        calls['open'].append(pid)
        fault = faults.get(('open', pid))
        if fault is not None:
            raise fault
        descriptor = object()
        descriptors[descriptor] = pid
        return descriptor

    def read(descriptor, count):
        pid = descriptors[descriptor]
        calls['read'].append((pid, count))
        value = faults.get(('read', pid), stat(pid))
        if isinstance(value, BaseException):
            raise value
        return value

    def close(descriptor):
        pid = descriptors.pop(descriptor)
        calls['close'].append(pid)
        fault = faults.get(('close', pid))
        if fault is not None:
            raise fault

    fake_os = types.SimpleNamespace(scandir=lambda path: contextlib.nullcontext(enumeration()),
                                    open=opened, read=read, close=close,
                                    O_RDONLY=0, O_NOFOLLOW=1, O_NONBLOCK=2)
    scan, state = extracted_factory()(
        fake_os, types.SimpleNamespace(monotonic=lambda: now), account,
        lambda: calls['clock'].append(True), refuse, calls['remember'].append,
        lambda: 0, terminal)
    return scan, state, account, calls, descriptors


class Synthetic(unittest.TestCase):
    def test_vanished_nonleader_continues_complete_scan(self):
        scan, state, account, calls, descriptors = scenario(
            [2204, 2203, 2205], faults={('open', 2204): FileNotFoundError(2, 'gone'),
                                      ('read', 2205): stat(2205, 'S', 2205)})
        self.assertTrue(scan(10))
        self.assertEqual(state(), (True, 99))
        self.assertEqual(calls['seen'], [2204, 2203, 2205])
        self.assertEqual(calls['open'], [2204, 2203, 2205])
        self.assertEqual(calls['close'], [2203, 2205])
        self.assertEqual([pid for pid, count in calls['read']], [2203, 2205])
        self.assertEqual(account.metadata_visits, 8)
        self.assertEqual(account.read_bytes, len(stat(2203)) + len(stat(2205, 'S', 2205)))
        self.assertEqual(account.spent_bytes, account.read_bytes)
        self.assertFalse(descriptors)

    def test_missing_owned_leader_revokes(self):
        scan, state, account, calls, descriptors = scenario(
            [2203], faults={('open', 2203): FileNotFoundError(2, 'gone')})
        with self.assertRaisesRegex(Refusal, '^ownership$'):
            scan(10)
        self.assertFalse(state()[0])
        self.assertEqual(account.metadata_visits, 3)
        self.assertEqual(account.spent_bytes, 8193)
        self.assertEqual(account.read_bytes, 0)
        self.assertFalse(calls['read'] or calls['close'] or descriptors)

    def test_other_io_failures_keep_refusal_and_debit(self):
        for operation, error in [('open', PermissionError(13, 'denied')),
                                 ('open', OSError(5, 'io')),
                                 ('read', FileNotFoundError(2, 'gone')),
                                 ('close', FileNotFoundError(2, 'gone'))]:
            with self.subTest(operation=operation, error=type(error).__name__):
                scan, state, account, calls, descriptors = scenario(
                    [2204, 2203], faults={(operation, 2204): error})
                with self.assertRaisesRegex(Refusal, '^proc$'):
                    scan(10)
                self.assertEqual(account.spent_bytes, 8193)
                self.assertEqual(calls['seen'], [2204])
                self.assertEqual(calls['close'], [] if operation == 'open' else [2204])
                self.assertFalse(descriptors)

    def test_enumeration_failure_is_not_absence(self):
        scan, state, account, calls, descriptors = scenario(
            [2204, FileNotFoundError(2, 'enumeration')],
            faults={('open', 2204): FileNotFoundError(2, 'gone')})
        with self.assertRaisesRegex(Refusal, '^proc$'):
            scan(10)
        self.assertEqual(account.spent_bytes, 0)
        self.assertFalse(calls['close'] or descriptors)

    def test_malformed_and_present_zombie_keep_behavior(self):
        for raw, reason in [(b'invalid', 'proc'), (stat(2204), None)]:
            with self.subTest(raw=raw):
                scan, state, account, calls, descriptors = scenario(
                    [2204, 2203], faults={('read', 2204): raw})
                if reason:
                    with self.assertRaisesRegex(Refusal, '^proc$'):
                        scan(10)
                    self.assertEqual(account.spent_bytes, 8193)
                else:
                    self.assertFalse(scan(10))
                    self.assertEqual(calls['seen'], [2204, 2203])
                self.assertFalse(descriptors)

    def test_budgets_and_deadline_remain_bound(self):
        for options, reason in [({'visits': 19997}, 'budget'),
                                ({'spent': 255 * 1024 * 1024 - 8192}, 'budget'),
                                ({'now': 10}, 'cleanup')]:
            with self.subTest(options=options):
                scan, state, account, calls, descriptors = scenario(
                    [2204, 2203], faults={('open', 2204): FileNotFoundError(2, 'gone')},
                    **options)
                with self.assertRaisesRegex(Refusal, '^' + reason + '$'):
                    scan(10)
                self.assertLessEqual(account.metadata_visits, 20000)
                self.assertLessEqual(account.spent_bytes, 255 * 1024 * 1024)
                self.assertFalse(calls['read'] or calls['close'] or descriptors)

    def test_complete_scan_still_needs_leader_and_terminal(self):
        scan, state, account, calls, descriptors = scenario(
            [2204], faults={('open', 2204): FileNotFoundError(2, 'gone')})
        with self.assertRaisesRegex(Refusal, '^ownership$'):
            scan(10)
        self.assertFalse(state()[0])
        scan, state, account, calls, descriptors = scenario([2203], terminal=None)
        self.assertFalse(scan(10))
        self.assertTrue(state()[0])
        self.assertFalse(descriptors)


if __name__ == '__main__':
    unittest.main()
