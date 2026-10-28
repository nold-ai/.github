import dataclasses
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


class OwnedReadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(os.environ['FIXED_PREFLIGHT_PATH'])
        if not path.is_absolute():
            raise ValueError('absolute FIXED_PREFLIGHT_PATH required')
        spec = importlib.util.spec_from_file_location('fixed_owned_read_subject', path)
        cls.subject = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.subject
        spec.loader.exec_module(cls.subject)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve(strict=True)
        self.root.chmod(0o700)
        self.root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.addCleanup(os.close, self.root_fd)
        value = os.fstat(self.root_fd)
        self.binding = self.subject._OwnedRoot(
            self.root, self.root_fd, value.st_dev, value.st_ino, value.st_uid, value.st_mode)
        self.path = self.root / 'plan.json'
        self.payload = b'{"plan":1}\n'
        self.path.write_bytes(self.payload)
        self.path.chmod(0o600)
        self.account = self.subject._AttemptAccount(
            self.binding, time.monotonic_ns() + 60_000_000_000, ())
        self.role = self.subject._SourceRole.PLAN
        self.opens = []
        self.reads = []
        self.real_open = os.open
        self.real_read = os.read

    def read(self, role=None):
        try:
            return self.subject._read_owned(self.account, self.role if role is None else role)
        except NotImplementedError as error:
            trace = error.__traceback__
            while trace.tb_next is not None:
                trace = trace.tb_next
            if (type(error) is NotImplementedError
                    and error.args == ('NEW owned-read boundary missing',)
                    and trace.tb_frame.f_code is self.subject._read_owned.__code__):
                raise AssertionError('NEW owned-read boundary missing') from error
            raise

    def recording_open(self, path, flags, *args, **kwargs):
        fd = self.real_open(path, flags, *args, **kwargs)
        self.opens.append((path, flags, kwargs.get('dir_fd'), fd))
        return fd

    def recording_read(self, fd, count):
        raw = self.real_read(fd, count)
        self.reads.append(raw)
        return raw

    def assert_closed(self):
        self.assertEqual(len(self.opens), 1)
        with self.assertRaises(OSError):
            os.fstat(self.opens[0][3])
        self.assertEqual(os.fstat(self.root_fd).st_ino, self.binding.inode)

    def assert_stopped(self, spent, observed=0):
        self.assertTrue(self.account.stopped)
        self.assertEqual(self.account.spent_bytes, spent)
        self.assertEqual(self.account.read_bytes, observed)
        self.assertEqual(self.account.retained_bytes, 0)
        self.assertEqual(self.account.retained_members, 0)
        prior = self.account.metadata_visits
        prior_opens, prior_reads = len(self.opens), len(self.reads)
        with patch.object(self.subject.os, 'open', self.recording_open):
            with patch.object(self.subject.os, 'read', self.recording_read):
                with self.assertRaises(self.subject._OwnedReadError):
                    self.read()
        self.assertEqual(self.account.metadata_visits, prior)
        self.assertEqual(len(self.opens), prior_opens)
        self.assertEqual(len(self.reads), prior_reads)

    def test_complete_read_and_immutable_identity(self):
        before = self.path.stat()
        with patch.object(self.subject.os, 'open', self.recording_open):
            with patch.object(self.subject.os, 'read', self.recording_read):
                result = self.read()
        self.assertEqual(result.role, self.role)
        self.assertEqual(result.data, self.payload)
        self.assertEqual(type(result.data), bytes)
        self.assertEqual(result.sha256, hashlib.sha256(self.payload).hexdigest())
        values = (before.st_dev, before.st_ino, before.st_mode, before.st_uid,
                  before.st_gid, before.st_nlink, before.st_size,
                  before.st_mtime_ns, before.st_ctime_ns)
        self.assertEqual(dataclasses.astuple(result.before), values)
        self.assertEqual(result.before, result.opened)
        self.assertEqual(result.before, result.after)
        self.assertEqual(result.before, result.current)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.data = b'changed'
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.before.inode = 0
        self.assertEqual(self.account.spent_bytes, 4 * len(self.payload))
        self.assertEqual(self.account.read_bytes, len(self.payload))
        self.assertEqual(self.account.retained_bytes, len(self.payload))
        self.assertEqual(self.account.retained_members, 1)
        self.assertEqual(self.account.metadata_visits, 2 * (len(self.root.parts) - 1) + 6)
        self.assertFalse(self.account.stopped)
        self.assertEqual(self.reads, [self.payload])
        name, flags, parent, _ = self.opens[0]
        self.assertEqual(name, 'plan.json')
        self.assertEqual(parent, self.root_fd)
        self.assertEqual(flags & (os.O_NOFOLLOW | os.O_NONBLOCK), os.O_NOFOLLOW | os.O_NONBLOCK)
        self.assertEqual(flags & os.O_ACCMODE, os.O_RDONLY)
        self.assert_closed()

    def test_complete_read_after_previous_metadata_limit(self):
        self.account.metadata_visits = 20000
        with patch.object(self.subject.os, 'open', self.recording_open):
            with patch.object(self.subject.os, 'read', self.recording_read):
                result = self.read()
        self.assertEqual(result.data, self.payload)
        self.assertEqual(result.sha256, hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(self.account.metadata_visits, 20000 + 2 * (len(self.root.parts) - 1) + 6)
        self.assertLessEqual(self.account.metadata_visits, 64000)
        self.assertEqual(self.account.spent_bytes, 4 * len(self.payload))
        self.assertEqual(self.account.read_bytes, len(self.payload))
        self.assertEqual(self.reads, [self.payload])
        self.assertFalse(self.account.stopped)
        self.assert_closed()

    def test_payload_admission_below_at_above(self):
        bound = 255 * 1024 * 1024
        admission = 4 * (len(self.payload) + 1)
        for spare in (-1, 0, 1):
            with self.subTest(spare=spare):
                self.account = self.subject._AttemptAccount(
                    self.binding, time.monotonic_ns() + 60_000_000_000, (),
                    spent_bytes=bound - admission - spare)
                initial = self.account.spent_bytes
                self.opens.clear()
                self.reads.clear()
                with patch.object(self.subject.os, 'open', self.recording_open):
                    with patch.object(self.subject.os, 'read', self.recording_read):
                        if spare < 0:
                            with self.assertRaises(self.subject._OwnedReadError):
                                self.read()
                        else:
                            self.assertEqual(self.read().data, self.payload)
                if spare < 0:
                    self.assertEqual(self.opens, [])
                    self.assertEqual(self.reads, [])
                    self.assertEqual(self.account.metadata_visits, len(self.root.parts) + 1)
                    self.assert_stopped(initial)
                else:
                    self.assertEqual(self.account.spent_bytes, initial + 4 * len(self.payload))
                    self.assertLessEqual(self.account.spent_bytes, bound)
                    self.assert_closed()

    def test_empty_read_still_needs_overrun_allowance(self):
        self.path.write_bytes(b'')
        with patch.object(self.subject.os, 'open', self.recording_open):
            result = self.read()
        self.assertEqual(result.data, b'')
        self.assertEqual(result.sha256, hashlib.sha256(b'').hexdigest())
        self.assertEqual(self.account.spent_bytes, 0)
        self.assertEqual(self.account.retained_members, 1)
        self.assert_closed()
        self.account = self.subject._AttemptAccount(
            self.binding, time.monotonic_ns() + 60_000_000_000, (), spent_bytes=255 * 1024 * 1024 - 3)
        self.opens.clear()
        with patch.object(self.subject.os, 'open', self.recording_open):
            with self.assertRaises(self.subject._OwnedReadError):
                self.read()
        self.assertEqual(self.opens, [])
        self.assert_stopped(255 * 1024 * 1024 - 3)

    def test_category_and_member_denial_precedes_open(self):
        for field, value in [('retained_bytes', 16 * 1024 * 1024 - len(self.payload) + 1),
                             ('retained_members', 64)]:
            with self.subTest(field=field):
                self.account = self.subject._AttemptAccount(
                    self.binding, time.monotonic_ns() + 60_000_000_000, ())
                setattr(self.account, field, value)
                with patch.object(self.subject.os, 'open', self.recording_open):
                    with self.assertRaises(self.subject._OwnedReadError):
                        self.read()
                self.assertEqual(self.opens, [])
                self.assertEqual(getattr(self.account, field), value)
                self.assertEqual(self.account.spent_bytes, 0)
                self.assertTrue(self.account.stopped)

    def test_metadata_and_clock_denial_have_no_io(self):
        near_reservation = 64000 - (2 * (len(self.root.parts) - 1) + 6) + 1
        for field, value in [('metadata_visits', 64000), ('metadata_visits', 64001),
                             ('metadata_visits', near_reservation), ('deadline_ns', 1)]:
            with self.subTest(field=field):
                self.account = self.subject._AttemptAccount(
                    self.binding, time.monotonic_ns() + 60_000_000_000, ())
                self.opens = []
                self.reads = []
                setattr(self.account, field, value)
                with (
                    patch.object(self.subject.os, 'open', self.recording_open),
                    patch.object(self.subject.os, 'read', self.recording_read),
                    patch.object(self.subject.os, 'lstat', wraps=os.lstat) as metadata,
                    patch.object(self.subject.os, 'fstat', wraps=os.fstat) as descriptor_metadata,
                    patch.object(self.subject.os, 'stat', wraps=os.stat) as path_metadata,
                ):
                    with self.assertRaises(self.subject._OwnedReadError):
                        self.read()
                metadata.assert_not_called()
                descriptor_metadata.assert_not_called()
                path_metadata.assert_not_called()
                self.assertEqual(self.opens, [])
                self.assertEqual(self.reads, [])
                self.assertEqual(self.account.metadata_visits, value if field == 'metadata_visits' else 0)
                self.assert_stopped(0)
    def test_malformed_inputs_do_not_open(self):
        for field, value in [('spent_bytes', True), ('read_bytes', -1),
                             ('deadline_ns', 2**63), ('secrets', (b'short',)),
                             ('retained_members', 65)]:
            with self.subTest(field=field):
                self.account = self.subject._AttemptAccount(
                    self.binding, time.monotonic_ns() + 60_000_000_000, ())
                setattr(self.account, field, value)
                with patch.object(self.subject.os, 'open', self.recording_open):
                    with self.assertRaises(self.subject._OwnedReadError):
                        self.read()
                self.assertEqual(self.opens, [])
                self.assertEqual(self.account.metadata_visits, 0)
                self.assertTrue(self.account.stopped)

    def test_unknown_role_does_not_open(self):
        with patch.object(self.subject.os, 'open', self.recording_open):
            with self.assertRaises(self.subject._OwnedReadError):
                self.read('plan.json')
        self.assertEqual(self.opens, [])
        self.assert_stopped(0)

    def test_filesystem_anchor_is_refused_before_metadata(self):
        self.account.root = dataclasses.replace(self.binding, path=Path('/'))
        with (
            patch.object(self.subject.os, 'lstat', wraps=os.lstat) as lstat_call,
            patch.object(self.subject.os, 'fstat', wraps=os.fstat) as fstat_call,
            patch.object(self.subject.os, 'stat', wraps=os.stat) as stat_call,
            patch.object(self.subject.os, 'open', wraps=os.open) as open_call,
            patch.object(self.subject.os, 'read', wraps=os.read) as read_call,
        ):
            with self.assertRaises(self.subject._OwnedReadError):
                self.read()
        for call in (lstat_call, fstat_call, stat_call, open_call, read_call):
            call.assert_not_called()
        self.assertEqual(self.account.metadata_visits, 0)
        self.assert_stopped(0)

    def test_child_symlink_and_directory_are_refused(self):
        self.path.unlink()
        self.path.symlink_to(self.root / 'elsewhere')
        with patch.object(self.subject.os, 'open', self.recording_open):
            with self.assertRaises(self.subject._OwnedReadError):
                self.read()
        self.assertEqual(self.opens, [])
        self.assert_stopped(0)
        self.path.unlink()
        self.path.mkdir()
        self.account = self.subject._AttemptAccount(
            self.binding, time.monotonic_ns() + 60_000_000_000, ())
        with patch.object(self.subject.os, 'open', self.recording_open):
            with self.assertRaises(self.subject._OwnedReadError):
                self.read()
        self.assertEqual(self.opens, [])
        self.assert_stopped(0)

    def test_root_identity_and_mode_are_required(self):
        self.account.root = dataclasses.replace(self.binding, inode=self.binding.inode + 1)
        with patch.object(self.subject.os, 'open', self.recording_open):
            with self.assertRaises(self.subject._OwnedReadError):
                self.read()
        self.assertEqual(self.opens, [])
        self.assert_stopped(0)
        self.account = self.subject._AttemptAccount(
            self.binding, time.monotonic_ns() + 60_000_000_000, ())
        self.root.chmod(0o755)
        with patch.object(self.subject.os, 'open', self.recording_open):
            with self.assertRaises(self.subject._OwnedReadError):
                self.read()
        self.assertEqual(self.opens, [])
        self.assert_stopped(0)

    def test_real_truncate_grow_and_mode_change_at_read(self):
        for mutation in ('truncate', 'grow', 'mode'):
            with self.subTest(mutation=mutation):
                self.path.write_bytes(self.payload)
                self.path.chmod(0o600)
                self.account = self.subject._AttemptAccount(
                    self.binding, time.monotonic_ns() + 60_000_000_000, ())
                self.opens.clear()
                self.reads.clear()
                def changed_read(fd, count):
                    if mutation == 'truncate':
                        self.path.write_bytes(self.payload[:-1])
                    elif mutation == 'grow':
                        self.path.write_bytes(self.payload + b'x')
                    else:
                        self.path.chmod(0o400)
                    return self.recording_read(fd, count)
                with patch.object(self.subject.os, 'open', self.recording_open):
                    with patch.object(self.subject.os, 'read', changed_read):
                        with self.assertRaises(self.subject._OwnedReadError):
                            self.read()
                observed = len(self.payload) + {'truncate': -1, 'grow': 1, 'mode': 0}[mutation]
                self.assertEqual(sum(map(len, self.reads)), observed)
                self.assert_stopped(4 * (len(self.payload) + 1), observed)
                self.assert_closed()

    def test_sensitive_bytes_are_withheld_and_charged(self):
        for secret, payload in [((), b'github_pat_abc123'), ((b'private-value',), b'private-value')]:
            with self.subTest(secret=bool(secret)):
                self.path.write_bytes(payload)
                self.account = self.subject._AttemptAccount(
                    self.binding, time.monotonic_ns() + 60_000_000_000, secret)
                self.opens.clear()
                with patch.object(self.subject.os, 'open', self.recording_open):
                    with self.assertRaises(self.subject._OwnedReadError) as refused:
                        self.read()
                self.assertNotIn(payload.decode(), str(refused.exception))
                self.assert_stopped((len(secret) + 4) * (len(payload) + 1), len(payload))
                self.assert_closed()

    def test_replacement_at_open_is_refused_without_payload_read(self):
        replacement = self.root / 'replacement'
        replacement.write_bytes(self.payload)
        replacement.chmod(0o600)
        def replaced_open(path, flags, *args, **kwargs):
            replacement.replace(self.path)
            return self.recording_open(path, flags, *args, **kwargs)
        with patch.object(self.subject.os, 'open', replaced_open):
            with patch.object(self.subject.os, 'read', self.recording_read):
                with self.assertRaises(self.subject._OwnedReadError):
                    self.read()
        self.assertEqual(self.reads, [])
        self.assert_stopped(4 * (len(self.payload) + 1))
        self.assert_closed()

    def test_parent_symlink_is_refused(self):
        actual = self.root / 'actual'
        actual.mkdir(mode=0o700)
        child = actual / 'child'
        child.mkdir(mode=0o700)
        (child / 'plan.json').write_bytes(self.payload)
        (child / 'plan.json').chmod(0o600)
        alias = self.root / 'alias'
        alias.symlink_to(actual, target_is_directory=True)
        fd = self.real_open(child, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.addCleanup(os.close, fd)
        value = os.fstat(fd)
        binding = self.subject._OwnedRoot(alias / 'child', fd, value.st_dev,
                                          value.st_ino, value.st_uid, value.st_mode)
        self.account = self.subject._AttemptAccount(
            binding, time.monotonic_ns() + 60_000_000_000, ())
        with patch.object(self.subject.os, 'open', self.recording_open):
            with self.assertRaises(self.subject._OwnedReadError):
                self.read()
        self.assertEqual(self.opens, [])
        self.assert_stopped(0)

    def test_exact_retention_limits_and_safe_secret_scan(self):
        initial = 16 * 1024 * 1024 - len(self.payload)
        self.account = self.subject._AttemptAccount(
            self.binding, time.monotonic_ns() + 60_000_000_000, (b'not-in-the-plan',),
            retained_bytes=initial, retained_members=63)
        result = self.read()
        self.assertEqual(result.data, self.payload)
        self.assertEqual(self.account.spent_bytes, 5 * len(self.payload))
        self.assertEqual(self.account.retained_bytes, 16 * 1024 * 1024)
        self.assertEqual(self.account.retained_members, 64)
        self.assertFalse(self.account.stopped)

    def test_open_failure_is_conservatively_charged(self):
        with patch.object(self.subject.os, 'open', side_effect=OSError('synthetic open failure')):
            with self.assertRaises(self.subject._OwnedReadError):
                self.read()
        self.assert_stopped(4 * (len(self.payload) + 1))
        self.assertEqual(os.fstat(self.root_fd).st_ino, self.binding.inode)

    def test_short_syscall_is_incomplete_and_descriptor_closes(self):
        def short_read(fd, count):
            return self.recording_read(fd, count - 2)
        with patch.object(self.subject.os, 'open', self.recording_open):
            with patch.object(self.subject.os, 'read', short_read):
                with self.assertRaises(self.subject._OwnedReadError):
                    self.read()
        self.assert_stopped(4 * (len(self.payload) + 1), len(self.payload) - 1)
        self.assert_closed()

    def test_repeated_reads_charge_every_retained_copy(self):
        first = self.read()
        second = self.read()
        self.assertEqual(first.data, second.data)
        self.assertEqual(self.account.spent_bytes, 8 * len(self.payload))
        self.assertEqual(self.account.read_bytes, 2 * len(self.payload))
        self.assertEqual(self.account.retained_bytes, 2 * len(self.payload))
        self.assertEqual(self.account.retained_members, 2)


if __name__ == '__main__':
    unittest.main()
