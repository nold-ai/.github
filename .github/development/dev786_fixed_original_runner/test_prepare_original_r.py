"""Draft stdlib tests. Local Git + Synthetic API never confer native authority."""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

R = '4ae6175a4d337296d0347e73b66c9da1f0e43f7f'
C = '9b5ad1e78430cc0b061cb16de42f73de96f4f312'
RT = 'baeb88acf0d2a5015810ad12dbfccfa7fdf9a21e'
CT = '24112d8c9983333f9059283965230348f718b74c'
RAW = '43f81bdc267a38928838620dd35a741e6329d46243fc78a9160a7a7ee3913a2e'
URL = 'https://github.com/nold-ai/specfact-cli.git'
BASE = '/repos/nold-ai/specfact-cli'
SOURCES = (
    ('tests/unit/scripts/test_dependency_compatibility_workflow.py', '416e367877990ebb2d809e11847c363cd599c32f32d014a818f09053d5fab7fa'),
    ('tests/unit/scripts/test_dependency_trust_review.py', 'bb20822cb58c8f773f8ed7a54628feef2e1eadbf5cc5c53936422223986ee7ac'),
    ('tests/unit/scripts/test_security_audit_gate.py', '5100ceaa78a4381b8565f5a3c996e8d8b15ceda44d18de9ebcf04eb0561f81a3'),
    ('tests/unit/security/test_frozen_gitpython_compatibility.py', 'c1d428aba630c5f4abd4f236c10540632fb86e9c0e93ea1a9ba91809dbe415af'),
    ('tests/unit/security/test_release_dependency_selection.py', 'f713acdfeba8235bd5f7e2c22b7a29585d61693798972b6e9a24a31423e7a4e6'),
    ('scripts/requirements_proof_pytest_plugin.py', '31a1a8e3f7cf4e9d35612e4395c03298be85262da2bcc91b33008919f2a24de8'),
    ('openspec/changes/security-dependencies-0-55-11-dev/requirements-evidence.yaml', '6a1f812cc9a0be0adf260cdfb48dda0a5af3c41b5827259459373123861e9e20'),
    ('openspec/changes/security-dependencies-0-55-11-dev/requirements-proof/review-evidence.json', 'a5664876536b22616c93489ceb4baacd9ba07515f83216e2441289aaf3606707'),
    ('requirements/ci/locked.txt', '0bf003b492508a171177f2ba386126b76200262e7e49c3d1a25e1c8139250266'),
    ('uv.lock', '850b941d7d7dabf102d39ce92fb23d7586d183384fac03c140ceae0a07d169b7'),
)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class MissingNew(unittest.TestCase):
    def test_00_original_r_body_is_missing(self):
        target = getattr(candidate, '_prepare_original_r', None)
        self.assertTrue(callable(target), 'NEW target _prepare_original_r is missing')
        try:
            target(None, None)
        except BaseException as error:
            self.assertIs(type(error), candidate._OriginalRNotImplemented)
            self.assertEqual(str(error), 'NEW original R preparation is not implemented')
            terminal = error.__traceback__
            while terminal.tb_next is not None:
                terminal = terminal.tb_next
            self.assertIs(terminal.tb_frame.f_code, target.__code__)
            self.assertEqual(Path(terminal.tb_frame.f_code.co_filename).resolve(),
                             options.candidate.resolve())
            self.fail('NEW target _prepare_original_r has no implementation')
        self.fail('Missing-NEW probe must not return successful prepared facts')


class RealGitSyntheticAPI(unittest.TestCase):
    def setUp(self):
        self.assertTrue(callable(getattr(candidate, '_prepare_original_r', None)),
                        'NEW target _prepare_original_r is missing')
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.previous_signal_handler = signal.getsignal(signal.SIGALRM)
        self.temporary = tempfile.TemporaryDirectory(prefix='original-r-test-')
        self.addCleanup(self.temporary.cleanup)
        out = Path(self.temporary.name).resolve()
        os.chmod(out, 0o700)
        descriptor = os.open(out, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.addCleanup(os.close, descriptor)
        value = os.fstat(descriptor)
        owned = candidate._OwnedRoot(out, descriptor, value.st_dev, value.st_ino,
                                     value.st_uid, value.st_mode)
        self.account = candidate._AttemptAccount(owned, time.monotonic_ns() + 400_000_000_000, ())
        self.addCleanup(self.close_preparation_descriptors)
        self.repo = {'id': 1085706003, 'full_name': 'nold-ai/specfact-cli',
                     'name': 'specfact-cli', 'owner': {'id': 225190663, 'login': 'nold-ai'}}
        self.c = {'sha': C, 'tree': {'sha': CT}, 'parents': [],
                  'verification': {'verified': False, 'reason': 'unsigned',
                                   'signature': None, 'payload': None}}
        raw = options.r_metadata.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         'fc6c12457844561262a9a8e92382ae53afe6c163214f77c9ae2e2cc4746f11fb')
        self.r = json.loads(raw)
        self.api_calls = []
        self.api = SimpleNamespace(GitHub=lambda: SimpleNamespace(get=self.synthetic_get))
        self.git_calls = []
        self.real_run = subprocess.run
        self.real_popen = subprocess.Popen
        self.real_waitpid = os.waitpid
        self.launches = []
        self.processes = {}
        self.wait_boundaries = {}
        self.terminal_reaps = []
        self.api_observations = []
        self.mutation = None
        self.after_fetch = None
        self.interrupt_fetch = False
        self.fetch_alarm = []
        self.fetch_alarm_returned = False
        popen_patch = patch.object(subprocess, 'Popen', side_effect=self.local_popen)
        wait_patch = patch.object(os, 'waitpid', side_effect=self.local_waitpid)
        popen_patch.start()
        self.addCleanup(popen_patch.stop)
        wait_patch.start()
        self.addCleanup(wait_patch.stop)

    def close_preparation_descriptors(self):
        preparation = getattr(self.account, 'preparation', None)
        if preparation is not None:
            for name in ('root', 'home', 'tmp', 'template'):
                child = getattr(preparation, name, None)
                descriptor = getattr(child, 'descriptor', None)
                if descriptor is not None:
                    os.close(descriptor)
                    child.descriptor = None

    def synthetic_get(self, path, *, archive=False):
        self.api_observations.append((path, archive))
        self.api_calls.append(path)
        value = {BASE: self.repo, BASE + '/git/commits/' + C: self.c,
                 BASE + '/git/commits/' + R: self.r}[path]
        return json.dumps(value).encode()

    def timer_observation(self):
        timer = getattr(signal.getsignal(signal.SIGALRM), '__self__', None)
        preparation = self.account.preparation
        remaining = (min(self.account.deadline_ns, preparation.deadline_ns)
                     - time.monotonic_ns()) / 1_000_000_000
        return (timer, getattr(timer, 'private_code', None),
                getattr(timer, 'seconds', None),
                signal.getitimer(signal.ITIMER_REAL)[0], remaining)

    def local_popen(self, argv, *args, **kwargs):
        launch = dict(kwargs)
        if isinstance(launch.get('env'), dict):
            launch['env'] = dict(launch['env'])
        observed = (type(argv), tuple(argv), launch, self.timer_observation())
        self.launches.append(observed)
        self.git_calls.append(tuple(argv))
        translated = list(argv)
        if 'fetch' in translated and URL in translated:
            translated[translated.index(URL)] = (options.fixture_root / 'original.git').as_uri()
        process = self.real_popen(translated, *args, **kwargs)
        self.processes[process.pid] = (process, tuple(argv))
        return process

    def local_waitpid(self, pid, options):
        recorded = self.processes.get(pid)
        if recorded is not None and pid not in self.wait_boundaries:
            self.wait_boundaries[pid] = self.timer_observation()
            if self.interrupt_fetch and 'fetch' in recorded[1]:
                self.interrupt_fetch = False
                self.fetch_alarm.append((pid, self.wait_boundaries[pid]))
                signal.raise_signal(signal.SIGALRM)
                self.fetch_alarm_returned = True
        waited, status = self.real_waitpid(pid, options)
        if (recorded is not None and waited == pid
                and (os.WIFEXITED(status) or os.WIFSIGNALED(status))):
            self.terminal_reaps.append((pid, status))
            if os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0:
                if self.after_fetch is not None and 'fetch' in recorded[1]:
                    self.after_fetch(self.account.root.path / 'original-r')
                    self.after_fetch = None
                if self.mutation is not None and 'checkout' in recorded[1]:
                    self.mutation(self.account.root.path / 'original-r')
                    self.mutation = None
        return waited, status

    def assert_timer_observation(self, observation):
        timer, private_code, seconds, active, remaining = observation
        self.assertIs(type(timer), candidate.Timer)
        self.assertIsNone(private_code)
        self.assertGreater(seconds, 0)
        self.assertLessEqual(seconds, 360)
        self.assertGreater(active, 0)
        self.assertGreater(remaining, 0)
        self.assertLessEqual(active, remaining + 0.01)

    def assert_process_observations(self):
        for path, archive in self.api_observations:
            self.assertFalse(archive)
            self.assertIn(path, (BASE, BASE + '/git/commits/' + C, BASE + '/git/commits/' + R))
        for argv_type, argv, kwargs, timer in self.launches:
            self.assertIn(argv_type, (list, tuple))
            self.assertEqual(Path(argv[0]).name, 'git')
            self.assertFalse(kwargs.get('shell', False))
            self.assertNotIn('timeout', kwargs)
            self.assertEqual(set(kwargs['env']),
                             {'HOME', 'TMPDIR', 'PATH', 'LANG', 'LC_ALL', 'GIT_TERMINAL_PROMPT'})
            self.assertEqual(kwargs['env']['GIT_TERMINAL_PROMPT'], '0')
            self.assertEqual(Path(kwargs['env']['HOME']), self.account.root.path / 'home')
            self.assertEqual(Path(kwargs['env']['TMPDIR']), self.account.root.path / 'tmp')
            self.assert_timer_observation(timer)
            if 'fetch' in argv:
                self.assertEqual(argv.count(URL), 1)
                for option in ('--depth=2', '--no-tags', '--no-recurse-submodules', R):
                    self.assertIn(option, argv)
        self.assertEqual(set(self.wait_boundaries), set(self.processes))
        for observation in self.wait_boundaries.values():
            self.assert_timer_observation(observation)
        self.assertEqual(sorted(pid for pid, status in self.terminal_reaps),
                         sorted(self.processes))

    def descendants(self, root):
        pending = [root]
        count = 0
        while pending:
            with os.scandir(pending.pop()) as entries:
                for entry in entries:
                    count += 1
                    if count > 20001:
                        return count
                    if entry.is_dir(follow_symlinks=False):
                        pending.append(Path(entry.path))
        return count

    def reachable_children(self):
        preparation = self.account.preparation
        self.assertIsNotNone(preparation)
        paths = {'root': 'original-r', 'home': 'home', 'tmp': 'tmp',
                 'template': 'git-template'}
        owned = []
        for name, relative in paths.items():
            child = getattr(preparation, name)
            if child is None:
                continue
            self.assertEqual(child.path, self.account.root.path / relative)
            self.assertIs(type(child.created), bool)
            if not child.created:
                self.assertIsNone(child.descriptor)
                continue
            value = os.lstat(child.path)
            self.assertEqual((value.st_dev, value.st_ino, value.st_uid, value.st_mode),
                             (child.device, child.inode, child.uid, child.mode))
            self.assertEqual(value.st_mode & 0o777, 0o700)
            if child.descriptor is not None:
                opened = os.fstat(child.descriptor)
                self.assertEqual((opened.st_dev, opened.st_ino),
                                 (value.st_dev, value.st_ino))
            owned.append(child.path)
        self.assertEqual(len(set(owned)), len(owned))
        return owned

    def git(self, root, *args):
        with patch.object(subprocess, 'Popen', self.real_popen), \
                patch.object(os, 'waitpid', self.real_waitpid):
            return self.real_run(['/usr/bin/git', '-C', str(root), *args], check=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30).stdout

    def test_actual_objects_sources_and_minimal_history(self):
        prepared = candidate._prepare_original_r(self.account, self.api)
        self.assert_process_observations()
        self.assertFalse(self.account.stopped)
        self.assertTrue(self.account.preparation.complete)
        self.assertIs(signal.getsignal(signal.SIGALRM), self.previous_signal_handler)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertEqual(set(self.reachable_children()),
                         {self.account.root.path / name for name in
                          ('original-r', 'home', 'tmp', 'git-template')})
        self.assertEqual((prepared.commit, prepared.parent, prepared.tree, prepared.parent_tree),
                         (R, C, RT, CT))
        self.assertEqual(prepared.out, self.account.root.path)
        self.assertEqual(prepared.root, prepared.out / 'original-r')
        self.assertEqual(tuple(prepared.sources), SOURCES)
        self.assertEqual(prepared.raw_commit_sha256, RAW)
        self.assertEqual(hashlib.sha256(self.git(prepared.root, 'cat-file', 'commit', R)).hexdigest(), RAW)
        self.assertEqual(self.git(prepared.root, 'rev-list', '--reverse', C + '..' + R), (R + '\n').encode())
        self.assertEqual(self.git(prepared.root, 'merge-base', C, R), (C + '\n').encode())
        self.assertEqual(self.git(prepared.root, 'status', '--porcelain', '--untracked-files=no'), b'')
        self.assertEqual((prepared.root / '.git/shallow').read_text(), C + '\n')
        for path, digest in SOURCES:
            source = (prepared.root / path).read_bytes()
            self.assertEqual(source, self.git(prepared.root, 'show', R + ':' + path))
            self.assertEqual(hashlib.sha256(source).hexdigest(), digest)
        self.assertEqual(self.api_calls, [BASE, BASE + '/git/commits/' + C, BASE + '/git/commits/' + R])
        self.assertGreater(self.account.read_bytes, 0)
        self.assertLessEqual(self.account.read_bytes, 256 * 1024 * 1024)

    def refused(self):
        with self.assertRaises(candidate._OriginalRPreparationError):
            candidate._prepare_original_r(self.account, self.api)
        self.assert_process_observations()
        self.assertTrue(self.account.stopped)
        self.assertFalse(self.account.preparation.complete)
        self.assertIs(signal.getsignal(signal.SIGALRM), self.previous_signal_handler)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.reachable_children()

    def no_checkout(self):
        self.assertFalse(any('checkout' in argv for argv in self.git_calls))

    def test_wrong_repository_id(self):
        self.repo['id'] += 1
        self.refused()
        self.assertFalse(any('fetch' in argv for argv in self.git_calls))

    def test_wrong_api_parent(self):
        self.r['parents'][0]['sha'] = '0' * 40
        self.refused()
        self.assertFalse(any('fetch' in argv for argv in self.git_calls))

    def test_expired_account_deadline_has_no_fetch(self):
        self.account.deadline_ns = time.monotonic_ns() - 1
        self.refused()
        self.assertFalse(any("fetch" in argv for argv in self.git_calls))

    def test_r_cannot_be_shallow(self):
        self.mutation = lambda root: (root / ".git/shallow").write_text(R + "\n")
        self.refused()
        self.assertIsNone(self.mutation)

    def test_graft_is_refused(self):
        self.mutation = lambda root: (root / ".git/info/grafts").write_text(R + " " + C + "\n")
        self.refused()
        self.assertIsNone(self.mutation)

    def test_alternate_is_refused(self):
        self.mutation = lambda root: (root / ".git/objects/info/alternates").write_text(str(options.fixture_root / "original.git/objects") + "\n")
        self.refused()
        self.assertIsNone(self.mutation)

    def test_actual_tracked_source_differs_from_blob(self):
        def alter(root):
            path = root / SOURCES[0][0]
            path.write_bytes(path.read_bytes() + b'\n# synthetic test mutation\n')
        self.mutation = alter
        self.refused()
        self.assertIsNone(self.mutation)
        self.assertIsNotNone(self.account.preparation.root)

    def test_actual_index_differs_while_source_bytes_stay_exact(self):
        observed = []
        def alter(root):
            self.git(root, 'update-index', '--force-remove', '--', SOURCES[0][0])
            observed.append((hashlib.sha256((root / SOURCES[0][0]).read_bytes()).hexdigest(),
                             self.git(root, 'diff', '--cached', '--name-only')))
        self.mutation = alter
        self.refused()
        self.assertIsNone(self.mutation)
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0][0], SOURCES[0][1])
        self.assertNotEqual(observed[0][1], b'')

    def test_actual_replace_ref_is_refused(self):
        observed = []
        def alter(root):
            replace = root / '.git/refs/replace'
            replace.mkdir()
            (replace / R).write_text(C + '\n')
            observed.append((replace / R).read_text())
        self.mutation = alter
        self.refused()
        self.assertIsNone(self.mutation)
        self.assertEqual(observed, [C + '\n'])

    def test_actual_alias_config_is_refused(self):
        observed = []
        def alter(root):
            with (root / '.git/config').open('a') as stream:
                stream.write('\n[alias]\n preparation-control = status\n')
            observed.append(self.git(root, 'config', '--local', '--list'))
        self.mutation = alter
        self.refused()
        self.assertIsNone(self.mutation)
        self.assertEqual(len(observed), 1)
        self.assertIn(b'preparation-control', observed[0])

    def test_actual_entry_limit_refuses_before_checkout(self):
        observed = []
        def alter(root):
            baseline = self.descendants(root)
            for number in range(max(0, 20001 - baseline)):
                (root / ('entry-control-%05d' % number)).touch()
            observed.append((baseline, self.descendants(root)))
        self.after_fetch = alter
        self.refused()
        self.assertIsNone(self.after_fetch)
        self.assertEqual(len(observed), 1)
        self.assertLess(observed[0][0], 20000)
        self.assertEqual(observed[0][1], 20001)
        self.no_checkout()
        self.assertIn('fetch', self.git_calls[-1])

    def test_actual_sparse_object_storage_limit_refuses_before_checkout(self):
        observed = []
        def alter(root):
            sizes = []
            allocated = 0
            preexisting = []
            directory = root / '.git/objects/aa'
            directory.mkdir(exist_ok=True)
            for number in range(2):
                path = directory / ('%038x' % number)
                preexisting.append(path.exists())
                with path.open('xb') as stream:
                    stream.truncate(129 * 1024 * 1024)
                sizes.append(path.stat().st_size)
                allocated += path.stat().st_blocks * 512
            observed.append((sum(sizes), allocated, preexisting))
        self.after_fetch = alter
        self.refused()
        self.assertIsNone(self.after_fetch)
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0][0], 258 * 1024 * 1024)
        self.assertLessEqual(observed[0][1], 8 * 1024 * 1024)
        self.assertEqual(observed[0][2], [False, False])
        self.no_checkout()
        self.assertIn('fetch', self.git_calls[-1])

    def test_actual_alarm_at_git_fetch_owner_wait_refuses_without_checkout(self):
        self.interrupt_fetch = True
        self.refused()
        self.assertEqual(len(self.fetch_alarm), 1)
        pid, observation = self.fetch_alarm[0]
        self.assertIn('fetch', self.processes[pid][1])
        self.assert_timer_observation(observation)
        self.assertTrue(observation[0].expired)
        self.assertFalse(observation[0].pending)
        self.assertFalse(self.fetch_alarm_returned)
        self.no_checkout()

    def test_actual_alarm_during_synthetic_api_get_restores_original_handler(self):
        observed = []
        wrong_handler_hits = []
        returned = []
        def previous_handler(number, frame):
            wrong_handler_hits.append(number)
        signal.signal(signal.SIGALRM, previous_handler)
        self.addCleanup(signal.signal, signal.SIGALRM, self.previous_signal_handler)
        self.previous_signal_handler = previous_handler
        def alarm_get(path, *, archive=False):
            self.api_calls.append(path)
            observed.append((path, archive, self.timer_observation()))
            signal.raise_signal(signal.SIGALRM)
            returned.append(True)
            raise RuntimeError('actual SIGALRM did not stop preparation at API boundary')
        self.api = SimpleNamespace(GitHub=lambda: SimpleNamespace(get=alarm_get))
        self.refused()
        self.assertEqual(len(observed), 1)
        path, archive, observation = observed[0]
        self.assertEqual(path, BASE)
        self.assertFalse(archive)
        self.assert_timer_observation(observation)
        self.assertTrue(observation[0].expired)
        self.assertFalse(observation[0].pending)
        self.assertFalse(wrong_handler_hits)
        self.assertFalse(returned)
        self.assertEqual(self.api_calls, [BASE])
        self.assertFalse(self.git_calls)

    def descriptor_failure(self, name):
        order = (('root', 'original-r'), ('home', 'home'),
                 ('tmp', 'tmp'), ('template', 'git-template'))
        failed = tuple(relative for slot, relative in order).index(name)
        real_open = os.open
        target = self.account.root.path / name
        injected = []
        def fail_directory_open(path, flags, *args, **kwargs):
            raw = os.fsdecode(path)
            matching = (Path(raw) == target or
                        (raw == name and kwargs.get('dir_fd') == self.account.root.descriptor))
            if matching and flags & os.O_DIRECTORY and target.is_dir():
                preparation = self.account.preparation
                slots = tuple(getattr(preparation, slot) for slot, relative in order)
                fields = tuple(None if child is None else
                               (child.path, child.created, child.descriptor,
                                child.device, child.inode, child.uid, child.mode)
                               for child in slots)
                actual = tuple(os.lstat(self.account.root.path / relative)
                               for slot, relative in order[:failed + 1])
                opened = tuple(None if child is None or child.descriptor is None else
                               os.fstat(child.descriptor) for child in slots)
                injected.append((preparation, slots, fields, actual, opened))
                raise OSError('synthetic descriptor acquisition failure after actual mkdir')
            return real_open(path, flags, *args, **kwargs)
        with patch.object(os, 'open', side_effect=fail_directory_open):
            self.refused()
        self.assertEqual(len(injected), 1)
        preparation, slots, fields, actual, opened = injected[0]
        self.assertIs(self.account.preparation, preparation)
        prefix = tuple(self.account.root.path / relative for slot, relative in order[:failed + 1])
        self.assertEqual(tuple(self.reachable_children()), prefix)
        self.assertEqual(tuple(field[0] for field in fields if field is not None), prefix)
        for index, (slot, relative) in enumerate(order):
            self.assertIs(getattr(preparation, slot), slots[index])
            if index > failed:
                self.assertIsNone(slots[index])
                self.assertIsNone(fields[index])
                continue
            child = slots[index]
            self.assertIsNotNone(child)
            path, created, descriptor, device, inode, uid, mode = fields[index]
            identity = actual[index]
            self.assertEqual(path, prefix[index])
            self.assertIs(created, True)
            self.assertEqual((device, inode, uid, mode),
                             (identity.st_dev, identity.st_ino, identity.st_uid, identity.st_mode))
            self.assertEqual((child.path, child.created, child.descriptor,
                              child.device, child.inode, child.uid, child.mode), fields[index])
            if index == failed:
                self.assertIsNone(descriptor)
                self.assertIsNone(opened[index])
            else:
                self.assertIsNotNone(descriptor)
                current = os.fstat(descriptor)
                for value in (opened[index], current):
                    self.assertEqual((value.st_dev, value.st_ino, value.st_uid, value.st_mode),
                                     (device, inode, uid, mode))
        self.assertFalse(self.api_calls)
        self.assertFalse(self.git_calls)

    def test_root_descriptor_failure_stays_reachable(self):
        self.descriptor_failure('original-r')

    def test_home_descriptor_failure_stays_reachable(self):
        self.descriptor_failure('home')

    def test_tmp_descriptor_failure_stays_reachable(self):
        self.descriptor_failure('tmp')

    def test_template_descriptor_failure_stays_reachable(self):
        self.descriptor_failure('git-template')

    def test_existing_child_is_never_owned_or_removed(self):
        existing = self.account.root.path / 'home'
        existing.mkdir(mode=0o700)
        sentinel = existing / 'keep.txt'
        sentinel.write_bytes(b'caller-owned child')
        identity = existing.stat()
        observed = []
        real_mkdir = os.mkdir
        def observe_existing_mkdir(path, *args, **kwargs):
            raw = os.fsdecode(path)
            if (Path(raw) == existing or
                    (raw == 'home' and kwargs.get('dir_fd') == self.account.root.descriptor)):
                preparation = self.account.preparation
                root = preparation.root
                fields = None if root is None else (
                    root.path, root.created, root.descriptor,
                    root.device, root.inode, root.uid, root.mode)
                opened = None if root is None or root.descriptor is None else os.fstat(root.descriptor)
                observed.append((preparation, root, fields, opened))
            return real_mkdir(path, *args, **kwargs)
        with patch.object(os, 'mkdir', side_effect=observe_existing_mkdir):
            self.refused()
        self.assertEqual(len(observed), 1)
        before_preparation, before_root, fields, before_opened = observed[0]
        preparation = self.account.preparation
        self.assertIs(preparation, before_preparation)
        root = preparation.root
        self.assertIs(root, before_root)
        self.assertIsNotNone(root)
        self.assertEqual((root.path, root.created, root.descriptor,
                          root.device, root.inode, root.uid, root.mode), fields)
        self.assertIsNotNone(before_opened)
        self.assertEqual((before_opened.st_dev, before_opened.st_ino,
                          before_opened.st_uid, before_opened.st_mode),
                         (root.device, root.inode, root.uid, root.mode))
        self.assertIs(root.created, True)
        self.assertIsNotNone(root.descriptor)
        self.assertEqual(tuple(self.reachable_children()), (self.account.root.path / 'original-r',))
        opened = os.fstat(root.descriptor)
        self.assertEqual((opened.st_dev, opened.st_ino, opened.st_uid, opened.st_mode),
                         (root.device, root.inode, root.uid, root.mode))
        self.assertIsNotNone(preparation.home)
        self.assertIs(preparation.home.created, False)
        self.assertIsNone(preparation.home.descriptor)
        self.assertEqual((preparation.home.device, preparation.home.inode,
                          preparation.home.uid, preparation.home.mode), (None, None, None, None))
        self.assertIsNone(preparation.tmp)
        self.assertIsNone(preparation.template)
        self.assertNotIn(existing, self.reachable_children())
        self.assertEqual(sentinel.read_bytes(), b'caller-owned child')
        self.assertEqual((existing.stat().st_dev, existing.stat().st_ino),
                         (identity.st_dev, identity.st_ino))
        self.assertFalse(self.api_calls)
        self.assertFalse(self.git_calls)

    def test_stopped_attempt_does_not_replace_cleanup_ownership(self):
        self.interrupt_fetch = True
        self.refused()
        self.assertEqual(len(self.fetch_alarm), 1)
        self.assertTrue(self.fetch_alarm[0][1][0].expired)
        self.assertFalse(self.fetch_alarm_returned)
        preparation = self.account.preparation
        children = tuple(self.reachable_children())
        names = ('root', 'home', 'tmp', 'template')
        slots = tuple(getattr(preparation, name) for name in names)
        fields = tuple((child.path, child.created, child.descriptor,
                        child.device, child.inode, child.uid, child.mode) for child in slots)
        for child in slots:
            self.assertIs(child.created, True)
            self.assertIsNotNone(child.descriptor)
        frontier = (len(self.api_calls), len(self.git_calls))
        self.refused()
        self.assertIs(self.account.preparation, preparation)
        self.assertEqual(tuple(self.reachable_children()), children)
        for name, child, before in zip(names, slots, fields):
            self.assertIs(getattr(preparation, name), child)
            self.assertEqual((child.path, child.created, child.descriptor,
                              child.device, child.inode, child.uid, child.mode), before)
            opened = os.fstat(child.descriptor)
            self.assertEqual((opened.st_dev, opened.st_ino, opened.st_uid, opened.st_mode),
                             (child.device, child.inode, child.uid, child.mode))
        self.assertEqual((len(self.api_calls), len(self.git_calls)), frontier)



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
def _preparation_exception_observer(results):
    previous = sys.gettrace()
    if previous is not None:
        raise RuntimeError('diagnostic requires no preexisting tracer')
    code_type = type(candidate._prepare_original_r.__code__)
    names = ('_prepare_original_r', 'clock', 'visit', 'charge', 'sensitive', 'retain',
             'children_check', 'metadata', 'commit_metadata', 'git', 'preexec',
             'observe', 'identity', 'group_empty', 'drain', 'group_signal', 'config',
             'inventory', 'walk', 'read_file', '_original_r_require', '_original_r_registration')
    codes = set()
    def collect(code):
        if code.co_name in names:
            codes.add(code)
        for value in code.co_consts:
            if type(value) is code_type:
                collect(value)
    collect(candidate._prepare_original_r.__code__)
    collect(candidate._original_r_require.__code__)
    collect(candidate._original_r_registration.__wrapped__.__code__)
    events = []
    overflow = observer_failed = False
    def observe(frame, event, argument):
        nonlocal overflow, observer_failed
        try:
            if not any(frame.f_code is code for code in codes):
                return None
            frame.f_trace_lines = False
            frame.f_trace_opcodes = False
            if event != 'exception' or observer_failed:
                return observe
            error = argument[1]
            if type(error) is StopIteration:
                return observe
            if len(events) == 8:
                overflow = True
                return observe
            local = frame.f_locals
            account = local.get('account')
            preparation = account.preparation if account is not None else None
            commands = preparation.commands if preparation is not None else ()
            last = commands[-1] if commands else None
            caller = frame.f_back
            value = {'function': frame.f_code.co_name, 'line': frame.f_lineno,
                     'caller_function': caller.f_code.co_name if caller is not None and any(caller.f_code is code for code in codes) else None,
                     'caller_line': caller.f_lineno if caller is not None and any(caller.f_code is code for code in codes) else None,
                     'class': 'PreparationRefusal' if type(error) is candidate._OriginalRPreparationError else _diagnostic_class(error),
                     'errno': _diagnostic_integer(error.errno) if isinstance(error, OSError) else None,
                     'command_count': _diagnostic_integer(len(commands)) if preparation is not None else None,
                     'last_reason': (last.reason if last is not None and last.reason in ('incomplete', 'deadline', 'complete') else None),
                     'last_pid': _diagnostic_integer(last.pid) if last is not None else None,
                     'last_status': _diagnostic_integer(last.wait_status) if last is not None else None,
                     'last_waitid': ([ _diagnostic_integer(v) for v in last.waitid ] if last is not None and type(last.waitid) is tuple and len(last.waitid) == 3 else None),
                     'last_cleanup': last.cleanup_complete is True if last is not None else None}
            events.append(value)
        except candidate.Deadline:
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
            if primary is None and not (results and not results[0].wasSuccessful()):
                raise
        try:
            raw = json.dumps({'preparation_exceptions': events, 'overflow': overflow,
                              'observer_failed': observer_failed}, separators=(',', ':'), sort_keys=True).encode()
            if len(raw) > 4096:
                raw = b'{"preparation_exceptions":[],"overflow":true}'
            sys.stdout.write(raw.decode() + '\n')
            sys.stdout.flush()
        except BaseException:
            if primary is None and not (results and not results[0].wasSuccessful()):
                raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--candidate', required=True, type=Path)
    parser.add_argument('--full', action='store_true')
    parser.add_argument('--diagnostic-positive', action='store_true')
    parser.add_argument('--fixture-root', type=Path)
    parser.add_argument('--r-metadata', type=Path)
    options = parser.parse_args()
    if not options.candidate.is_absolute():
        parser.error('--candidate must be absolute')
    if options.diagnostic_positive and not options.full:
        parser.error('--diagnostic-positive requires --full')
    sys.dont_write_bytecode = True
    candidate = load(options.candidate, 'original_r_candidate')
    if options.full:
        if not options.fixture_root or not options.r_metadata:
            parser.error('--full requires --fixture-root and --r-metadata')
        if not options.fixture_root.is_absolute() or not options.r_metadata.is_absolute():
            parser.error('fixture paths must be absolute')
        helper = options.candidate.parents[2] / 'scripts/late_cycle_admission.py'
        if hashlib.sha256(helper.read_bytes()).hexdigest() != '57d0149537c0d69078b4aa490510da434ede292e71de9d55abd2743f9ba78b64':
            parser.error('strict JSON owner source changed')
        load(helper, 'late_cycle_admission')
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RealGitSyntheticAPI if options.full else MissingNew)
    if options.diagnostic_positive:
        suite = unittest.TestSuite([RealGitSyntheticAPI('test_actual_objects_sources_and_minimal_history')])
        results = []
        with _preparation_exception_observer(results):
            result = unittest.TextTestRunner(verbosity=2).run(suite)
            results.append(result)
        raise SystemExit(not result.wasSuccessful())
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
