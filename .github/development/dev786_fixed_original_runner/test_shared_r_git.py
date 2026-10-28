"""Focused Synthetic controls. Execution belongs to root after independent review."""
import argparse
import ast
import hashlib
import os
from pathlib import Path
import signal
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

LIMIT = 8 * 1024 * 1024 - 65536
HELPER_HASH = '8b8a5ebc0ddcbfd545d868d34771abc1698fb87f44b30e7b1d3207e6459c340f'


class SharedGit(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture_module.RealGitSyntheticAPI('test_actual_objects_sources_and_minimal_history')
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.account = self.fixture.account
        self.account.metadata_bytes = 4096

    def prepare(self):
        prepared = candidate._prepare_original_r(self.account, self.fixture.api)
        self.assertTrue(self.account.preparation.complete)
        self.assertFalse(self.account.stopped)
        self.fixture.assert_process_observations()
        root = self.account.root.path
        tool = SimpleNamespace(python=root / 'synthetic/bin/python',
                               site_packages=root / 'synthetic/site-packages',
                               core_root=root / 'synthetic/core', modules_root=root / 'synthetic/modules',
                               uv=root / 'synthetic/bin/uv')
        return prepared, tool

    def test_live_then_index_only_drift(self):
        prepared, tool = self.prepare()
        preparation = self.account.preparation
        preparation.deadline_ns = time.monotonic_ns() - 1
        api_before = tuple(self.fixture.api_calls)
        first = len(self.fixture.launches)
        metadata_before = preparation.metadata_bytes
        with candidate.Timer(1200) as timer:
            owner_end = timer.end
            candidate._verify_original_r_live(self.account, prepared, tool, timer)
            self.assertEqual(timer.end, owner_end)
            self.assertIs(signal.getsignal(signal.SIGALRM).__self__, timer)
            self.assertGreater(len(self.fixture.launches), first)
            expected = {os.fsdecode(k): os.fsdecode(v)
                        for k, v in candidate._original_vectors(tool, prepared)[0].environment}
            self.assertEqual(set(expected), {'HOME', 'TMPDIR', 'PATH', 'LC_ALL', 'VIRTUAL_ENV',
                                             'SPECFACT_MODULES_REPO', 'SPECFACT_MODULES_ROOTS'})
            for _, argv, kwargs, observation in self.fixture.launches[first:]:
                self.assertEqual({os.fsdecode(k): os.fsdecode(v) for k, v in kwargs['env'].items()}, expected)
                self.assertIs(observation[0], timer)
                self.assertFalse(set(argv) & {'fetch', 'checkout', 'init'})
            relative = fixture_module.SOURCES[0][0]
            source_before = (prepared.root / relative).read_bytes()
            self.fixture.git(prepared.root, 'update-index', '--force-remove', '--', relative)
            self.assertEqual((prepared.root / relative).read_bytes(), source_before)
            with self.assertRaises(candidate._OriginalProofError):
                candidate._verify_original_r_live(self.account, prepared, tool, timer)
            self.assertEqual(timer.end, owner_end)
            self.assertEqual(self.account.preparation.commands[-1].argv[1:],
                             ('ls-files', '--stage', '-z'))
            self.assertTrue(self.account.preparation.commands[-1].cleanup_complete)
        self.assertEqual(tuple(self.fixture.api_calls), api_before)
        self.assertGreater(preparation.metadata_bytes, metadata_before)
        self.assertEqual(self.account.metadata_bytes, 4096)
        self.assertTrue(preparation.complete)
        self.assertTrue(self.account.stopped)

    def test_live_effective_home_config_refused(self):
        prepared, tool = self.prepare()
        (prepared.home / '.gitconfig').write_text('[alias]\n\tshared-test = status\n')
        first = len(self.fixture.launches)
        with candidate.Timer(1200) as timer:
            with self.assertRaises(candidate._OriginalProofError):
                candidate._verify_original_r_live(self.account, prepared, tool, timer)
        launches = self.fixture.launches[first:]
        self.assertTrue(any('config' in argv for _, argv, _, _ in launches))
        for _, _, kwargs, _ in launches:
            self.assertNotIn('GIT_CONFIG_NOSYSTEM', {os.fsdecode(k) for k in kwargs['env']})
        self.assertTrue(self.account.stopped)
        self.assertTrue(self.account.preparation.complete)

    def test_original_owner_alarm_during_live_reap(self):
        prepared, tool = self.prepare()
        first_pids = set(self.fixture.processes)
        original_wait = self.fixture.local_waitpid
        fired = []
        def alarm_once(pid, options):
            if pid in self.fixture.processes and pid not in first_pids and not fired:
                fired.append(pid)
                signal.raise_signal(signal.SIGALRM)
            return original_wait(pid, options)
        with candidate.Timer(1200) as timer:
            owner_end = timer.end
            with patch.object(os, 'waitpid', side_effect=alarm_once):
                with self.assertRaises(candidate._OriginalProofError):
                    candidate._verify_original_r_live(self.account, prepared, tool, timer)
            self.assertTrue(timer.expired)
            self.assertEqual(timer.end, owner_end)
        self.assertEqual(len(fired), 1)
        new_pids = set(self.fixture.processes) - first_pids
        self.assertEqual({pid for pid, _ in self.fixture.terminal_reaps} & new_pids, new_pids)
        for pid in new_pids:
            process = self.fixture.processes[pid][0]
            self.assertTrue(process.stdout.closed)
            self.assertTrue(process.stderr.closed)
        self.assertTrue(self.account.stopped)
        self.assertTrue(self.account.preparation.complete)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_live_cache_inventory_then_unmatched_directory(self):
        """Synthetic unit input uses actual cache bytes, never NativeTool or row evidence."""
        prepared, tool = self.prepare()
        self.assertTrue(callable(getattr(candidate, '_verify_original_r_live', None)),
                        'missing live-verifier integration; no cache semantic evidence')
        preparation = self.account.preparation
        index_argv = ('ls-files', '--stage', '-z')
        status_argv = ('status', '--porcelain=v1', '-z', '--untracked-files=all', '--ignored=matching')
        baseline_index = next(record.stdout for record in preparation.commands
                              if record.argv[1:] == index_argv)
        cache = prepared.root / '.pytest_cache' / 'synthetic-cache'
        self.assertFalse(cache.parent.exists())
        cache.parent.mkdir()
        cache.write_bytes(b'Synthetic generated cache unit input\n')
        actual = cache.read_bytes()
        inventory = candidate.encoded([('R', str(cache.relative_to(prepared.root)),
                                        len(actual), hashlib.sha256(actual).hexdigest())])
        self.assertLessEqual(preparation.metadata_bytes + self.account.metadata_bytes + len(inventory), LIMIT)
        self.account.live_metadata += (inventory,)
        self.account.metadata_bytes += len(inventory)
        retained_metadata = self.account.live_metadata
        metadata_before = self.account.metadata_bytes
        api_before = tuple(self.fixture.api_calls)
        first = len(preparation.commands)
        with candidate.Timer(1200) as timer:
            owner_end = timer.end
            candidate._verify_original_r_live(self.account, prepared, tool, timer)
            self.assertFalse(self.account.stopped)
            positive = preparation.commands[first:]
            status = [record for record in positive if record.argv[1:] == status_argv]
            self.assertEqual(len(status), 1)
            self.assertTrue(status[0].cleanup_complete)
            self.assertEqual(status[0].stdout, b'!! .pytest_cache/\0')
            self.assertEqual(status[0].stderr, b'')
            self.assertTrue(status[0].receipt)
            self.assertEqual(timer.end, owner_end)
            self.assertIs(signal.getsignal(signal.SIGALRM).__self__, timer)
            unmatched = prepared.root / '__pycache__' / 'synthetic-cache'
            self.assertFalse(unmatched.parent.exists())
            unmatched.parent.mkdir()
            unmatched.write_bytes(b'Synthetic unmatched cache unit input\n')
            self.assertEqual(self.account.live_metadata, retained_metadata)
            first = len(preparation.commands)
            with self.assertRaises(candidate._OriginalProofError):
                candidate._verify_original_r_live(self.account, prepared, tool, timer)
            negative = preparation.commands[first:]
            status = [record for record in negative if record.argv[1:] == status_argv]
            self.assertEqual(len(status), 1, 'unmatched-cache refusal must reach actual status')
            self.assertTrue(status[0].cleanup_complete)
            self.assertEqual(set(status[0].stdout.split(b'\0')),
                             {b'!! .pytest_cache/', b'!! __pycache__/', b''})
            self.assertEqual(status[0].stderr, b'')
            self.assertTrue(status[0].receipt)
            self.assertEqual(timer.end, owner_end)
        for commands in (positive, negative):
            staged = [record for record in commands if record.argv[1:] == index_argv]
            self.assertEqual(len(staged), 1)
            self.assertEqual(staged[0].stdout, baseline_index)
            self.assertTrue(staged[0].cleanup_complete)
            for argv in (('diff', '--cached', '--exit-code', '--no-ext-diff', '--no-textconv',
                          candidate._ORIGINAL_R, '--'),
                         ('diff-files', '--exit-code', '--no-ext-diff', '--no-textconv', '--')):
                records = [record for record in commands if record.argv[1:] == argv]
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0].stdout, b'')
                self.assertEqual(records[0].stderr, b'')
                self.assertTrue(records[0].cleanup_complete)
                self.assertIsNotNone(records[0].wait_status)
                self.assertTrue(os.WIFEXITED(records[0].wait_status))
                self.assertEqual(os.WEXITSTATUS(records[0].wait_status), 0)
        self.assertEqual(tuple(self.fixture.api_calls), api_before)
        self.assertEqual(self.account.live_metadata, retained_metadata)
        self.assertEqual(self.account.metadata_bytes, metadata_before)
        self.assertTrue(preparation.complete)
        self.assertTrue(self.account.stopped)

    def retention(self, caller, over):
        observed = {}
        previous = sys.gettrace()
        self.assertIsNone(previous)
        def observe(frame, event, arg):
            if (event == 'call' and frame.f_code.co_name == 'retain'
                    and Path(frame.f_code.co_filename).resolve() == options.candidate.resolve()):
                parent = frame.f_back
                if observed:
                    raise RuntimeError('Synthetic retention probe complete')
                if parent.f_code.co_name == caller:
                    raw = frame.f_locals['raw']
                    preparation = self.account.preparation
                    self.account.metadata_bytes = LIMIT - preparation.metadata_bytes - len(raw) + over
                    observed.update(raw=raw, before=preparation.metadata_bytes,
                                    subtotal=self.account.metadata_bytes, parent=parent)
                    if caller == 'drain':
                        observed['chunks'] = parent.f_locals['chunks'][parent.f_locals['index']]
            return observe
        try:
            sys.settrace(observe)
            with self.assertRaises(candidate._OriginalRPreparationError):
                candidate._prepare_original_r(self.account, self.fixture.api)
        finally:
            sys.settrace(previous)
        self.assertTrue(observed, 'actual retention seam was not reached')
        parent = observed.pop('parent')
        if caller == 'metadata':
            attached = getattr(self.account.preparation, parent.f_locals['slot'])
        elif caller == 'git':
            attached = parent.f_locals['record'].receipt
        else:
            attached = b''.join(observed['chunks'])
        self.assertEqual(attached, b'' if caller != 'metadata' and over else
                         None if over else observed['raw'])
        self.assertEqual(self.account.preparation.metadata_bytes,
                         observed['before'] + (0 if over else len(observed['raw'])))
        self.assertEqual(self.account.metadata_bytes, observed['subtotal'])
        self.assertGreater(self.account.metadata_bytes, 0)
        self.assertTrue(self.account.stopped)

    def test_api_exact(self):
        self.retention('metadata', 0)

    def test_api_one_over(self):
        self.retention('metadata', 1)

    def test_chunk_exact(self):
        self.retention('drain', 0)

    def test_chunk_one_over(self):
        self.retention('drain', 1)

    def test_receipt_exact(self):
        self.retention('git', 0)

    def test_receipt_one_over(self):
        self.retention('git', 1)

    def final_segment(self, over):
        source = options.candidate.read_text()
        tree = ast.parse(source)
        owner = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_original15')
        body = next(n for n in owner.body if isinstance(n, ast.Try)).body
        start = next(i for i, n in enumerate(body)
                     if any(isinstance(c, ast.Constant) and c.value == 'binary_identities' for c in ast.walk(n)))
        end = next(i for i, n in enumerate(body) if isinstance(n, ast.Assign)
                   and any(isinstance(t, ast.Attribute) and t.attr == 'live_complete' for t in n.targets))
        self.assertLess(start, end)
        self.assertLessEqual(end - start, 8)
        segment = ast.Module(body=body[start:end], type_ignores=[])
        preparation = candidate._OriginalRPreparation(time.monotonic_ns(), self.account.deadline_ns)
        preparation.metadata_bytes = 4096
        self.account.preparation = preparation
        self.account.tool_identity = ()
        self.account.live_metadata = (b'existing cache record',)
        tool = SimpleNamespace(inventory=(('GitPython', '3.2.1'),))
        observed = []
        original_encoded = candidate.encoded
        def encode(value):
            raw = original_encoded(value)
            self.assertFalse(observed)
            self.account.metadata_bytes = LIMIT - preparation.metadata_bytes - len(raw) + over
            observed.append((raw, self.account.metadata_bytes))
            return raw
        namespace = dict(vars(candidate), account=self.account, tool=tool, encoded=encode)
        before = self.account.live_metadata
        error = None
        try:
            exec(compile(segment, str(options.candidate), 'exec'), namespace)
        except candidate._OriginalProofError as caught:
            error = caught
        self.assertEqual(len(observed), 1)
        raw, subtotal = observed[0]
        if over:
            self.assertIsNotNone(error)
            self.assertEqual(self.account.live_metadata, before)
            self.assertEqual(self.account.metadata_bytes, subtotal)
        else:
            self.assertIsNone(error)
            self.assertEqual(self.account.live_metadata, before + (raw,))
            self.assertEqual(self.account.metadata_bytes, subtotal + len(raw))
        self.assertEqual(preparation.metadata_bytes, 4096)
        self.assertFalse(self.account.live_complete)

    def test_final_segment_exact(self):
        self.final_segment(0)

    def test_final_segment_one_over(self):
        self.final_segment(1)


class SourceAdmission(unittest.TestCase):
    def test_pipe_footer_and_receipt_are_separate(self):
        tree = ast.parse(options.candidate.read_text())
        drains = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == 'drain']
        capacities = [node.value for owner in drains for node in ast.walk(owner)
                      if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'capacity'
                                                               for t in node.targets)]
        self.assertEqual(len(capacities), 1)
        expression = capacities[0]
        allowed = (ast.Expression, ast.Call, ast.Name, ast.Load, ast.BinOp, ast.Sub, ast.Add,
                   ast.Mult, ast.Constant, ast.Attribute, ast.Subscript)
        self.assertTrue(all(isinstance(n, allowed) for n in ast.walk(expression)))
        self.assertTrue(all(isinstance(n.func, ast.Name) and n.func.id == 'min'
                            for n in ast.walk(expression) if isinstance(n, ast.Call)))
        namespace = {'min': min, 'MIB': 1024 * 1024, 'sizes': [0, 0], 'index': 0,
                     'preparation': SimpleNamespace(metadata_bytes=1024),
                     'account': SimpleNamespace(metadata_bytes=2048)}
        capacity = eval(compile(ast.Expression(expression), '<actual drain capacity>', 'eval'),
                        {'__builtins__': {}}, namespace)
        self.assertEqual(capacity, min(4 * 1024 * 1024, LIMIT - 65536 - 1024 - 2048))
        namespace['account'].metadata_bytes = LIMIT - 65536 - 1024 - 17
        capacity = eval(compile(ast.Expression(expression), '<actual drain capacity>', 'eval'),
                        {'__builtins__': {}}, namespace)
        self.assertEqual(capacity, 17)



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--candidate', required=True, type=Path)
    parser.add_argument('--preparation-tests', type=Path)
    parser.add_argument('--fixture-root', type=Path)
    parser.add_argument('--r-metadata', type=Path)
    parser.add_argument('--case', action='append', required=True)
    options = parser.parse_args()
    if not options.candidate.is_absolute():
        parser.error('candidate path must be absolute')
    sys.dont_write_bytecode = True
    if any(name.startswith('SharedGit.') for name in options.case):
        if not all(p is not None and p.is_absolute() for p in
                   (options.preparation_tests, options.fixture_root, options.r_metadata)):
            parser.error('runtime controls require absolute fixture paths')
        if hashlib.sha256(options.preparation_tests.read_bytes()).hexdigest() != HELPER_HASH:
            parser.error('accepted preparation fixture source changed')
        import importlib.util
        spec = importlib.util.spec_from_file_location('accepted_preparation_fixture', options.preparation_tests)
        fixture_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture_module)
        candidate = fixture_module.load(options.candidate, 'shared_r_candidate')
        helper = options.candidate.parents[2] / 'scripts/late_cycle_admission.py'
        if hashlib.sha256(helper.read_bytes()).hexdigest() != '57d0149537c0d69078b4aa490510da434ede292e71de9d55abd2743f9ba78b64':
            parser.error('strict JSON owner source changed')
        fixture_module.load(helper, 'late_cycle_admission')
        fixture_module.candidate = candidate
        fixture_module.options = options
    suite = unittest.TestSuite()
    for name in options.case:
        owner, method = name.split('.')
        if owner not in ('SharedGit', 'SourceAdmission') or not method.startswith('test_'):
            parser.error('unknown fixed test selection')
        suite.addTest(globals()[owner](method))
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
