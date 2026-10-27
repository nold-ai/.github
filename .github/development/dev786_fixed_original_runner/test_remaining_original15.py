from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from xml.etree import ElementTree as ET


TARGET = None
PROFILE = None
FIXTURES = None


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def put(path, data):
    with path.open('wb') as stream:
        stream.write(data)
    path.chmod(0o600)


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


@contextmanager
def owned_account():
    with tempfile.TemporaryDirectory(prefix='synthetic-fixed-proof-') as name:
        parent = Path(name).resolve()
        root = parent / 'new-out'
        root.mkdir(mode=0o700)
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        value = os.fstat(descriptor)
        owner = TARGET._OwnedRoot(root, descriptor, value.st_dev, value.st_ino,
                                  value.st_uid, value.st_mode)
        account = TARGET._AttemptAccount(owner, time.monotonic_ns() + 60_000_000_000, ())
        account.original_output = parent / 'old-output'
        account.original_output.mkdir(mode=0o700)
        account.export_path = parent / 'new-export'
        try:
            yield account
        finally:
            preparation = getattr(account, 'preparation', None)
            descriptors = [descriptor]
            if preparation is not None:
                descriptors.extend(child.descriptor for child in (
                    preparation.root, preparation.home, preparation.tmp, preparation.template)
                    if child is not None and child.descriptor is not None)
            for item in descriptors:
                try:
                    os.close(item)
                except OSError:
                    pass


def synthetic_products(account):
    for name in ('plan.json', 'planning-report.json', 'planning-summary.md', 'local-red-summary.md'):
        put(account.root.path / name, (FIXTURES / name).read_bytes())
    xml = (FIXTURES / 'requirements-proof-network.xml').read_bytes()
    old = b'name="specfact.python" value="3.12.13"'
    new = b'name="specfact.python" value="3.12.15"'
    if xml.count(old) != 15:
        raise AssertionError('Historical semantic fixture has another Python property shape')
    xml = xml.replace(old, new)
    put(account.root.path / 'requirements-proof.xml', xml)
    unbound = json.loads((FIXTURES / 'local-red-unbound-report.json').read_bytes())
    bound = json.loads((FIXTURES / 'local-red-report.json').read_bytes())
    unbound['execution_proof']['junit_digest'] = 'sha256:' + digest(xml)
    bound['execution_proof']['junit_digest'] = 'sha256:' + digest(xml)
    bound['execution_proof']['toolchain_identity']['python'] = '3.12.15'
    put(account.root.path / 'local-red-report.json', wire(unbound))
    return unbound, bound


def stage(account, name):
    TARGET._check_products(account, getattr(TARGET._OriginalStage, name))


def through_executor(account):
    stage(account, 'PLANNER')
    stage(account, 'EXECUTOR')


def refuse(test, account, operation):
    with test.assertRaises(TARGET._OriginalProofError):
        operation()
    test.assertTrue(account.stopped)
    test.assertFalse(account.live_complete)


def child(account, slot, relative):
    path = account.root.path / relative
    path.mkdir(mode=0o700)
    value = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    record = TARGET._OriginalRChild(path=path, created=True, descriptor=descriptor,
        device=value.st_dev, inode=value.st_ino, uid=value.st_uid, mode=value.st_mode)
    setattr(account.preparation, slot, record)
    put(path / 'tiny.txt', b'Synthetic scratch bytes\n')
    return record


def registered_children(account):
    now = time.monotonic_ns()
    account.preparation = TARGET._OriginalRPreparation(now, now + 30_000_000_000)
    return tuple(child(account, slot, relative) for slot, relative in (
        ('root', 'original-r'), ('home', 'home'), ('tmp', 'tmp'), ('template', 'git-template')))


def failed_original(error=None):
    if error is None:
        return TARGET._OwnerOutcome(TARGET._OwnerState.RETURNED, False, None)
    return TARGET._OwnerOutcome(TARGET._OwnerState.RAISED, None, error)


def not_published():
    return TARGET._OwnerOutcome(TARGET._OwnerState.NOT_STARTED, None, None)


def published(value):
    return TARGET._OwnerOutcome(TARGET._OwnerState.RETURNED, value, None)


def actual_failed_old_export(account):
    source = account.root.path / 'tiny-old-input'
    put(source, b'Synthetic original Evidence fixture bytes\n')
    evidence = TARGET.Evidence(account.original_output / 'materialization')
    fact, raw = evidence.read(source, retain=True)
    if raw != source.read_bytes() or not fact['complete']:
        raise AssertionError('Real old Evidence did not read complete tiny fixture')
    evidence.incomplete('Synthetic original failure, no native materialization')
    evidence.finish({'outcome': 'EVIDENCE_INCOMPLETE', 'yielded': False})
    if not TARGET.publish_safe(account.original_output):
        raise AssertionError('Real publisher did not export tiny safe failed evidence')
    export = account.original_output / 'export'
    return export, json.loads((export / 'export.json').read_bytes())


class MissingNew(unittest.TestCase):
    def test_exact_remaining_original15_body_is_missing(self):
        try:
            TARGET._original15(None, None, None, None)
        except BaseException as error:
            self.assertIs(type(error), TARGET._OriginalProofNotImplemented)
            self.assertEqual(error.args, ('NEW fixed original15 proof and join is not implemented',))
            tb = error.__traceback__
            while tb.tb_next is not None:
                tb = tb.tb_next
            self.assertIs(tb.tb_frame.f_code, TARGET._original15.__code__)
            self.fail('Exact remaining original15 target is genuinely missing NEW')
        self.fail('Missing-NEW target did not raise its named missing body')


class ProductFacts(unittest.TestCase):
    def test_historical_family_is_complete_and_internally_matched(self):
        for name, fact in PROFILE['fixture_files'].items():
            raw = (FIXTURES / name).read_bytes()
            self.assertEqual((len(raw), digest(raw)), (fact['bytes'], fact['sha256']))
        plan = json.loads((FIXTURES / 'plan.json').read_bytes())
        unbound = json.loads((FIXTURES / 'local-red-unbound-report.json').read_bytes())
        bound = json.loads((FIXTURES / 'local-red-report.json').read_bytes())
        xml = (FIXTURES / 'requirements-proof-network.xml').read_bytes()
        self.assertEqual(unbound['execution_proof']['junit_digest'], 'sha256:' + digest(xml))
        self.assertEqual(bound['execution_proof']['junit_digest'], 'sha256:' + digest(xml))
        self.assertEqual(unbound['plan'], plan['plan'])
        self.assertEqual(unbound['execution_plan'], plan['plan'])
        stripped = copy.deepcopy(bound)
        for key in ('source_tree', 'merge_base', 'test_file_digests', 'toolchain_identity'):
            stripped['execution_proof'].pop(key)
        self.assertEqual(stripped, unbound)
        self.assertEqual(bound['execution_proof']['toolchain_identity'], PROFILE['historical_toolchain'])

    def test_real_owned_reads_and_all_product_checks_have_no_live_credit(self):
        with owned_account() as account:
            _, bound = synthetic_products(account)
            original_read = account.read_bytes
            through_executor(account)
            stage(account, 'RECONCILER')
            frozen = account.products.unbound_report
            self.assertEqual(frozen.data, (account.root.path / 'local-red-unbound-report.json').read_bytes())
            put(account.root.path / 'local-red-report.json', wire(bound))
            stage(account, 'BINDER')
            self.assertEqual(account.products.plan.sha256, PROFILE['fixture_files']['plan.json']['sha256'])
            facts = account.products.junit_facts
            self.assertEqual((facts.failures, facts.errors, facts.passes, facts.skips), (15, 0, 0, 0))
            self.assertEqual(tuple(facts.selectors), tuple(c['selector'] for c in PROFILE['cases15']))
            self.assertGreater(account.read_bytes, original_read)
            self.assertGreater(account.spent_bytes, account.read_bytes)
            self.assertGreater(account.retained_bytes, 0)
            self.assertEqual(frozen.data, account.products.unbound_report.data)
            self.assertNotEqual(frozen.sha256, account.products.bound_report.sha256)
            self.assertFalse(account.live_complete)
            self.assertIsNone(account.final_packet)

    def test_reordered_repeated_or_missing_product_stages_refuse(self):
        for route in (('EXECUTOR',), ('PLANNER', 'PLANNER'), ('PLANNER', 'BINDER')):
            with self.subTest(route=route), owned_account() as account:
                synthetic_products(account)
                for previous in route[:-1]:
                    stage(account, previous)
                refuse(self, account, lambda: stage(account, route[-1]))

    def test_plan_or_planning_report_byte_changes_refuse(self):
        for name in ('plan.json', 'planning-report.json'):
            with self.subTest(name=name), owned_account() as account:
                synthetic_products(account)
                raw = (account.root.path / name).read_bytes()
                put(account.root.path / name, raw + b' ')
                refuse(self, account, lambda: stage(account, 'PLANNER'))

    def test_symlink_product_is_not_opened(self):
        with owned_account() as account:
            synthetic_products(account)
            path = account.root.path / 'planning-report.json'
            path.unlink()
            outside = account.root.path.parent / 'outside-report'
            put(outside, b'Outside must not be read')
            path.symlink_to(outside)
            real_open, opened = os.open, []
            def observe(name, *args, **kwargs):
                opened.append(os.fspath(name))
                return real_open(name, *args, **kwargs)
            with patch.object(TARGET.os, 'open', observe):
                refuse(self, account, lambda: stage(account, 'PLANNER'))
            self.assertNotIn('planning-report.json', opened)
            self.assertNotIn(str(outside), opened)

    def test_xml_short_read_is_incomplete_and_real_fd_closes(self):
        with owned_account() as account:
            synthetic_products(account)
            stage(account, 'PLANNER')
            real_read, real_close = os.read, os.close
            closed = []
            def short(descriptor, size):
                return real_read(descriptor, max(0, size - 100))
            def close(descriptor):
                closed.append(descriptor)
                return real_close(descriptor)
            before = account.read_bytes
            with patch.object(TARGET.os, 'read', short), patch.object(TARGET.os, 'close', close):
                refuse(self, account, lambda: stage(account, 'EXECUTOR'))
            self.assertGreater(account.read_bytes, before)
            self.assertTrue(closed)
            for descriptor in closed:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def test_xml_limit_is_checked_before_body_read(self):
        with owned_account() as account:
            synthetic_products(account)
            stage(account, 'PLANNER')
            path = account.root.path / 'requirements-proof.xml'
            with path.open('wb') as stream:
                stream.truncate(10 * 1048576 + 1)
            with patch.object(TARGET.os, 'read', side_effect=AssertionError('Body read before size admission')):
                refuse(self, account, lambda: stage(account, 'EXECUTOR'))

    def test_report_field_digest_plan_and_sorted_selector_mutations_refuse(self):
        mutations = (
            lambda report: report.update(mapping_digest='sha256:' + '0' * 64),
            lambda report: report.update(plan_digest='sha256:' + '0' * 64),
            lambda report: report['plan']['cases'][0].update(intent='Changed Synthetic intent'),
            lambda report: report['execution_plan']['cases'].pop(),
            lambda report: report['execution_proof'].update(junit_digest='sha256:' + '0' * 64),
            lambda report: report['execution_proof'].update(source_ref='0' * 40),
            lambda report: report['execution_proof'].update(run_stage='green'),
            lambda report: report['execution_proof']['selectors'].reverse(),
            lambda report: report['execution_proof'].update(source_tree=PROFILE['policy_tree']),
            lambda report: report.update(verdict='pass'),
            lambda report: report.update(extra_unbound_field='Synthetic unsupported field'),
        )
        for index, change in enumerate(mutations):
            with self.subTest(index=index), owned_account() as account:
                unbound, _ = synthetic_products(account)
                through_executor(account)
                change(unbound)
                put(account.root.path / 'local-red-report.json', wire(unbound))
                refuse(self, account, lambda: stage(account, 'RECONCILER'))

    def test_strict_json_duplicate_nonfinite_trailing_and_nonobject_refuse(self):
        for raw in (b'{"plan":{},"plan":{}}', b'{"x":NaN}', b'{}{}', b'[]', b'\xff', b'{'):
            with self.subTest(raw=raw), owned_account() as account:
                synthetic_products(account)
                through_executor(account)
                put(account.root.path / 'local-red-report.json', raw)
                refuse(self, account, lambda: stage(account, 'RECONCILER'))

    def test_unbound_copy_must_be_exclusive_and_stays_immutable(self):
        with owned_account() as account:
            synthetic_products(account)
            through_executor(account)
            put(account.root.path / 'local-red-unbound-report.json', b'Prior attempt bytes')
            refuse(self, account, lambda: stage(account, 'RECONCILER'))
            self.assertEqual((account.root.path / 'local-red-unbound-report.json').read_bytes(), b'Prior attempt bytes')

    def test_binder_all_four_bindings_and_whole_object_are_checked(self):
        mutations = (
            lambda report: report['execution_proof'].pop('source_tree'),
            lambda report: report['execution_proof'].update(source_tree='0' * 40),
            lambda report: report['execution_proof'].update(merge_base='0' * 40),
            lambda report: report['execution_proof']['test_file_digests'].pop(next(iter(report['execution_proof']['test_file_digests']))),
            lambda report: report['execution_proof']['test_file_digests'].update({'extra.py': 'sha256:' + '0' * 64}),
            lambda report: report['execution_proof']['toolchain_identity'].update(python='3.12.13'),
            lambda report: report['execution_proof'].update(extra_binding=True),
            lambda report: report['plan']['cases'][0].update(intent='Changed after binder'),
            lambda report: report.update(extra_top_level=True),
        )
        for index, change in enumerate(mutations):
            with self.subTest(index=index), owned_account() as account:
                _, bound = synthetic_products(account)
                through_executor(account)
                stage(account, 'RECONCILER')
                predecessor = account.products.unbound_report.data
                change(bound)
                put(account.root.path / 'local-red-report.json', wire(bound))
                refuse(self, account, lambda: stage(account, 'BINDER'))
                self.assertEqual(account.products.unbound_report.data, predecessor)

    def test_real_second_read_and_retained_copy_are_charged(self):
        with owned_account() as account:
            synthetic_products(account)
            first = TARGET._read_owned(account, TARGET._SourceRole.PLAN)
            reads, retained = account.read_bytes, account.retained_bytes
            second = TARGET._read_owned(account, TARGET._SourceRole.PLAN)
            self.assertEqual(first.data, second.data)
            self.assertEqual(account.read_bytes - reads, len(first.data))
            self.assertEqual(account.retained_bytes - retained, len(first.data))


class JunitSemantics(unittest.TestCase):
    def altered_xml(self, change):
        with owned_account() as account:
            synthetic_products(account)
            stage(account, 'PLANNER')
            path = account.root.path / 'requirements-proof.xml'
            root = ET.fromstring(path.read_bytes())
            change(root)
            put(path, ET.tostring(root, encoding='utf-8'))
            refuse(self, account, lambda: stage(account, 'EXECUTOR'))

    def test_all_fifteen_actual_historical_assertion_shapes_pass_only_as_parser_facts(self):
        with owned_account() as account:
            synthetic_products(account)
            through_executor(account)
            self.assertEqual(account.products.junit_facts.failures, 15)
            self.assertIn(b'Full output truncated', account.products.junit.data)
            self.assertFalse(account.live_complete)

    def test_old_installation_failures_are_not_intended_red(self):
        with owned_account() as account:
            synthetic_products(account)
            stage(account, 'PLANNER')
            raw = (FIXTURES / 'requirements-proof.xml').read_bytes()
            raw = raw.replace(b'name="specfact.python" value="3.12.13"',
                              b'name="specfact.python" value="3.12.15"')
            put(account.root.path / 'requirements-proof.xml', raw)
            refuse(self, account, lambda: stage(account, 'EXECUTOR'))

    def test_each_case_wrong_final_assertion_location_refuses(self):
        for index in range(15):
            with self.subTest(index=index):
                def change(root):
                    failure = list(root.iter('testcase'))[index].find('failure')
                    original = PROFILE['cases15'][index]
                    line = original['file'] + ':' + str(original['line']) + ': AssertionError'
                    failure.text = failure.text.replace(line, original['file'] + ':1: AssertionError')
                self.altered_xml(change)

    def test_each_case_wrong_intended_assertion_content_refuses(self):
        for index in range(15):
            with self.subTest(index=index):
                def change(root):
                    failure = list(root.iter('testcase'))[index].find('failure')
                    marker = PROFILE['cases15'][index]['markers'][0]
                    self.assertIn(marker, failure.text)
                    failure.text = failure.text.replace(marker, 'assert Synthetic_wrong_earlier_helper')
                self.altered_xml(change)

    def test_duplicate_missing_reordered_and_unknown_selectors_refuse(self):
        def duplicate(root):
            suite = root.find('testsuite')
            suite.append(copy.deepcopy(suite.find('testcase')))
        def missing(root):
            suite = root.find('testsuite')
            suite.remove(suite.find('testcase'))
        def reordered(root):
            suite = root.find('testsuite')
            cases = suite.findall('testcase')
            suite.remove(cases[0])
            suite.append(cases[0])
        def unknown(root):
            next(root.iter('property')).set('value', 'tests/unknown.py::test_unknown')
        for change in (duplicate, missing, reordered, unknown):
            with self.subTest(change=change.__name__):
                self.altered_xml(change)

    def test_property_runner_python_pytest_and_duplicates_refuse(self):
        for key, value in (('specfact.runner', 'other'), ('specfact.python', '3.12.13'),
                           ('specfact.pytest', '0'), ('specfact.selector', '')):
            with self.subTest(key=key):
                def change(root):
                    next(p for p in root.iter('property') if p.get('name') == key).set('value', value)
                self.altered_xml(change)
        def duplicate(root):
            properties = next(root.iter('properties'))
            properties.append(copy.deepcopy(properties[0]))
        self.altered_xml(duplicate)

    def test_pass_error_skip_second_failure_and_false_totals_refuse(self):
        def outcome(root, kind):
            case = next(root.iter('testcase'))
            case.remove(case.find('failure'))
            if kind != 'pass':
                ET.SubElement(case, kind).text = 'Synthetic setup failure'
        for kind in ('pass', 'error', 'skipped'):
            with self.subTest(kind=kind):
                self.altered_xml(lambda root: outcome(root, kind))
        self.altered_xml(lambda root: next(root.iter('testcase')).append(ET.Element('failure')))
        for key in ('tests', 'failures', 'errors', 'skipped'):
            with self.subTest(key=key):
                self.altered_xml(lambda root: root.find('testsuite').set(key, '99'))

    def test_xml_declarations_entities_dtd_malformed_and_incomplete_refuse(self):
        additions = (b'<?xml version="1.0"?>', b'<!DOCTYPE testsuites>',
                     b'<!DOCTYPE testsuites [<!ENTITY x "Synthetic">]>',
                     b'<!DOCTYPE testsuites SYSTEM "file:///no-such-synthetic-file">')
        for prefix in additions:
            with self.subTest(prefix=prefix), owned_account() as account:
                synthetic_products(account)
                stage(account, 'PLANNER')
                path = account.root.path / 'requirements-proof.xml'
                put(path, prefix + path.read_bytes())
                refuse(self, account, lambda: stage(account, 'EXECUTOR'))
        for raw in (b'<testsuites>', b'<testsuites><testcase></testsuites>', b'\xff'):
            with self.subTest(raw=raw), owned_account() as account:
                synthetic_products(account)
                stage(account, 'PLANNER')
                put(account.root.path / 'requirements-proof.xml', raw)
                refuse(self, account, lambda: stage(account, 'EXECUTOR'))

    def test_inherited_secret_withholds_entire_member(self):
        with owned_account() as account:
            synthetic_products(account)
            stage(account, 'PLANNER')
            account.secrets = (b'Synthetic-credential-marker-15',)
            path = account.root.path / 'requirements-proof.xml'
            put(path, path.read_bytes().replace(b'</testsuites>', b'<!--Synthetic-credential-marker-15--></testsuites>'))
            refuse(self, account, lambda: stage(account, 'EXECUTOR'))
            self.assertIsNone(account.products.junit)


class SyntheticPublicBoundary(unittest.TestCase):
    def setUp(self):
        self.expiry = datetime(2026, 11, 4, 23, 0, tzinfo=timezone.utc)
        self.clock = [self.expiry - timedelta(seconds=1)]
        self.clock_reads = []
        clock, reads = self.clock, self.clock_reads
        class SyntheticDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                value = clock[0].astimezone(tz) if tz is not None else clock[0].replace(tzinfo=None)
                reads.append((tz, value))
                return value
        clock_patch = patch.object(TARGET, 'datetime', SyntheticDateTime)
        clock_patch.start()
        self.addCleanup(clock_patch.stop)

    def assert_aware_clock(self):
        self.assertTrue(self.clock_reads)
        for requested_timezone, value in self.clock_reads:
            self.assertIsNotNone(requested_timezone)
            self.assertIsNotNone(value.utcoffset())
            self.assertEqual(value.utcoffset(), timedelta(0))
        berlin_expiry = datetime(2026, 11, 5, 0, 0,
                                 tzinfo=timezone(timedelta(hours=1), 'CET'))
        self.assertEqual(self.expiry, berlin_expiry)

    def values(self):
        policy, core = 'nold-ai/.github', 'nold-ai/specfact-cli'
        def repository(name, number):
            return {'id': number, 'full_name': name, 'owner': {'login': 'nold-ai', 'id': 225190663}}
        def ref(branch, sha):
            return {'ref': 'refs/heads/' + branch, 'object': {'type': 'commit', 'sha': sha}}
        return [
            ('/repos/' + policy, repository(policy, 1110267669)),
            ('/repos/' + core, repository(core, 1085706003)),
            ('/repos/' + policy + '/git/ref/heads/main', ref('main', PROFILE['policy_main'])),
            ('/repos/' + policy + '/git/commits/' + PROFILE['policy_main'],
             {'sha': PROFILE['policy_main'], 'tree': {'sha': PROFILE['policy_tree']},
              'parents': [{'sha': sha} for sha in PROFILE['policy_parents']],
              'verification': {'verified': True, 'reason': 'valid', 'signature': 'Synthetic', 'payload': 'Synthetic'}}),
            ('/repos/' + core + '/git/ref/heads/main', ref('main', PROFILE['core_main'])),
            ('/repos/' + core + '/git/ref/heads/dev', ref('dev', PROFILE['core_dev'])),
        ]

    def api(self, values, calls):
        class GitHub:
            def get(self, path):
                ordinal = len(calls)
                calls.append(path)
                return wire(values[ordinal][1]) if ordinal < len(values) else b'{}'
        return SimpleNamespace(GitHub=GitHub)

    def test_current_merge_and_parent_order_from_synthetic_api_are_exact(self):
        with owned_account() as account:
            values, calls = self.values(), []
            facts = TARGET._check_current_boundary(account, self.api(values, calls))
            self.assertEqual(facts.policy_main, PROFILE['policy_main'])
            self.assertEqual(tuple(facts.policy_parents), tuple(PROFILE['policy_parents']))
            self.assertEqual(facts.policy_tree, PROFILE['policy_tree'])
            self.assertEqual(facts.core_main, PROFILE['core_main'])
            self.assertEqual(facts.core_dev, '9b5ad1e78430cc0b061cb16de42f73de96f4f312')
            self.assert_aware_clock()
            self.assertTrue(all(value < self.expiry for _, value in self.clock_reads))
            self.assertEqual(calls, [p for p, _ in values])
            self.assertFalse(account.live_complete)

    def test_wrong_repo_bool_id_historical_main_parent_order_tree_core_drift_refuse(self):
        mutations = (
            lambda values: values[0][1].update(id=True),
            lambda values: values[0][1].update(id=1085706003),
            lambda values: values[2][1]['object'].update(sha=PROFILE['policy_parents'][0]),
            lambda values: values[3][1]['parents'].reverse(),
            lambda values: values[3][1]['parents'].pop(),
            lambda values: values[3][1]['tree'].update(sha='0' * 40),
            lambda values: values[4][1]['object'].update(sha='0' * 40),
            lambda values: values[5][1]['object'].update(sha='0' * 40),
            lambda values: values[5][1]['object'].update(sha='4ae6175a4d337296d0347e73b66c9da1f0e43f7f'),
        )
        for index, change in enumerate(mutations):
            with self.subTest(index=index), owned_account() as account:
                values, calls = self.values(), []
                change(values)
                refuse(self, account, lambda: TARGET._check_current_boundary(account, self.api(values, calls)))
                self.assertTrue(calls)
                self.assertLessEqual(len(calls), 6)
                self.assertEqual(calls, [path for path, _ in values][:len(calls)])

    def test_first_new_post_unwind_api_read_sees_one_started_final_window(self):
        with owned_account() as account:
            account.unwound = True
            values, calls = self.values(), []
            delegate = self.api(values, calls)
            windows = []
            class GitHub:
                def get(inner, path):
                    windows.append((account.final_started_ns, account.final_deadline_ns))
                    return delegate.GitHub().get(path)
            TARGET._check_current_boundary(account, SimpleNamespace(GitHub=GitHub))
            self.assertEqual(len(windows), 6)
            self.assertEqual(calls, [path for path, _ in values])
            for window_start, window_end in windows:
                self.assertIsNotNone(window_start)
                self.assertLessEqual(window_end, window_start + 60_000_000_000)
            start = account.final_started_ns
            account.stopped = True
            TARGET._finish_original15(account, failed_original(), not_published())
            self.assertEqual(account.final_started_ns, start)

    def test_exact_aware_expiry_refuses_before_any_request(self):
        with owned_account() as account:
            self.clock[0] = self.expiry
            values, calls = self.values(), []
            refuse(self, account, lambda: TARGET._check_current_boundary(account, self.api(values, calls)))
            self.assertEqual(calls, [])
            self.assertIsNone(account.boundary_before)
            self.assertIsNone(account.boundary_after)
            self.assert_aware_clock()
            self.assertTrue(all(value == self.expiry for _, value in self.clock_reads))

    def test_crossing_aware_expiry_by_last_response_refuses_after_boundary(self):
        with owned_account() as account:
            account.unwound = True
            values, calls = self.values(), []
            delegate = self.api(values, calls)
            clock, expiry, admissions = self.clock, self.expiry, []
            reads = self.clock_reads
            class GitHub:
                def get(inner, path):
                    admissions.append(tuple(reads))
                    result = delegate.GitHub().get(path)
                    if len(calls) == len(values):
                        clock[0] = expiry
                    return result
            api = SimpleNamespace(GitHub=GitHub)
            refuse(self, account, lambda: TARGET._check_current_boundary(account, api))
            self.assertEqual(calls, [path for path, _ in values])
            self.assertTrue(admissions[0])
            self.assertLess(admissions[0][-1][1], self.expiry)
            self.assert_aware_clock()
            self.assertEqual(self.clock_reads[-1][1], self.expiry)
            self.assertIsNone(account.boundary_after)
            self.clock[0] = self.expiry - timedelta(seconds=1)
            refuse(self, account, lambda: TARGET._check_current_boundary(account, api))
            self.assertEqual(calls, [path for path, _ in values])
            self.assertIsNone(account.boundary_after)


class RealFailureFinalization(unittest.TestCase):
    def test_real_old_failed_evidence_export_integrity_is_joined_without_native_success(self):
        with owned_account() as account:
            registered_children(account)
            export, summary = actual_failed_old_export(account)
            expected = tuple((r['file'], r['bytes'], r['sha256']) for r in summary['files'])
            old_before = {p.name: p.read_bytes() for p in export.iterdir()}
            result = TARGET._finish_original15(account, failed_original(), published(True))
            self.assertFalse(result.complete)
            self.assertTrue(account.old_join.integrity_complete)
            self.assertEqual(account.old_join.collector_plus_export_read_bytes,
                             summary['collector_plus_export_read_bytes'])
            self.assertEqual(account.old_join.payload_bytes, summary['raw_payload_bytes'])
            self.assertEqual(tuple(account.old_join.files), expected)
            self.assertGreater(account.read_bytes, 0)
            self.assertGreaterEqual(account.spent_bytes, account.read_bytes)
            self.assertEqual({p.name: p.read_bytes() for p in export.iterdir()}, old_before)

    def test_actual_old_export_member_hash_length_and_name_tampering_refuse_integrity(self):
        for kind in ('changed-bytes', 'missing-member', 'wrong-length', 'duplicate-name', 'escape-name', 'withheld'):
            with self.subTest(kind=kind), owned_account() as account:
                registered_children(account)
                export, summary = actual_failed_old_export(account)
                first = summary['files'][0]
                if kind == 'changed-bytes':
                    path = export / first['file']
                    put(path, path.read_bytes() + b'x')
                elif kind == 'missing-member':
                    (export / first['file']).unlink()
                elif kind == 'wrong-length':
                    first['bytes'] += 1
                elif kind == 'duplicate-name':
                    summary['files'].append(copy.deepcopy(first))
                elif kind == 'escape-name':
                    first['file'] = '../outside'
                else:
                    summary['withheld'] = [{'file': 'Synthetic-secret', 'reason': 'secret match'}]
                    summary['public_evidence_complete'] = False
                if kind not in ('changed-bytes', 'missing-member'):
                    put(export / 'export.json', wire(summary))
                result = TARGET._finish_original15(account, failed_original(), published(True))
                self.assertFalse(result.complete)
                self.assertIsNotNone(account.old_join)
                self.assertFalse(account.old_join.integrity_complete)

    def test_earliest_old_export_body_read_has_final_clock_and_no_reset(self):
        with owned_account() as account:
            registered_children(account)
            actual_failed_old_export(account)
            account.unwound = True
            real_read, observations = os.read, []
            def read(descriptor, size):
                observations.append((account.final_started_ns, account.final_deadline_ns))
                return real_read(descriptor, size)
            with patch.object(TARGET.os, 'read', read):
                result = TARGET._finish_original15(account, failed_original(), published(True))
            self.assertFalse(result.complete)
            self.assertTrue(observations)
            for window_start, window_end in observations:
                self.assertIsNotNone(window_start)
                self.assertEqual(window_start, account.final_started_ns)
                self.assertLessEqual(window_end, window_start + 60_000_000_000)

    def test_real_export_destination_failure_cannot_skip_any_root_cleanup(self):
        with owned_account() as account:
            children = registered_children(account)
            put(account.export_path, b'Existing destination is caller-owned')
            result = TARGET._finish_original15(account, failed_original(), not_published())
            self.assertFalse(result.complete)
            self.assertEqual(account.export_path.read_bytes(), b'Existing destination is caller-owned')
            self.assertTrue(all(not c.path.exists() for c in children))
            self.assertTrue(all(item.attempted for item in result.cleanup))

    def test_all_registered_real_roots_are_deleted_on_original_failure(self):
        with owned_account() as account:
            children = registered_children(account)
            root_path, descriptor = account.root.path, account.root.descriptor
            primary = RuntimeError('Synthetic primary error must survive')
            account.primary_error = primary
            result = TARGET._finish_original15(account, failed_original(primary), not_published())
            self.assertFalse(result.complete)
            self.assertIs(account.primary_error, primary)
            self.assertTrue(all(not c.path.exists() for c in children))
            self.assertFalse(root_path.exists())
            with self.assertRaises(OSError):
                os.fstat(descriptor)
            self.assertEqual({r.role for r in result.cleanup}, {'R', 'HOME', 'TMP', 'TEMPLATE', 'OUT'})
            self.assertTrue(all(r.attempted for r in result.cleanup))

    def test_created_root_without_descriptor_still_gets_real_deletion(self):
        with owned_account() as account:
            children = registered_children(account)
            os.close(children[0].descriptor)
            children[0].descriptor = None
            result = TARGET._finish_original15(account, failed_original(), not_published())
            self.assertFalse(result.complete)
            self.assertFalse(children[0].path.exists())
            self.assertTrue(all(not child.path.exists() for child in children))

    def test_preexisting_unowned_child_is_never_deleted(self):
        with owned_account() as account:
            now = time.monotonic_ns()
            account.preparation = TARGET._OriginalRPreparation(now, now + 1_000_000_000)
            path = account.root.path / 'original-r'
            path.mkdir(mode=0o700)
            put(path / 'caller-owned', b'Preserve exact bytes')
            account.preparation.root = TARGET._OriginalRChild(path=path, created=False)
            result = TARGET._finish_original15(account, failed_original(), not_published())
            self.assertFalse(result.complete)
            self.assertEqual((path / 'caller-owned').read_bytes(), b'Preserve exact bytes')

    def test_one_deletion_failure_cannot_skip_later_roots(self):
        with owned_account() as account:
            children = registered_children(account)
            primary = RuntimeError('Synthetic first primary')
            account.primary_error = primary
            real_rmtree, attempts = shutil.rmtree, []
            def fail_first(path, *args, **kwargs):
                attempts.append(Path(path))
                if Path(path) == children[0].path:
                    raise OSError('Synthetic deletion failure')
                return real_rmtree(path, *args, **kwargs)
            with patch.object(shutil, 'rmtree', fail_first):
                result = TARGET._finish_original15(account, failed_original(primary), not_published())
            self.assertFalse(result.complete)
            self.assertIs(account.primary_error, primary)
            self.assertTrue(all(not c.path.exists() for c in children[1:]))
            self.assertTrue(set(c.path for c in children) <= set(attempts))
            self.assertEqual(attempts.count(children[0].path), 1)
            self.assertTrue(children[0].path.exists())
            self.assertTrue(account.root.path.exists())
            self.assertTrue(any(item.role == 'OUT' and item.attempted and not item.deleted
                                for item in result.cleanup))
            self.assertTrue(any(item.role == 'R' and not item.deleted for item in result.cleanup))

    def cleanup_fault(self, fault):
        with owned_account() as account:
            children = registered_children(account)
            roots = (*children, account.root)
            descriptors = {root.descriptor: (root.device, root.inode) for root in roots}
            failed_fd = children[0].descriptor
            footer = account.export_path / 'closure.json'
            primary = RuntimeError('Synthetic first primary')
            injected = OSError('Synthetic exact filesystem fault')
            account.primary_error = primary
            real_open, real_write, real_close = os.open, os.write, os.close
            footer_fds, footer_opens, close_calls, hits, events = set(), [], [], [], []
            def observe_open(path, flags, mode=0o777, *, dir_fd=None):
                descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
                if os.fspath(path) == 'closure.json' and dir_fd is not None:
                    directory = os.fstat(dir_fd)
                    expected = account.export_path.lstat()
                    if (directory.st_dev, directory.st_ino) == (expected.st_dev, expected.st_ino):
                        footer_fds.add(descriptor)
                        footer_opens.append((flags, mode))
                return descriptor
            def write(descriptor, data):
                if fault == 'closure-write' and descriptor in footer_fds:
                    hits.append(injected)
                    events.append('closure-write-failed')
                    raise injected
                return real_write(descriptor, data)
            def close(descriptor):
                expected = descriptors.get(descriptor)
                if expected is not None:
                    try:
                        value = os.fstat(descriptor)
                    except OSError:
                        close_calls.append(descriptor)
                        return real_close(descriptor)
                    if (value.st_dev, value.st_ino) == expected:
                        close_calls.append(descriptor)
                        events.append(('owned-close', descriptor))
                        if fault == 'close' and descriptor == failed_fd:
                            hits.append(injected)
                            raise injected
                footer_fds.discard(descriptor)
                return real_close(descriptor)
            try:
                with (patch.object(TARGET.os, 'open', observe_open),
                      patch.object(TARGET.os, 'write', write), patch.object(TARGET.os, 'close', close)):
                    result = TARGET._finish_original15(account, failed_original(primary), not_published())
                self.assertEqual(hits, [injected])
                self.assertIs(hits[0], injected)
                self.assertIs(account.primary_error, primary)
                self.assertFalse(result.complete)
                self.assertEqual([item.role for item in result.cleanup], ['R', 'HOME', 'TMP', 'TEMPLATE', 'OUT'])
                self.assertTrue(all(item.attempted for item in result.cleanup))
                self.assertTrue(all(not root.path.exists() for root in roots))
                for descriptor in descriptors:
                    self.assertEqual(close_calls.count(descriptor), 1)
                    if fault == 'close' and descriptor == failed_fd:
                        value = os.fstat(descriptor)
                        self.assertEqual((value.st_dev, value.st_ino), descriptors[descriptor])
                    else:
                        with self.assertRaises(OSError):
                            os.fstat(descriptor)
                for item in result.cleanup:
                    self.assertEqual(item.descriptor_closed, not (fault == 'close' and item.role == 'R'))
                if fault == 'closure-write':
                    self.assertEqual(len(footer_opens), 1)
                    flags, mode = footer_opens[0]
                    self.assertEqual(mode, 0o600)
                    required = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                    self.assertEqual(flags & required, required)
                    self.assertEqual(events[0], 'closure-write-failed')
                    self.assertEqual(len(events), 6)
                    self.assertTrue(not footer.exists() or footer.read_bytes() == b'')
            finally:
                if fault == 'close':
                    try:
                        value = os.fstat(failed_fd)
                    except OSError:
                        pass
                    else:
                        if (value.st_dev, value.st_ino) == descriptors[failed_fd]:
                            real_close(failed_fd)

    def test_owned_descriptor_close_failure_still_cleans_every_independent_root(self):
        self.cleanup_fault('close')

    def test_concrete_closure_write_failure_still_cleans_every_independent_root(self):
        self.cleanup_fault('closure-write')

    def test_replaced_root_identity_refuses_deleting_replacement(self):
        with owned_account() as account:
            children = registered_children(account)
            target = children[0].path
            saved = account.root.path.parent / 'saved-owned-r'
            target.rename(saved)
            target.mkdir(mode=0o700)
            put(target / 'replacement', b'Keep replacement')
            result = TARGET._finish_original15(account, failed_original(), not_published())
            self.assertFalse(result.complete)
            self.assertEqual((target / 'replacement').read_bytes(), b'Keep replacement')
            self.assertTrue(all(not c.path.exists() for c in children[1:]))

    def test_safe_closure_omits_arbitrary_exception_message_and_secret(self):
        with owned_account() as account:
            registered_children(account)
            marker = b'Synthetic-credential-must-not-export'
            account.secrets = (marker,)
            error = RuntimeError(marker.decode())
            result = TARGET._finish_original15(account, failed_original(error), not_published())
            self.assertFalse(result.complete)
            if account.export_path.exists():
                for path in account.export_path.iterdir():
                    if path.is_file():
                        self.assertNotIn(marker, path.read_bytes())

    def test_retry_cannot_read_or_reopen_or_repeat_cleanup(self):
        with owned_account() as account:
            registered_children(account)
            TARGET._finish_original15(account, failed_original(), not_published())
            spent, reads = account.spent_bytes, account.read_bytes
            with (patch.object(TARGET.os, 'open', side_effect=AssertionError('Retry open')),
                  patch.object(TARGET.os, 'read', side_effect=AssertionError('Retry read'))):
                with self.assertRaises(TARGET._OriginalProofError):
                    TARGET._finish_original15(account, failed_original(), not_published())
            self.assertEqual((account.spent_bytes, account.read_bytes), (spent, reads))

    def test_expired_final_window_remains_incomplete_and_cleanup_is_attempted(self):
        with owned_account() as account:
            children = registered_children(account)
            account.final_started_ns = time.monotonic_ns() - 61_000_000_000
            account.final_deadline_ns = account.final_started_ns + 60_000_000_000
            start = account.final_started_ns
            result = TARGET._finish_original15(account, failed_original(), not_published())
            self.assertFalse(result.complete)
            self.assertEqual(account.final_started_ns, start)
            self.assertTrue(all(any(item.role == role and item.attempted for item in result.cleanup)
                                for role in ('R', 'HOME', 'TMP', 'TEMPLATE')))


class MainFailureLifecycle(unittest.TestCase):
    def invoke(self, original_error=None, publisher_error=None, finalizer_error=None,
               publisher_value=False):
        with tempfile.TemporaryDirectory(prefix='synthetic-main-failure-') as name:
            parent = Path(name).resolve()
            policy, output = parent / 'policy', parent / 'old-output'
            policy.mkdir()
            output.mkdir(mode=0o700)
            primary = next((error for error in (original_error, publisher_error, finalizer_error)
                            if error is not None), None)
            calls, accounts, registered, published_paths, outcomes, packets = [], [], [], [], [], []
            owned_descriptors, close_calls = {}, []
            real_finish, real_close = TARGET._finish_original15, os.close
            def actual(api, policy, output, rows, fixture, account):
                calls.append('synthetic-actual')
                accounts.append(account)
                registered.extend(registered_children(account))
                for root in (*registered, account.root):
                    owned_descriptors[root.descriptor] = (root.device, root.inode)
                if original_error is not None:
                    raise original_error
                return False
            def publish(path):
                published_paths.append(path)
                calls.append('original-publisher-attempt')
                if publisher_error is not None:
                    raise publisher_error
                return publisher_value
            def finish(account, original, published):
                calls.append('real-new-finalizer')
                outcomes.append((original, published))
                result = real_finish(account, original, published)
                packets.append(result)
                if finalizer_error is not None:
                    raise finalizer_error
                return result
            def close(descriptor):
                expected = owned_descriptors.get(descriptor)
                if expected is not None:
                    try:
                        value = os.fstat(descriptor)
                    except OSError:
                        close_calls.append(descriptor)
                        return real_close(descriptor)
                    if (value.st_dev, value.st_ino) == expected:
                        close_calls.append(descriptor)
                return real_close(descriptor)
            arguments = ['preflight.py', 'actual', '--policy', str(policy), '--output', str(output)]
            observed_error, returned = None, None
            with (patch.object(sys, 'argv', arguments), patch.object(TARGET, 'load_policy', return_value=SimpleNamespace()),
                  patch.object(TARGET, 'fixtures', return_value={}), patch.object(TARGET, 'schedule', return_value=[]),
                  patch.object(TARGET, 'actual', actual), patch.object(TARGET, 'publish_safe', publish),
                  patch.object(TARGET, '_finish_original15', finish), patch.object(TARGET.os, 'close', close)):
                try:
                    returned = TARGET.main()
                except BaseException as error:
                    observed_error = error
            self.assertIs(observed_error, primary)
            if primary is None:
                self.assertIs(type(returned), int)
                self.assertNotEqual(returned, 0)
            self.assertEqual(calls, ['synthetic-actual', 'original-publisher-attempt', 'real-new-finalizer'])
            self.assertEqual(published_paths, [output])
            self.assertEqual(len(accounts), 1)
            self.assertEqual(len(outcomes), 1)
            original, publication = outcomes[0]
            self.assertIs(original.error, original_error)
            self.assertIs(original.state, TARGET._OwnerState.RAISED if original_error is not None
                          else TARGET._OwnerState.RETURNED)
            self.assertIs(original.value, None if original_error is not None else False)
            self.assertIs(publication.error, publisher_error)
            self.assertIs(publication.state, TARGET._OwnerState.RAISED if publisher_error is not None
                          else TARGET._OwnerState.RETURNED)
            self.assertIs(publication.value, None if publisher_error is not None else publisher_value)
            self.assertEqual(len(packets), 1)
            self.assertIs(accounts[0].final_packet, packets[0])
            self.assertTrue(accounts[0].finish_started)
            self.assertFalse(packets[0].complete)
            self.assertEqual([item.role for item in packets[0].cleanup], ['R', 'HOME', 'TMP', 'TEMPLATE', 'OUT'])
            self.assertTrue(all(item.attempted and item.deleted and item.descriptor_closed
                                for item in packets[0].cleanup))
            self.assertTrue(all(not root.path.exists() for root in (*registered, accounts[0].root)))
            for descriptor in owned_descriptors:
                self.assertEqual(close_calls.count(descriptor), 1)
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def test_actual_primary_survives_publisher_failure_and_real_finalizer_runs(self):
        self.invoke(RuntimeError('Synthetic actual primary'), OSError('Synthetic publisher failure'))

    def test_actual_primary_survives_false_publisher_and_real_finalizer_runs(self):
        self.invoke(RuntimeError('Synthetic actual primary'), None)

    def test_actual_false_preserves_publisher_primary_after_real_cleanup(self):
        self.invoke(publisher_error=OSError('Synthetic publisher primary'))

    def test_actual_false_preserves_wrapper_primary_after_real_finalizer_cleanup(self):
        self.invoke(finalizer_error=RuntimeError('Synthetic finalizer wrapper primary'))

    def test_actual_primary_survives_publisher_and_post_cleanup_wrapper_exceptions(self):
        self.invoke(RuntimeError('Synthetic actual primary'), OSError('Synthetic publisher secondary'),
                    RuntimeError('Synthetic finalizer wrapper tertiary'))

    def test_actual_false_publisher_true_real_incomplete_packet_returns_nonzero(self):
        self.invoke(publisher_value=True)


class OriginalSourcePreservation(unittest.TestCase):
    def test_twenty_three_unamended_original_owners_remain_exact_bytes(self):
        raw = Path(TARGET.__file__).read_bytes()
        source = raw.decode()
        lines = source.splitlines(keepends=True)
        owners = {node.name: node for node in ast.parse(source).body
                  if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
        amended = {'actual', 'main', 'restored_acquisition'}
        self.assertEqual(len(PROFILE['original_owners']), 26)
        for name, fact in PROFILE['original_owners'].items():
            self.assertIn(name, owners)
            if name in amended:
                continue
            node = owners[name]
            start = min([node.lineno] + [d.lineno for d in node.decorator_list]) - 1
            segment = ''.join(lines[start:node.end_lineno]).encode()
            self.assertEqual(digest(segment), fact['sha256'], name)

    def test_actual_calls_rows_inside_original_materializer_before_tool_facts(self):
        tree = ast.parse(Path(TARGET.__file__).read_bytes())
        actual = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'actual')
        calls = [n for n in ast.walk(actual) if isinstance(n, ast.Call)]
        prepared = [n for n in calls if isinstance(n.func, ast.Name) and n.func.id == '_prepare_original_r']
        rows = [n for n in calls if isinstance(n.func, ast.Name) and n.func.id == '_original15']
        facts = [n for n in calls if isinstance(n.func, ast.Name) and n.func.id == 'tool_facts']
        owner_timers = [n for n in calls if isinstance(n.func, ast.Name) and n.func.id == 'Timer'
                        and n.args and isinstance(n.args[0], ast.Constant) and n.args[0].value == 1200]
        self.assertEqual(tuple(map(len, (prepared, rows, facts, owner_timers))), (1, 1, 1, 1))
        self.assertLess(prepared[0].lineno, owner_timers[0].lineno)
        self.assertLess(rows[0].lineno, facts[0].lineno)
        materializers = [n for n in ast.walk(actual) if isinstance(n, ast.With)
                         and any(isinstance(i.context_expr, ast.Call)
                                 and isinstance(i.context_expr.func, ast.Attribute)
                                 and i.context_expr.func.attr == 'materialize_native_tool'
                                 for i in n.items)]
        self.assertEqual(len(materializers), 1)
        self.assertIn(rows[0], list(ast.walk(materializers[0])))
        self.assertEqual([a.arg for a in actual.args.args], ['api', 'policy', 'output', 'rows', 'fixture', 'account'])


def main():
    global TARGET, PROFILE, FIXTURES
    parser = argparse.ArgumentParser()
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--fixtures', type=Path)
    parser.add_argument('--policy-helper', type=Path)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--missing', action='store_true')
    modes.add_argument('--products', action='store_true')
    modes.add_argument('--boundary', action='store_true')
    modes.add_argument('--joins', action='store_true')
    modes.add_argument('--preservation', action='store_true')
    args = parser.parse_args()
    TARGET = load(args.candidate.resolve(strict=True), 'fixed_remaining_original15_candidate')
    if args.missing:
        classes = (MissingNew,)
    else:
        PROFILE = json.loads(Path(__file__).with_name('profile.json').read_bytes())
        if not args.preservation and args.policy_helper is None:
            parser.error('--policy-helper is required for implemented modes')
        if not args.preservation:
            helper = args.policy_helper.resolve(strict=True)
            if digest(helper.read_bytes()) != PROFILE['helper_sha256']:
                parser.error('Original P strict JSON helper source drift')
            load(helper, 'late_cycle_admission')
        if args.preservation:
            classes = (OriginalSourcePreservation,)
        elif args.products:
            if args.fixtures is None:
                parser.error('--fixtures is required for --products')
            FIXTURES = args.fixtures.resolve(strict=True)
            for name, fact in PROFILE['fixture_files'].items():
                raw = (FIXTURES / name).read_bytes()
                if (len(raw), digest(raw)) != (fact['bytes'], fact['sha256']):
                    parser.error('Historical Synthetic fixture source drift')
            classes = (ProductFacts, JunitSemantics)
        elif args.boundary:
            classes = (SyntheticPublicBoundary,)
        else:
            classes = (RealFailureFinalization, MainFailureLifecycle)
    suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(cls) for cls in classes)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
