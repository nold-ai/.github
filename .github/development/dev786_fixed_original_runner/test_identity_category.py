from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


HELPERS = None
TARGET = None
CAP = 16 * 1024 * 1024
DIAGNOSTIC = b'{"synthetic_failed_live_diagnostic":true}\n'


def failed_live_export(test, retained=None, exhausted=False):
    with HELPERS.owned_account() as account:
        children = HELPERS.registered_children(account)
        roots = (*children, account.root)
        descriptors = {root.descriptor: (root.device, root.inode) for root in roots}
        HELPERS.put(account.root.path / 'plan.json', DIAGNOSTIC)
        account.products.plan = TARGET._read_owned(account, TARGET._SourceRole.PLAN)
        account.live_entered = True
        account.live_complete = False
        account.preparation.repository_metadata = b'Synthetic finite repository diagnostic'
        account.live_metadata = (b'Synthetic finite live diagnostic',)
        primary = RuntimeError('Synthetic first primary before finalization')
        account.primary_error = primary
        if retained is not None:
            account.retained_bytes = retained
        before = account.retained_bytes
        if exhausted:
            account.spent_bytes = 511 * 1024 * 1024 - 65536
        real_open, real_write, real_close = os.open, os.write, os.close
        real_base64 = TARGET.base64.b64encode
        identity_fds, identity_opens, identity_writes = set(), [], []
        close_calls, base64_calls = [], []

        def observe_open(path, flags, mode=0o777, *, dir_fd=None):
            is_identity = os.fspath(path) == 'identity.json' and dir_fd is not None
            if is_identity:
                identity_opens.append((flags, mode))
            descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
            if is_identity:
                identity_fds.add(descriptor)
            return descriptor

        def observe_write(descriptor, data):
            if descriptor in identity_fds:
                identity_writes.append(bytes(data))
            return real_write(descriptor, data)

        def observe_close(descriptor):
            expected = descriptors.get(descriptor)
            if expected is not None:
                value = os.fstat(descriptor)
                if (value.st_dev, value.st_ino) == expected:
                    close_calls.append(descriptor)
            identity_fds.discard(descriptor)
            return real_close(descriptor)

        def observe_base64(data):
            base64_calls.append(len(data))
            return real_base64(data)

        with (patch.object(TARGET.os, 'open', observe_open),
              patch.object(TARGET.os, 'write', observe_write),
              patch.object(TARGET.os, 'close', observe_close),
              patch.object(TARGET.base64, 'b64encode', observe_base64)):
            result = TARGET._finish_original15(account, HELPERS.failed_original(), HELPERS.not_published())

        test.assertIs(account.primary_error, primary)
        test.assertFalse(account.live_complete)
        test.assertFalse(result.complete)
        test.assertEqual(result.outcome, 'Incomplete')
        test.assertEqual([item.role for item in result.cleanup], ['R', 'HOME', 'TMP', 'TEMPLATE', 'OUT'])
        test.assertTrue(all(item.attempted and item.deleted and item.descriptor_closed for item in result.cleanup))
        for root in roots:
            test.assertFalse(root.path.exists())
            test.assertEqual(close_calls.count(root.descriptor), 1)
            with test.assertRaises(OSError):
                os.fstat(root.descriptor)
        test.assertEqual(result.export_path, account.export_path)
        closure = json.loads((account.export_path / 'closure.json').read_bytes())
        test.assertFalse(closure['complete'])
        test.assertEqual(closure['outcome'], 'Incomplete')
        identity_path = account.export_path / 'identity.json'
        identity = identity_path.read_bytes() if identity_path.exists() else None
        if identity is not None:
            test.assertEqual(identity_writes, [identity])
            test.assertEqual(len(identity_opens), 1)
        return {'identity': identity, 'opens': identity_opens, 'writes': identity_writes,
                'base64': base64_calls, 'before': before, 'after': account.retained_bytes,
                'diagnostics': result.diagnostics}


class IdentityCategoryFailureControls(unittest.TestCase):
    def test_identity_copy_is_debited_at_exact_report_category_boundary(self):
        calibration = failed_live_export(self)
        self.assertIsNotNone(calibration['identity'])
        identity_size = len(calibration['identity'])
        self.assertGreater(identity_size, 0)
        self.assertTrue(calibration['base64'])
        result = failed_live_export(self, CAP - len(DIAGNOSTIC) - identity_size)
        self.assertIsNotNone(result['identity'])
        self.assertEqual(len(result['identity']), identity_size)
        self.assertEqual(result['after'] - result['before'], len(DIAGNOSTIC) + identity_size)
        self.assertEqual(result['after'], CAP)

    def test_one_byte_over_category_refuses_identity_open_and_write(self):
        calibration = failed_live_export(self)
        self.assertIsNotNone(calibration['identity'])
        identity_size = len(calibration['identity'])
        result = failed_live_export(self, CAP - len(DIAGNOSTIC) - identity_size + 1)
        self.assertEqual(result['opens'], [], 'Over-cap identity member was opened')
        self.assertEqual(result['writes'], [], 'Over-cap identity bytes reached os.write')
        self.assertIsNone(result['identity'])
        self.assertEqual(result['after'] - result['before'], len(DIAGNOSTIC))
        self.assertIn('finalization-refused', result['diagnostics'])

    def test_exhausted_serialization_work_starts_no_base64_copy(self):
        result = failed_live_export(self, exhausted=True)
        self.assertEqual(result['base64'], [], 'Base64 conversion began before failed work admission')
        self.assertEqual(result['opens'], [])
        self.assertEqual(result['writes'], [])
        self.assertIsNone(result['identity'])
        self.assertIn('finalization-refused', result['diagnostics'])


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main():
    global HELPERS, TARGET
    parser = argparse.ArgumentParser(description='Synthetic real-filesystem failed-live accounting controls')
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--helpers', type=Path, required=True)
    args = parser.parse_args()
    HELPERS = load(args.helpers.resolve(strict=True), 'identity_category_accepted_helpers')
    TARGET = HELPERS.load(args.candidate.resolve(strict=True), 'identity_category_candidate')
    HELPERS.TARGET = TARGET
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(IdentityCategoryFailureControls)
    return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
