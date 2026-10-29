import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_remaining_original15 as f

t = f.load(Path(os.environ.get('CANDIDATE', Path(__file__).with_name('preflight.py'))), 'identity_metadata_candidate')
f.TARGET = t
f.load(Path(__file__).resolve().parents[2] / 'scripts/late_cycle_admission.py', 'late_cycle_admission')
CAP = 8 * t.MIB - 65536

class IdentityMetadata(unittest.TestCase):
    def finish(self, raw_size, input_total=None):
        with f.owned_account() as account:
            roots = (*f.registered_children(account), account.root)
            f.actual_failed_old_export(account)
            raw = b'x' * raw_size
            account.preparation.repository_metadata = raw
            account.preparation.metadata_bytes = len(raw)
            account.metadata_bytes = 0 if input_total is None else input_total - len(raw)
            before = (account.metadata_bytes, account.preparation.metadata_bytes)
            account.live_entered = True
            result = t._finish_original15(account, f.failed_original(), f.published(True))
            self.assertFalse(result.complete)
            self.assertTrue(account.old_join.integrity_complete)
            self.assertTrue(all(row.deleted and row.descriptor_closed for row in result.cleanup))
            self.assertEqual(len(result.cleanup), 5)
            for root in roots:
                self.assertFalse(root.path.exists())
                with self.assertRaises(OSError):
                    os.fstat(root.descriptor)
            identity_path = account.export_path / 'identity.json'
            identity = identity_path.read_bytes() if identity_path.exists() else None
            closure = json.loads((account.export_path / 'closure.json').read_bytes())
            self.assertLessEqual(account.spent_bytes, 512 * t.MIB)
            self.assertLessEqual(account.read_bytes, 255 * t.MIB)
            self.assertEqual((account.metadata_bytes, account.preparation.metadata_bytes), before)
            if identity is not None:
                self.assertEqual(base64.b64decode(json.loads(identity)['preparation']['repository']), raw)
                self.assertEqual(account.retained_bytes, len(identity))
                self.assertLessEqual(len(identity), 16 * t.MIB)
                self.assertIn(['identity.json', len(identity), hashlib.sha256(identity).hexdigest()], closure['files'])
            print(json.dumps({'input_total':sum(before), 'identity_bytes':len(identity) if identity else None,
                              'diagnostics':result.diagnostics, 'exception':closure['exception']}))
            return result, identity, closure

    def test_legitimate_preparation_and_identity_fit_separate_categories(self):
        result, identity, _ = self.finish(4 * t.MIB)
        self.assertIsNotNone(identity, 'Valid 4 MiB raw input and <16 MiB identity must export independently')
        self.assertNotIn('finalization-refused', result.diagnostics)

    def test_input_metadata_before_at_and_over_existing_reserve_boundary(self):
        for total in (CAP - 1, CAP, CAP + 1):
            with self.subTest(total=total):
                result, identity, closure = self.finish(1024, total)
                if total <= CAP:
                    self.assertIsNotNone(identity)
                    self.assertNotIn('finalization-refused', result.diagnostics)
                else:
                    self.assertIsNone(identity)
                    self.assertIn('finalization-refused', result.diagnostics)
                    self.assertEqual(closure['files'], [])
                    self.assertEqual(closure['exception'][0]['class'], '_OriginalProofError')

if __name__ == '__main__':
    unittest.main(verbosity=2)
