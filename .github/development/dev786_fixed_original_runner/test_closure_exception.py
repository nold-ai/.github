import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('fixtures', ROOT / 'test_remaining_original15.py')
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)
t = f.load(Path(os.environ.get('CANDIDATE', ROOT / 'preflight.py')), 'closure_candidate')
f.TARGET = t
f.load(ROOT.parents[1] / 'scripts/late_cycle_admission.py', 'late_cycle_admission')

class ClosureException(unittest.TestCase):
    def test_real_metadata_budget_refusal_is_exported(self):
        with f.owned_account() as account:
            f.registered_children(account)
            f.actual_failed_old_export(account)
            account.live_entered = True
            account.metadata_bytes = 8 * t.MIB - 65536 + 1
            result = t._finish_original15(account, f.failed_original(), f.published(True))
            self.assertFalse(result.complete)
            self.assertIn('finalization-refused', result.diagnostics)
            self.assertTrue(all(row.deleted and row.descriptor_closed for row in result.cleanup))
            expected = t.exception_facts(account.primary_error)
            self.assertEqual(expected[0]['class'], '_OriginalProofError')
            self.assertTrue(any(frame['function'] == '_finish_original15' for frame in expected[0]['frames']))
            raw = (account.export_path / 'closure.json').read_bytes()
            value = json.loads(raw)
            self.assertEqual(value.get('exception'), expected, 'Primary refusal facts must survive scratch deletion')
            self.assertFalse(value['complete'])
            self.assertEqual(value['files'], [])
            self.assertLessEqual(len(raw), 65536)
            self.assertLessEqual(account.spent_bytes, 512 * t.MIB)

    def test_original_primary_wins_and_secret_message_is_not_exported(self):
        with f.owned_account() as account:
            f.registered_children(account)
            secret = 'github_pat_SyntheticSecretForNegativeControl'
            account.secrets = (secret.encode(),)
            try:
                raise RuntimeError(secret)
            except RuntimeError as error:
                primary = error
            account.primary_error = primary
            result = t._finish_original15(account, f.failed_original(primary), f.not_published())
            self.assertFalse(result.complete)
            self.assertIs(account.primary_error, primary)
            self.assertTrue(all(row.deleted and row.descriptor_closed for row in result.cleanup))
            raw = (account.export_path / 'closure.json').read_bytes()
            self.assertNotIn(secret.encode(), raw)
            self.assertEqual(json.loads(raw).get('exception'), t.exception_facts(primary))

    def test_no_primary_error_has_empty_facts(self):
        with f.owned_account() as account:
            f.registered_children(account)
            result = t._finish_original15(account, f.failed_original(), f.not_published())
            self.assertFalse(result.complete)
            self.assertIsNone(account.primary_error)
            self.assertEqual(json.loads((account.export_path / 'closure.json').read_bytes()).get('exception'), [])

if __name__ == '__main__':
    unittest.main(verbosity=2)
