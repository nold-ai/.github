import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('original_finalizer_controls', ROOT / 'test_remaining_original15.py')
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
fixtures.TARGET = fixtures.load(ROOT / 'preflight.py', 'failed_preparation_candidate')
fixtures.load(ROOT.parents[1] / 'scripts/late_cycle_admission.py', 'late_cycle_admission')
target = fixtures.TARGET


class FailedPreparationExport(unittest.TestCase):
    def test_cleanup_refusal_is_retained_in_incomplete_footer(self):
        with fixtures.owned_account() as account:
            children = fixtures.registered_children(account)
            account.metadata_visits = 128000
            result = target._finish_original15(account, fixtures.failed_original(), fixtures.not_published())
            self.assertFalse(result.complete)
            self.assertTrue(all(not row.deleted for row in result.cleanup))
            self.assertTrue(all(child.path.exists() for child in children))
            footer = json.loads((account.export_path / 'closure.json').read_bytes())
            self.assertFalse(footer['complete'])
            self.assertEqual(len(footer['cleanup']), 5)
            self.assertTrue(all(not row['deleted'] for row in footer['cleanup']))
            self.assertIn('scratch-cleanup-incomplete', footer['diagnostics'])

    def test_captured_command_survives_later_bulk_join_refusal(self):
        with fixtures.owned_account() as account:
            fixtures.registered_children(account)
            export, summary = fixtures.actual_failed_old_export(account)
            name = 'materialization--raw-output.bin'
            payload = b'Synthetic safe bulk evidence\n' * 40000
            fixtures.put(export / name, payload)
            old = next(row for row in summary['files'] if row['file'] == name)
            summary['raw_payload_bytes'] += len(payload) - old['bytes']
            old.update(bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest())
            fixtures.put(export / 'export.json', fixtures.wire(summary))
            command = target._OriginalRGit(('/usr/bin/git', 'config'), 1, 2)
            command.receipt = b'{"reason":"complete","synthetic":true}'
            command.stdout = b'local\0file:.git/config\0extra.test\nSynthetic\0'
            earlier = target._OriginalRGit(('/usr/bin/git', 'ls-files'), 1, 2)
            earlier.stdout = b'Synthetic earlier captured command\n' * 100000
            account.preparation.commands = (earlier, command)
            account.preparation.metadata_bytes = len(earlier.stdout) + len(command.receipt) + len(command.stdout)
            account.live_entered, account.stopped = True, True
            account.spent_bytes = 511 * target.MIB - 65536
            primary = RuntimeError('Synthetic config refusal')
            account.primary_error = primary
            result = target._finish_original15(account, fixtures.failed_original(primary), fixtures.published(True))
            self.assertFalse(result.complete)
            self.assertIn('old-export-refused', result.diagnostics)
            self.assertIs(account.primary_error, primary)
            self.assertTrue(all(row.deleted and row.descriptor_closed for row in result.cleanup))
            path = account.export_path / 'preparation-commands.json'
            self.assertTrue(path.is_file(), 'Already captured command evidence must survive bulk join refusal')
            raw = path.read_bytes()
            rows = json.loads(raw)
            self.assertEqual([[base64.b64decode(value) for value in row] for row in rows],
                             [[command.receipt, command.stdout, command.stderr]])
            footer = json.loads((account.export_path / 'closure.json').read_bytes())
            self.assertIn(['preparation-commands.json', len(raw), hashlib.sha256(raw).hexdigest()], footer['files'])
            self.assertLessEqual(account.spent_bytes, 512 * target.MIB)

    def test_sensitive_command_is_withheld_before_encoding(self):
        with fixtures.owned_account() as account:
            fixtures.registered_children(account)
            command = target._OriginalRGit(('/usr/bin/git', 'config'), 1, 2)
            command.stdout = b'github_pat_SyntheticSecretForNegativeControl'
            account.preparation.commands = (command,)
            account.preparation.metadata_bytes = len(command.stdout)
            account.live_entered, account.stopped = True, True
            result = target._finish_original15(account, fixtures.failed_original(), fixtures.not_published())
            self.assertFalse(result.complete)
            self.assertFalse((account.export_path / 'preparation-commands.json').exists())
            self.assertTrue(all(row.deleted and row.descriptor_closed for row in result.cleanup))


if __name__ == '__main__':
    sys.dont_write_bytecode = True
    unittest.main(verbosity=2)
