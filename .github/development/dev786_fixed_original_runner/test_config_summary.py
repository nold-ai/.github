"""Root-only Synthetic controls. No candidate import or fixture execution."""
import ast
import hashlib
import json
from pathlib import Path
import unittest

source = Path(__file__).with_name('test_prepare_original_r.py')
nodes = ast.parse(source.read_text()).body
selected = [node for node in nodes if isinstance(node, ast.FunctionDef)
            and node.name == '_diagnostic_config_summary']
if len(selected) != 1 or selected[0].decorator_list:
    raise ValueError('single undecorated summary required')
namespace = {'hashlib': hashlib}
exec(compile(ast.Module(body=selected, type_ignores=[]), str(source), 'exec'), namespace)
summary = namespace['_diagnostic_config_summary']


class SyntheticSummaryControls(unittest.TestCase):
    def test_closed_benign_values(self):
        triples = [(b'global', b'file:/redacted', b'init.defaultbranch\nmain'),
                   (b'local', b'file:.git/config', b'core.filemode\nfalse'),
                   (b'command', b'command line:', b'core.autocrlf\ninput'),
                   (b'system', b'file:/redacted', b'protocol.version\n2'),
                   (b'global', b'file:/redacted', b'protocol.file.allow\nalways'),
                   (b'local', b'file:.git/config', b'filter.lfs.required\ntrue')]
        raw = b''.join(scope+b'\0'+origin+b'\0'+pair+b'\0' for scope, origin, pair in triples)
        got = summary(raw)
        self.assertEqual(got['status'], 'complete')
        self.assertEqual([record['value'] for record in got['records']],
                         ['main', 'false', 'input', '2', 'always', 'true'])
        self.assertEqual(got['records'][3]['origin'], 'systemfile')
        self.assertEqual(got['sha256'], hashlib.sha256(raw).hexdigest())

    def test_sensitive_and_unknown_fields_are_withheld(self):
        keys = [b'secret-key-MARKER', b'filter.lfs.clean', b'filter.lfs.process',
                b'filter.lfs.smudge', b'credential.helper', b'core.sshcommand',
                b'core.hookspath', b'http.extraheader', b'http.proxy',
                b'https.proxy', b'safe.directory', b'init.defaultbranch']
        raw = b''.join(b'global\0file:/private/PATHMARKER\0'+key+
                       b'\nhttps://user:SECRET@example.invalid/CMDMARKER\0' for key in keys)
        got = summary(raw)
        text = json.dumps(got)
        for marker in ('secret-key-MARKER', 'PATHMARKER', 'SECRET', 'CMDMARKER',
                       'example.invalid', 'https://user'):
            self.assertNotIn(marker, text)
        self.assertEqual(got['records'][0]['key'], 'other')
        self.assertTrue(all(record['value'] == 'withheld' for record in got['records']))
        self.assertEqual(got['records'][-1]['value_code'], 'unknown_value')
        self.assertEqual(got['sha256'], hashlib.sha256(raw).hexdigest())

    def test_size_and_record_bounds(self):
        raw = b'global\0file:/x\0core.filemode\ntrue\0'
        self.assertEqual(len(summary(raw*16)['records']), 16)
        self.assertEqual(summary(raw*17)['status'], 'record_overflow')
        large = b'X'*16385
        got = summary(large)
        self.assertEqual(got['status'], 'oversized')
        self.assertEqual(got['records'], [])
        self.assertEqual(got['bytes'], 16385)
        self.assertEqual(got['sha256'], hashlib.sha256(large).hexdigest())
        boundary = b'global\0file:/x\0other\n'+b'X'*(16384-22)+b'\0'
        self.assertEqual(len(boundary), 16384)
        self.assertEqual(summary(boundary)['status'], 'complete')

    def test_malformed_and_unknown_classes(self):
        self.assertEqual(summary(None)['status'], 'malformed_type')
        for raw in (b'global\0', b'global\0file:/x\0core.filemode\ntrue',
                    b'global\0file:/x\0missing-newline\0', b'\0file:/x\0a\nb\0'):
            got = summary(raw)
            self.assertTrue(got['status'].startswith('malformed'))
            self.assertEqual(got['records'], [])
        got = summary(b'nonstandard\0nonstandard-origin\0core.filemode\nTRUE\0')
        self.assertEqual(got['records'], [{'key': 'core.filemode', 'scope': 'unknown',
                         'origin': 'unknown', 'value': 'withheld', 'value_code': 'unknown_value'}])
        self.assertEqual(summary(b'')['records'], [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
