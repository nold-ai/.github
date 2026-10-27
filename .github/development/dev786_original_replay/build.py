from pathlib import Path
import ast
import base64
import hashlib
import stat
import textwrap
import zlib

PREFIX = '''name: Native materialization development preflight
on:
  push:
    branches: [codex/dev786-native-materialization-preflight]
    paths: [.github/workflows/native-materialization-preflight.yml]
permissions:
  contents: read
jobs:
  materialize:
    if: github.repository == 'nold-ai/.github' && github.event.deleted != true
    runs-on: ubuntu-24.04
    timeout-minutes: 40
    steps:
      - name: Checkout exact auxiliary candidate
        uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10
        with:
          ref: ${{ github.sha }}
          persist-credentials: false
'''
SUFFIX = '''      - name: Observe benign creation deadline
        shell: bash
        run: |
          set -euo pipefail
          /usr/bin/python3 -I -S "$RUNNER_TEMP/native-materialization-preflight/preflight.py" creation-control --policy "$GITHUB_WORKSPACE" --output "$RUNNER_TEMP/native-materialization-preflight/evidence"
      - name: Observe benign cleanup and original command controls
        id: controls
        shell: bash
        run: |
          set -euo pipefail
          /usr/bin/python3 -I -S "$RUNNER_TEMP/native-materialization-preflight/preflight.py" controls --policy "$GITHUB_WORKSPACE" --output "$RUNNER_TEMP/native-materialization-preflight/evidence"
      - name: Observe one unchanged native materialization
        if: success() && steps.controls.outcome == 'success'
        shell: bash
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          set -euo pipefail
          /usr/bin/python3 -I -S "$RUNNER_TEMP/native-materialization-preflight/preflight.py" actual --policy "$GITHUB_WORKSPACE" --output "$RUNNER_TEMP/native-materialization-preflight/evidence"
      - name: Retain safe development diagnostics
        if: always()
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a
        with:
          name: native-materialization-development-${{ github.run_id }}-${{ github.run_attempt }}
          path: ${{ runner.temp }}/native-materialization-preflight/evidence/export/
          if-no-files-found: warn
          retention-days: 7
          compression-level: 6
'''

base = Path(__file__).parent
assert len(SUFFIX) <= 21000
script = (base / 'preflight.py').read_bytes()
definitions = [node for node in ast.parse(script).body if isinstance(node, ast.Assign)
               and any(isinstance(target, ast.Name) and target.id == 'FIXTURE_HASHES' for target in node.targets)]
assert len(definitions) == 1
fixture_hashes = ast.literal_eval(definitions[0].value)
definitions = [node for node in ast.parse(script).body if isinstance(node, ast.Assign)
               and any(isinstance(target, ast.Name) and target.id == 'HELPER_MANIFEST' for target in node.targets)]
assert len(definitions) == 1
helper_manifest = ast.literal_eval(definitions[0].value)
assert len(fixture_hashes) == 9 and set(fixture_hashes) == {p.name for p in (base / 'fixtures').iterdir()}
files = {'preflight.py': script}
for name, size, digest, module_name in helper_manifest:
    assert Path(name).name == name and name.endswith('.py') and name not in files
    path = base / name
    assert stat.S_ISREG(path.lstat().st_mode)
    with path.open('rb') as stream:
        raw = stream.read(size + 1)
    assert len(raw) == size and hashlib.sha256(raw).hexdigest() == digest
    files[name] = raw
observer_tree = ast.parse(files['observation.py'])
limits = {}
for node in observer_tree.body:
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in ('READ_LIMIT', 'CLOSURE_BYTES', 'SOURCE_LIMIT'):
                limits[target.id] = ast.literal_eval(node.value)
assert set(limits) == {'READ_LIMIT', 'CLOSURE_BYTES', 'SOURCE_LIMIT'}
assert script.count(b'HELPER_LIMITS = ()') == 1
files['preflight.py'] = script.replace(b'HELPER_LIMITS = ()',
    ('HELPER_LIMITS = ' + repr(tuple(limits[name] for name in
        ('READ_LIMIT', 'CLOSURE_BYTES', 'SOURCE_LIMIT')))).encode('ascii'))
for name, digest in sorted(fixture_hashes.items()):
    assert Path(name).name == name
    raw = (base / 'fixtures' / name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest
    files['fixtures/' + name] = raw
manifest = [(name, len(raw), hashlib.sha256(raw).hexdigest()) for name, raw in files.items()]
joined = b''.join(files.values())
assert len(joined) <= 256 * 1024
compressed = zlib.compress(joined, level=9)
transport = base64.b64encode(compressed).decode('ascii')


def step(name, run):
    assert len(run) <= 21000, (name, len(run))
    return f'      - name: {name}\n        shell: bash\n        run: |\n' + textwrap.indent(run, '          ')


preparation = []
for offset in range(0, len(transport), 12000):
    chunk = transport[offset:offset + 12000]
    run = 'set -euo pipefail\numask 077\n'
    if offset == 0:
        run += 'mkdir "$RUNNER_TEMP/native-materialization-preflight"\n'
    run += "printf '%s' '" + chunk + "' >> \"$RUNNER_TEMP/native-materialization-preflight/transport.b64\"\n"
    preparation.append(step(f'Write reviewed compressed bytes {offset // 12000 + 1}', run))
decode = '''set -euo pipefail
umask 077
/usr/bin/python3 -I -S - <<'PY_DECODE'
from pathlib import Path
import base64, hashlib, os, zlib
root = Path(os.environ['RUNNER_TEMP']) / 'native-materialization-preflight'
HELPER_MANIFEST = ''' + repr(helper_manifest) + '''
FIXTURE_HASHES = ''' + repr(fixture_hashes) + '''
manifest = ''' + repr(manifest) + '''
expected_names = ''' + repr(list(files)) + '''
helper_identities = {name: (size, digest) for name, size, digest, _ in HELPER_MANIFEST}
fixture_names = ['fixtures/' + name for name in sorted(FIXTURE_HASHES)]
trusted_names = ['preflight.py', *helper_identities, *fixture_names]
assert len(manifest) == len(trusted_names) and [entry[0] for entry in manifest] == trusted_names
assert expected_names == trusted_names and len(set(expected_names)) == len(trusted_names)
assert all(Path(name).name == name and name.endswith('.py') for name in helper_identities)
assert all(name.startswith('fixtures/') and len(Path(name).parts) == 2
           and Path(name).name not in {'.', '..'} for name in fixture_names)
for name, size, digest in manifest:
    if name in helper_identities:
        assert (size, digest) == helper_identities[name]
    elif name.startswith('fixtures/'):
        assert digest == FIXTURE_HASHES[Path(name).name]
transport = root / 'transport.b64'
assert transport.stat().st_size == ''' + str(len(transport)) + '''
with transport.open('rb') as stream:
    transport_bytes = stream.read(''' + str(len(transport) + 1) + ''')
assert len(transport_bytes) == ''' + str(len(transport)) + '''
compressed = base64.b64decode(transport_bytes, validate=True)
assert len(compressed) == ''' + str(len(compressed)) + '''
assert hashlib.sha256(compressed).hexdigest() == ''' + repr(hashlib.sha256(compressed).hexdigest()) + '''
total = sum(size for _, size, _ in manifest)
assert total == ''' + str(len(joined)) + ''' and total <= 256 * 1024
decoder = zlib.decompressobj()
raw = decoder.decompress(compressed, total + 1)
assert len(raw) == total and decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
decoded, offset = {}, 0
for name, size, digest in manifest:
    data = raw[offset:offset + size]
    assert len(data) == size and hashlib.sha256(data).hexdigest() == digest
    decoded[name] = data
    offset += size
assert offset == total and list(decoded) == expected_names
(root / 'fixtures').mkdir(mode=0o700)
for name, data in decoded.items():
    with (root / name).open('xb') as stream:
        stream.write(data)
for name, size, digest in manifest:
    data = (root / name).read_bytes()
    assert len(data) == size and hashlib.sha256(data).hexdigest() == digest
assert sorted(p.name for p in (root / 'fixtures').iterdir()) == sorted(Path(name).name for name in fixture_names)
transport.unlink()
PY_DECODE
'''
preparation.append(step('Prepare reviewed scratch instrument', decode))
(base / 'native-materialization-preflight.yml').write_text(PREFIX + ''.join(preparation) + SUFFIX)
