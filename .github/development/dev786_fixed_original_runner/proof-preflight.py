from __future__ import annotations

import argparse
import ast
import base64
import dis
import hashlib
import importlib.util
import json
import os
import platform
import re
import signal
import shutil
from xml.parsers import expat
import stat
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from enum import Enum
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

MIB = 1024 * 1024
P = '46a4f141de4497c1f46a6114683308fd6f3b2525'
I = '1' * 40
C = '9b5ad1e78430cc0b061cb16de42f73de96f4f312'
M = '69f075819be5e1ceca1446b026b0417f19e584ca'
MODULES = {
    'native_requirements_bootstrap': '41b6c601923c676e01c64dc6e34dbec0ab6b9586036b180d855a4aba8210b1c4',
    'native_requirements_acquisition': 'eca68d533288503dea824c5419c4aa7f019f9c094c965752127e0c19c5ff1efe',
    'late_cycle_admission': '57d0149537c0d69078b4aa490510da434ede292e71de9d55abd2743f9ba78b64',
    'native_requirements_materialization': '029634a7336e5738a369cd1f2a5cbbf1bda1595cfd6564c043c77aceecb0e4bf',
}
RELEASE = {
    'build-locked.txt': '928e25d0f4f7dfb58c42fe6fccb53048c244ceb18ec9529639bdfc00ce280dc7',
    'build-requirements.in': 'd419d33b0b94793ff3265c6edb9d33340f1f36d2b43d0186a5c4d6525e2955df',
    'locked.txt': 'a4dc12334a3c6ea6090dfa8c32181024338ebad4c24124410dc5a0ea8fd1e341',
    'requirements.in': 'fec04cc26882cc777b6f6c2c1c23d2716eaacc13079316e0c6a2fd5f86aceb5f',
    'tool-files.json': '969cabb52fc6db85de46967f62ffe4f0f9b0ca50a80b5a3e46255a89b51f78ad',
    'runtime.json': '7d8c44bbac4faeca5fdfb34bca673d12691022c17bfc42912ed8c8785525882f',
}
FIXTURE_HASHES = {
    'main.json': '2e6ee0a8cf7619f4dbe5624eb4814d59df4a701158d64c8af177c426e30b71db',
    'index.json': '8bb0276e13664a5208a26451fd66a7e83620c445209b0d24a569daf78d78bc27',
    'compare.json': 'e49c731f723a5bfe5daae171806b3e37caad1f46902e37a27d7bb6800a0f8599',
    'index-envelope.json': '50e7030d2509d0adeae22777643fcae3af4ce8656c65fc623fe46fc7ea9ef520',
    'wrong-index.json': 'cd491ae49ee174fc79d4eed775b22c03156d2d39ad147769da3a5afbed171359',
    'wrong-index-envelope.json': '29ef78589ab54e3eba309f464d21d5051d0041eb93a1a05fda292d43034805b5',
    'moved-main.json': '9187f2fd6a58682fcd4965fefc100865e6d7b8f5155034d382a24b478e8d664e',
    'corrupt-requirements.in': 'b909849caf501cb1343aecf0e80fc26bf997126a78d574c46881d5e54741b18b',
    'corrupt-input-envelope.json': '873544e96ec37ac6b2557691048493a492557aaade29a6eab0eb2606a451eeb5',
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def frozen_inputs(policy):
    records = {}
    for relative, digest in [(f'.github/scripts/{n}.py', h) for n, h in MODULES.items()] + [
            (f'.github/native-tools/dev786/{n}', h) for n, h in RELEASE.items()]:
        path = policy / relative
        require(path.is_file() and not path.is_symlink(), 'frozen file kind')
        raw = path.read_bytes()
        require(sha(raw) == digest, 'frozen input drift')
        records[relative] = {'bytes': len(raw), 'sha256': digest}
    return records


def load_policy(policy):
    frozen_inputs(policy)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(policy / '.github/scripts'))
    loaded = {}
    for name in ('native_requirements_bootstrap', 'late_cycle_admission',
                 'native_requirements_acquisition', 'native_requirements_materialization'):
        require(name not in sys.modules, 'preloaded policy module')
        path = policy / '.github/scripts' / (name + '.py')
        raw = path.read_bytes()
        require(sha(raw) == MODULES[name], 'pre-import source drift')
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        exec(compile(raw, str(path), 'exec'), module.__dict__)
        loaded[name] = module
    identities = {}
    for name, module in loaded.items():
        path = Path(module.__file__)
        require(path == policy / '.github/scripts' / (name + '.py'), 'module path drift')
        require(module.__spec__.origin == str(path), 'module spec origin drift')
        identities[name] = {'file': str(path), 'spec_origin': module.__spec__.origin,
                            'sha256': sha(path.read_bytes())}
    frozen_inputs(policy)
    return SimpleNamespace(bootstrap=loaded['native_requirements_bootstrap'],
                           acquisition=loaded['native_requirements_acquisition'],
                           materialization=loaded['native_requirements_materialization'],
                           GitHub=loaded['late_cycle_admission'].GitHub, identities=identities)


def fixtures():
    result = {}
    for name, digest in FIXTURE_HASHES.items():
        raw = (Path(__file__).parent / 'fixtures' / name).read_bytes()
        require(sha(raw) == digest, 'fixture drift')
        result[name] = raw
    return result


class Deadline(RuntimeError):
    pass


def command_cleanup(private_code):
    mat = sys.modules['native_requirements_materialization']
    path = Path(mat.__file__)
    raw = path.read_bytes()
    require(sha(raw) == MODULES['native_requirements_materialization']
            and mat._private_root.__wrapped__.__code__ is private_code,
            'cleanup owner drift')
    tree = ast.parse(raw)
    owners = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == '_Commands']
    require(len(owners) == 1, 'command owner shape')
    methods = [node for node in owners[0].body if isinstance(node, ast.FunctionDef) and node.name == 'run']
    require(len(methods) == 1, 'command method shape')
    blocks = [node for node in ast.walk(methods[0]) if isinstance(node, ast.Try) and node.finalbody]
    require(len(blocks) == 1, 'command cleanup block count')
    body = blocks[0].finalbody
    expected_body = ast.parse('''_kill_group(marker)
_write(stem.with_suffix(".json"), json.dumps(record, sort_keys=True).encode())
self.records.append((f"process.{self.sequence}", str(stem.with_suffix(".json"))))
_read(stderr, _METADATA_LIMIT)
''').body
    require([ast.dump(node) for node in body] == [ast.dump(node) for node in expected_body],
            'command cleanup block shape')
    kill_nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == '_kill_group']
    require(len(kill_nodes) == 1, 'group cleanup owner shape')
    run_code, kill_code = mat._Commands.run.__code__, mat._kill_group.__code__
    require(run_code.co_filename == kill_code.co_filename == private_code.co_filename == str(path)
            and run_code.co_firstlineno == methods[0].lineno
            and kill_code.co_firstlineno == kill_nodes[0].lineno, 'cleanup code identity')
    start, end = body[0].lineno, body[-1].end_lineno
    require(raw.decode().splitlines()[start - 2].strip() == 'finally:', 'cleanup entry line')
    instructions = list(dis.get_instructions(run_code, show_caches=True))
    offsets = {item.offset for item in instructions if item.positions.lineno is not None
               and start - 1 <= item.positions.lineno <= end}
    entries = [item.offset for index, item in enumerate(instructions[:-1])
               if item.opname == 'PUSH_EXC_INFO' and item.positions.lineno is None
               and instructions[index + 1].positions.lineno == start]
    require(len(entries) == 1 and offsets, 'command cleanup bytecode entry')
    return run_code, kill_code, (start - 1, end), frozenset(offsets | set(entries))


class Timer:
    def __init__(self, seconds, private_code=None):
        self.seconds, self.private_code = seconds, private_code
        self.expired, self.pending, self.deferred = False, False, 0
        guard = command_cleanup(private_code) if private_code else (None, None, (0, 0), frozenset())
        self.run_code, self.kill_code, self.cleanup_lines, self.cleanup_offsets = guard

    def alarm(self, number, frame):
        self.expired = True
        current = frame
        while current:
            if current.f_code is self.private_code:
                self.deferred += 1
                self.pending = True
                signal.setitimer(signal.ITIMER_REAL, 0)
                return
            if current.f_code is self.kill_code or (current.f_code is self.run_code
                    and current.f_lasti in self.cleanup_offsets):
                self.deferred += 1
                self.pending = True
                signal.setitimer(signal.ITIMER_REAL, 0.001)
                return
            current = current.f_back
        self.pending = False
        signal.setitimer(signal.ITIMER_REAL, 0)
        raise Deadline('wall deadline')

    def check(self):
        if self.expired or time.monotonic() >= self.end:
            self.expired = True
            self.pending = False
            signal.setitimer(signal.ITIMER_REAL, 0)
            raise Deadline('wall deadline')

    def cancel(self):
        signal.setitimer(signal.ITIMER_REAL, 0)

    def __enter__(self):
        require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), 'existing timer')
        self.previous = signal.getsignal(signal.SIGALRM)
        self.end = time.monotonic() + self.seconds
        signal.signal(signal.SIGALRM, self.alarm)
        try:
            signal.setitimer(signal.ITIMER_REAL, self.seconds)
            return self
        except BaseException:
            self.cancel()
            signal.signal(signal.SIGALRM, self.previous)
            raise

    def __exit__(self, *exc):
        try:
            self.cancel()
        finally:
            signal.signal(signal.SIGALRM, self.previous)
        if self.pending:
            self.pending = False
            raise Deadline('wall deadline')


def schedule(policy):
    base = '/repos/nold-ai/.github'
    rows = [(base, None), (base + '/git/ref/heads/main', 'main.json'),
            (base + '/contents/.github/native-releases/dev786.json?ref=' + I, 'index-envelope.json'),
            (base + '/compare/' + P + '...' + I, 'compare.json')]
    rows += [(base + '/contents/.github/native-tools/dev786/' + n + '?ref=' + P, None) for n in RELEASE]
    rows += [(base + '/git/ref/heads/main', 'main.json')]
    result = [((path, 4194304, 'application/vnd.github+json', 'none'), fixture) for path, fixture in rows]
    assets = json.loads((policy / '.github/native-tools/dev786/runtime.json').read_bytes())['assets']
    for role in ('uv', 'python', 'gh'):
        asset = assets[role]
        result.append(((f"/repos/{asset['repository']}/releases/assets/{asset['asset_id']}",
                        asset['size'], 'application/octet-stream', 'release'), None))
    for repository, commit in [('nold-ai/specfact-cli', C), ('nold-ai/specfact-cli-modules', M)]:
        for path in ['/repos/' + repository, '/repos/' + repository + '/git/commits/' + commit]:
            result.append(((path, 4194304, 'application/vnd.github+json', 'none'), None))
    return result


class Transcript:
    def __init__(self, rows, fixture, saved, timer, mutation=None):
        self.rows, self.fixture, self.saved, self.timer = rows, fixture, saved, timer
        self.mutation, self.events, self.position, self.real = mutation, [], 0, 0

    def call(self, client, path, *, maximum, accept, redirects):
        self.timer.check()
        request = (path, maximum, accept, redirects)
        require(self.position < len(self.rows) and request == self.rows[self.position][0],
                'transcript unmatched or out of order')
        ordinal = self.position + 1
        name = self.rows[self.position][1]
        event = {'ordinal': ordinal, 'tuple': list(request), 'source': 'synthetic' if name else 'real',
                 'completed': False}
        self.events.append(event)
        if self.mutation == 'benign-acquisition-deadline':
            event['source'] = 'benign-deadline-before-delegation'
            signal.raise_signal(signal.SIGALRM)
        if ordinal == 3 and self.mutation == 'wrong-descriptor':
            name = 'wrong-index-envelope.json'
        if ordinal == 11 and self.mutation == 'moved-main':
            name = 'moved-main.json'
        if name:
            raw = self.fixture[name]
        else:
            self.real += 1
            raw = self.saved(client, path, maximum=maximum, accept=accept, redirects=redirects)
        if ordinal == 8 and self.mutation == 'corrupt-input':
            value = json.loads(raw)
            original = base64.b64decode(value['content'].replace('\n', ''), validate=True)
            require(sha(original) == RELEASE['requirements.in'], 'corrupt control input drift')
            changed = original[:-1] + bytes([original[-1] ^ 1])
            require(changed == self.fixture['corrupt-requirements.in'], 'corrupt control bytes')
            replacement = json.loads(self.fixture['corrupt-input-envelope.json'])
            for field in ('size', 'content', 'sha'):
                value[field] = replacement[field]
            raw = encoded(value)
            event['source'] = 'mutated-real-negative-only'
            event['decoded_sha256'] = sha(changed)
        event.update(bytes=len(raw), sha256=sha(raw), completed=True)
        self.position += 1
        return raw

    @contextmanager
    def installed(self, cls):
        saved = cls._https_get
        require(saved is self.saved, 'transport identity before patch')
        def adapter(client, path, *, maximum, accept, redirects):
            return self.call(client, path, maximum=maximum, accept=accept, redirects=redirects)
        cls._https_get = adapter
        try:
            yield self
        finally:
            cls._https_get = saved
            require(cls._https_get is saved, 'transport restoration')


def expected(api, wrong=False):
    digest = RELEASE['runtime.json']
    return api.acquisition.ProtectedSelection(I, P, RELEASE['tool-files.json'],
        '0' + digest[1:] if wrong else digest, datetime(2026, 11, 4, 23, tzinfo=timezone.utc))


def exception_facts(error):
    result, seen = [], set()
    while error is not None and id(error) not in seen and len(result) < 8:
        seen.add(id(error))
        frames, tb = [], error.__traceback__
        while tb is not None and len(frames) < 32:
            code = tb.tb_frame.f_code
            frames.append({'file': code.co_filename, 'function': code.co_name, 'line': tb.tb_lineno})
            tb = tb.tb_next
        item = {'class': type(error).__name__, 'frames': frames}
        if isinstance(error, ValueError) and len(error.args) == 1 and type(error.args[0]) is str:
            message = error.args[0]
            if len(message) <= 256 and message.startswith(('native materialization rejected:',
                    'native acquisition rejected:', 'tool files rejected:')):
                item['policy_reason'] = message
            elif message in {'api-status', 'immutable-contents-unavailable', 'api-token', 'api-host'}:
                item['boundary_reason'] = message
        result.append(item)
        error = error.__context__
    return result


class Evidence:
    def __init__(self, output):
        output.mkdir(mode=0o700, parents=False, exist_ok=False)
        self.output = output
        self.read_bytes = self.raw_bytes = self.ledger_bytes = 0
        self.complete = True
        self.issues, self.files, self.envs, self.executables = [], [], {}, {}
        self.secrets = [v.encode() for k, v in os.environ.items()
                        if re.search(r'TOKEN|SECRET|PASSWORD|CREDENTIAL|COOKIE', k, re.I) and len(v) >= 8]
        self.raw = (output / 'raw-output.bin').open('xb')
        self.ledger = (output / 'commands.jsonl').open('xb')
        self.collection_started = None
        self.collection_finished = None

    def incomplete(self, reason):
        self.complete = False
        self.issues.append(reason)

    def safe(self, raw):
        return not any(value in raw for value in self.secrets) and not re.search(
            rb'(?i)(?:authorization\s*:\s*bearer |github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9]+|X-Amz-Signature=|sig=)', raw)

    def record(self, value):
        raw = encoded(value) + b'\n'
        require(self.safe(raw), 'unsafe ledger withheld')
        require(self.ledger_bytes + len(raw) <= 15 * MIB, 'ledger budget')
        self.ledger.write(raw)
        self.ledger_bytes += len(raw)

    def read(self, path, retain=False, maximum=8*MIB):
        if self.collection_started is None:
            self.collection_started = time.monotonic()
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode), 'evidence nonregular file')
        limit = min(before.st_size, 512*MIB-self.read_bytes)
        if retain:
            limit = min(limit, maximum, 32*MIB-self.raw_bytes)
        require(limit >= 0, 'negative budget')
        digest, total, chunks = hashlib.sha256(), 0, []
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            opened = os.fstat(stream.fileno())
            require((before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino), 'file replaced')
            while total < limit:
                chunk = stream.read(min(65536, limit-total))
                if not chunk:
                    break
                total += len(chunk)
                digest.update(chunk)
                if retain:
                    chunks.append(chunk)
            after = os.fstat(stream.fileno())
        current = path.lstat()
        fields = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        stable = fields(before) == fields(opened) == fields(after) == fields(current)
        complete = stable and total == before.st_size
        self.read_bytes += total
        fact = {'path': str(path), 'bytes': before.st_size, 'full_read_bytes': total,
                'complete': complete, 'retention': 'raw' if retain else 'digest_only'}
        if complete:
            fact['sha256'] = digest.hexdigest()
        else:
            fact['truncated'] = total < before.st_size
            self.incomplete('unstable or truncated ' + path.name)
        raw = b''.join(chunks) if retain else None
        if retain:
            if not self.safe(raw):
                self.incomplete('unsafe payload withheld ' + path.name)
                fact['retention'] = 'withheld'
                raw = None
            else:
                fact['offset'], fact['retained_bytes'] = self.raw_bytes, len(raw)
                self.raw.write(raw)
                self.raw_bytes += len(raw)
        return fact, raw

    def capture(self, root, timeout=60, fault=None):
        if self.collection_started is None:
            self.collection_started = time.monotonic()
        remaining = min(timeout, 60 - (time.monotonic() - self.collection_started))
        require(remaining > 0, 'collector wall budget')
        with Timer(remaining):
            if fault == 'raise':
                raise RuntimeError('benign collector failure')
            if fault == 'timeout':
                time.sleep(timeout + 1)
            for relative in ['runtime.json', 'install-report.json'] + [
                    'inputs/' + n for n in RELEASE if n != 'runtime.json']:
                path = root / relative
                if not path.exists():
                    self.files.append({'path': relative, 'status': 'not_created'})
                    continue
                require(not path.parent.is_symlink(), 'metadata parent symlink')
                fact, _ = self.read(path, retain=True)
                self.files.append(fact)
            logs = root / 'logs'
            if not logs.exists():
                self.files.append({'path': 'logs', 'status': 'not_created'})
                return
            require(stat.S_ISDIR(logs.lstat().st_mode), 'logs directory kind')
            names = set()
            with os.scandir(logs) as entries:
                for entry in entries:
                    require(len(names) < 80096, 'log entry limit')
                    require(re.fullmatch(r'[0-9]{5}\.(json|stdout|stderr|pgid)', entry.name), 'unknown log entry')
                    require(entry.is_file(follow_symlinks=False), 'log entry kind')
                    names.add(entry.name)
            sequences = sorted({int(n.split('.')[0]) for n in names})
            require(len(sequences) <= 20024 and sequences == list(range(1, len(sequences)+1)), 'command sequence')
            mapping, blob_seen = {}, {}
            self.command_count = len(sequences)
            for number in sequences:
                stem = f'{number:05d}'
                if not all(stem + '.' + suffix in names for suffix in ('json', 'stdout', 'stderr', 'pgid')):
                    self.incomplete('missing command file ' + stem)
                    self.record({'number': number, 'complete': False, 'status': 'missing_command_file'})
                    continue
                receipt, raw = self.read(logs / (stem + '.json'), retain=True, maximum=65536)
                if not receipt['complete'] or raw is None:
                    self.incomplete('incomplete receipt ' + stem)
                    self.record({'number': number, 'complete': False, 'original_receipt': receipt})
                    continue
                record = json.loads(raw)
                argv, env = record['argv'], record.pop('env')
                environment = sha(encoded(env))
                self.envs[environment] = env
                record.update(number=number, environment_sha256=environment, original_receipt=receipt)
                executable = Path(argv[0])
                if not executable.is_absolute():
                    executable = Path(root / 'bin' / argv[0])
                resolved = executable.resolve(strict=True)
                if str(resolved) not in self.executables:
                    self.executables[str(resolved)], _ = self.read(resolved)
                identity = self.executables[str(resolved)]
                record['executable'] = {'spelling': argv[0], 'resolved': str(resolved), **identity}
                marker, marker_raw = self.read(logs / (stem + '.pgid'), retain=True, maximum=32)
                record['process_group_marker'] = marker
                record['pass_fds'] = {'count': 1, 'target': str(logs / (stem + '.pgid')),
                                      'basis': 'unchanged _Commands pass_fds implementation'}
                blob = len(argv) >= 3 and argv[-3:-1] == ['cat-file', 'blob'] and record['exit_code'] == 0
                retain_stdout = not blob or (logs / (stem + '.stderr')).lstat().st_size > 0
                stdout, stdout_raw = self.read(logs / (stem + '.stdout'), retain=retain_stdout)
                stderr, _ = self.read(logs / (stem + '.stderr'), retain=True)
                record.update(stdout_observation=stdout, stderr_observation=stderr)
                if 'ls-tree' in argv and record['exit_code'] == 0 and stdout_raw is not None:
                    repository = argv[argv.index('-C')+1]
                    require(stdout['complete'] and stdout_raw.endswith(b'\0'), 'incomplete ls-tree')
                    entries = []
                    for line in stdout_raw[:-1].split(b'\0'):
                        match = re.fullmatch(rb'(100644|100755) blob ([a-f0-9]{40})\t(.+)', line)
                        require(match is not None, 'ls-tree record')
                        entries.append({'mode': match[1].decode(), 'blob': match[2].decode(),
                                        'path': match[3].decode()})
                    require(len(entries) <= 10000, 'tree entry count')
                    mapping[repository] = entries
                    blob_seen[repository] = 0
                if blob:
                    repository = argv[argv.index('-C')+1]
                    index = blob_seen[repository]
                    entry = mapping[repository][index]
                    require(entry['blob'] == argv[-1], 'blob order or identity')
                    record['source_blob'] = {'repository': repository, **entry}
                    blob_seen[repository] += 1
                self.record(record)
            self.source_counts = {key: len(value) for key, value in mapping.items()}
            self.blob_counts = blob_seen

    def finish(self, manifest):
        if self.collection_started is not None and (self.collection_finished or time.monotonic()) - self.collection_started > 60:
            self.incomplete('collection and cleanup exceeded 60 seconds')
        if not self.complete and manifest.get('outcome') == 'DEVELOPMENT_MATERIALIZATION_OBSERVED':
            manifest['outcome'] = 'EVIDENCE_INCOMPLETE'
        self.raw.close()
        self.ledger.close()
        manifest.update(evidence_complete=self.complete, issues=self.issues, files=self.files,
                        collector_read_bytes=self.read_bytes, raw_retained_bytes=self.raw_bytes,
                        source_counts=getattr(self, 'source_counts', {}),
                        source_blob_counts=getattr(self, 'blob_counts', {}),
                        command_count=getattr(self, 'command_count', 0))
        for name, value in [('environments.json', self.envs), ('manifest.json', manifest)]:
            if name == 'manifest.json' and not self.complete:
                manifest['evidence_complete'] = False
                if manifest.get('outcome') == 'DEVELOPMENT_MATERIALIZATION_OBSERVED':
                    manifest['outcome'] = 'EVIDENCE_INCOMPLETE'
            raw = encoded(value)
            if not self.safe(raw):
                self.complete = False
                raw = encoded({'outcome': 'EVIDENCE_INCOMPLETE', 'withheld': name})
            require(self.ledger_bytes + len(raw) <= 16*MIB, 'combined metadata budget')
            self.ledger_bytes += len(raw)
            (self.output / name).write_bytes(raw)
        files = list(self.output.iterdir())
        require(len(files) <= 64 and sum(p.stat().st_size for p in files) <= 48*MIB, 'export budget')
        return self.complete


@contextmanager
def cleanup_observer(materialization, workspace, evidence, timer, state, fault=None):
    saved = materialization.shutil
    parent = workspace.stat()
    state.update(observations=0, deleted=False, capture='not_started')
    def observe(target, *args, **kwargs):
        path = Path(target)
        owned = path.parent == workspace and path.name.startswith('native-tool-')
        if not owned:
            return saved.rmtree(target, *args, **kwargs)
        timer.cancel()
        state['deadline_expired'] = timer.expired
        state['deadline_deferrals'] = timer.deferred
        state['scope_seconds_before_collection'] = time.monotonic() - (timer.end - timer.seconds)
        state['observations'] += 1
        state['root'] = str(path)
        state['setup_exception'] = exception_facts(sys.exc_info()[1])
        try:
            current = workspace.stat()
            require((current.st_dev, current.st_ino) == (parent.st_dev, parent.st_ino), 'parent replaced')
            root_before = path.lstat()
            require(stat.S_ISDIR(root_before.st_mode), 'owned root kind')
            require(state['observations'] == 1, 'multiple owned cleanup')
            evidence.capture(path, timeout=0.05 if fault == 'timeout' else 60, fault=fault)
            root_after = path.lstat()
            require((root_before.st_dev, root_before.st_ino) == (root_after.st_dev, root_after.st_ino),
                    'owned root replaced during capture')
            state['capture'] = 'complete' if evidence.complete else 'incomplete'
        except BaseException as error:
            evidence.incomplete('capture ' + type(error).__name__)
            state['capture'] = type(error).__name__
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            try:
                saved.rmtree(target, *args, **kwargs)
            except BaseException as error:
                state['deletion_failure'] = type(error).__name__
                raise
            finally:
                state['deleted'] = not path.exists()
                evidence.collection_finished = time.monotonic()
    materialization.shutil = SimpleNamespace(which=saved.which, rmtree=observe)
    try:
        yield
    finally:
        materialization.shutil = saved
        state['shutil_restored'] = materialization.shutil is saved
        require(state['shutil_restored'], 'shutil restoration')


def adapter_controls(api, rows, fixture):
    calls = []
    def harmless(client, path, **kwargs):
        calls.append(path)
        return b'{}'
    receipts = []
    with Timer(10) as timer:
        for kind in ('unmatched', 'out-of-order', 'duplicate'):
            transcript = Transcript(rows, fixture, harmless, timer)
            if kind == 'duplicate':
                request = rows[0][0]
                transcript.call(None, request[0], maximum=request[1], accept=request[2], redirects=request[3])
            request = rows[1][0] if kind == 'out-of-order' else rows[0][0]
            if kind == 'unmatched':
                request = ('/repos/nold-ai/.github/contents/UNMATCHED?ref=' + P, *request[1:])
            before = len(calls)
            try:
                transcript.call(None, request[0], maximum=request[1], accept=request[2], redirects=request[3])
            except ValueError:
                pass
            else:
                raise ValueError('adapter control unexpectedly accepted')
            require(len(calls) == before, 'mismatch delegated')
            receipts.append({'control': kind, 'consumed': transcript.position, 'delegated_on_mismatch': 0})
        saved = api.GitHub._https_get
        transcript = Transcript(rows, fixture, saved, timer)
        try:
            with transcript.installed(api.GitHub):
                raise RuntimeError('benign adapter caller failure')
        except RuntimeError:
            pass
        require(api.GitHub._https_get is saved, 'exception restoration')
        fresh = Transcript(rows, fixture, saved, timer)
        require(fresh.position == 0 and fresh.real == 0, 'fresh transcript state')
        receipts.append({'control': 'restoration-and-fresh-state', 'restored': True, 'next_ordinal': 1})
    return receipts


def cleanup_signal_control(api, output):
    import ctypes

    require(sys.platform == 'linux', 'original command signal control requires Linux')
    mat = api.materialization
    workspace = Path(tempfile.mkdtemp(prefix='preflight-cleanup-signal-')).resolve()
    evidence = Evidence(output / 'cleanup-signal')
    state = {}
    observation = {'control': 'cleanup-signal', 'signal_deliveries': 0,
                   'pending_delivered': False, 'independent_cleanup_used': False,
                   'descendant_waited': False, 'original_group_absent': False}
    saved, transport = mat.shutil, api.GitHub._https_get
    owners = (mat._Commands.run, mat._kill_group, mat._private_root)
    previous_alarm = signal.getsignal(signal.SIGALRM)
    libc = ctypes.CDLL(None, use_errno=True)

    def subreaper():
        value = ctypes.c_int()
        require(libc.prctl(37, ctypes.byref(value), 0, 0, 0) == 0, 'read child subreaper')
        return value.value

    prior_subreaper = subreaper()
    observation['subreaper_before'] = prior_subreaper
    marker, stdout, armed, injected_at = None, None, False, None

    def identity():
        with marker.open('rb') as stream:
            group_raw = stream.read(33)
        require(re.fullmatch(rb'[1-9][0-9]*', group_raw) is not None, 'control group marker')
        group = int(group_raw)
        require(group != os.getpgrp(), 'control owned group')
        observation['group'] = group
        with stdout.open('rb') as stream:
            child_raw = stream.read(129)
        require(re.fullmatch(rb'[1-9][0-9]* [1-9][0-9]*\n', child_raw) is not None,
                'control descendant identity')
        parent, child = map(int, child_raw.split())
        require(parent == group and child != group, 'control descendant group')
        observation['descendant'] = child

    def at_cleanup(event, args):
        nonlocal armed, injected_at
        if not armed or event != 'open' or args[0] != str(marker):
            return
        frame = sys._getframe(1)
        while frame and frame.f_code is not owners[1].__code__:
            frame = frame.f_back
        if frame is None:
            return
        armed = False
        try:
            caller = frame.f_back
            require(caller.f_code is owners[0].__code__
                    and caller.f_lasti in timer.cleanup_offsets
                    and timer.cleanup_lines[0] <= caller.f_lineno <= timer.cleanup_lines[1],
                    'signal outside original command cleanup')
            identity()
            child, group = observation['descendant'], observation['group']
            require(os.getpgid(child) == group, 'descendant group drift')
            waited, status = os.waitpid(child, os.WNOHANG)
            if waited:
                observation.update(descendant_waited=True, descendant_wait_status=status)
            require(waited == 0, 'descendant not live at cleanup')
            os.killpg(group, 0)
            observation.update(audit_event=event, original_cleanup_line=caller.f_lineno,
                               group_alive_before_signal=True, signal_deliveries=1)
        except Exception as error:
            observation['audit_validation_exception'] = exception_facts(error)
            return
        injected_at = time.monotonic()
        signal.raise_signal(signal.SIGALRM)
        observation['pending_at_injection'] = timer.pending

    sys.addaudithook(at_cleanup)
    try:
        require(libc.prctl(36, 1, 0, 0, 0) == 0 and subreaper() == 1, 'enable child subreaper')
        observation['subreaper_during'] = subreaper()
        with Timer(15, mat._private_root.__wrapped__.__code__) as timer:
            with cleanup_observer(mat, workspace, evidence, timer, state):
                with mat._private_root(workspace) as root:
                    timer.check()
                    commands = mat._Commands(root, mat._environment(root))
                    marker, stdout = root / 'logs/00001.pgid', root / 'logs/00001.stdout'
                    armed = True
                    try:
                        commands.run(['/usr/bin/python3', '-I', '-S', '-c', '''import os, time
read_fd, write_fd = os.pipe()
child = os.fork()
if child == 0:
    os.close(write_fd)
    ready = os.read(read_fd, 1)
    os.close(read_fd)
    if ready == b'1':
        time.sleep(30)
    os._exit(0)
os.close(read_fd)
print(os.getpid(), child, flush=True)
os.write(write_fd, b'1')
os.close(write_fd)
'''])
                        time.sleep(0.25)
                        raise ValueError('pending cleanup deadline not redelivered')
                    except Deadline:
                        observation['pending_delivered'] = True
                        observation['delivery_seconds'] = time.monotonic() - injected_at if injected_at else None
                        observation['receipt_present_at_delivery'] = (root / 'logs/00001.json').is_file()
                        raise
                    finally:
                        armed = False
                        timer.cancel()
                        try:
                            if 'descendant' not in observation:
                                identity()
                            child = observation['descendant']
                            until = time.monotonic() + 2
                            while not observation['descendant_waited']:
                                waited, status = os.waitpid(child, os.WNOHANG)
                                if waited:
                                    observation.update(descendant_waited=True, descendant_wait_status=status)
                                elif time.monotonic() >= until:
                                    observation['independent_cleanup_used'] = True
                                    os.kill(child, signal.SIGKILL)
                                    waited, status = os.waitpid(child, 0)
                                    observation.update(descendant_waited=waited == child, descendant_wait_status=status)
                                else:
                                    time.sleep(0.005)
                            try:
                                os.killpg(observation['group'], 0)
                            except ProcessLookupError:
                                observation['group_absent_after_wait'] = True
                                observation['original_group_absent'] = not observation['independent_cleanup_used']
                            else:
                                observation['group_absent_after_wait'] = False
                        except BaseException as error:
                            observation['child_cleanup_exception'] = exception_facts(error)
                        finally:
                            if 'group' in observation and (not observation['descendant_waited']
                                    or 'child_cleanup_exception' in observation):
                                observation['independent_cleanup_used'] = True
                                observation['fallback_waits'] = []
                                try:
                                    try:
                                        os.killpg(observation['group'], signal.SIGKILL)
                                    except ProcessLookupError:
                                        pass
                                    until = time.monotonic() + 2
                                    while True:
                                        try:
                                            waited, status = os.waitpid(-observation['group'], os.WNOHANG)
                                        except ChildProcessError:
                                            observation['fallback_group_children_waited'] = True
                                            break
                                        if waited:
                                            require(len(observation['fallback_waits']) < 2, 'control child count')
                                            observation['fallback_waits'].append({'pid': waited, 'wait_status': status})
                                            if waited == observation.get('descendant'):
                                                observation.update(descendant_waited=True, descendant_wait_status=status)
                                        else:
                                            require(time.monotonic() < until, 'control fallback wait bound')
                                            time.sleep(0.005)
                                except BaseException as error:
                                    observation['independent_cleanup_exception'] = exception_facts(error)
                                finally:
                                    try:
                                        os.killpg(observation['group'], 0)
                                    except ProcessLookupError:
                                        observation['group_absent_after_fallback'] = True
                                    else:
                                        observation['group_absent_after_fallback'] = False
    except BaseException as error:
        observation['exception'] = exception_facts(error)
    finally:
        armed = False
        restored = libc.prctl(36, prior_subreaper, 0, 0, 0) == 0
        observation['subreaper_after'] = subreaper()
        observation['subreaper_restored'] = restored and observation['subreaper_after'] == prior_subreaper
        observation['state_restored'] = (mat.shutil is saved and api.GitHub._https_get is transport
            and (mat._Commands.run, mat._kill_group, mat._private_root) == owners
            and signal.getsignal(signal.SIGALRM) is previous_alarm
            and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0))
        if not list(workspace.iterdir()):
            workspace.rmdir()
    observation['cleanup'] = state
    observation['deadline_deferrals'] = timer.deferred if 'timer' in locals() else 0
    status = observation.get('descendant_wait_status')
    observation['descendant_killed'] = (type(status) is int and os.WIFSIGNALED(status)
                                         and os.WTERMSIG(status) == signal.SIGKILL)
    evidence.raw.flush()
    evidence.ledger.flush()
    records = [json.loads(line) for line in (evidence.output / 'commands.jsonl').read_bytes().splitlines()]
    observation['original_receipt_complete'] = (len(records) == 1 and records[0].get('exit_code') == 0
        and 'failure_type' not in records[0] and records[0].get('original_receipt', {}).get('complete') is True)
    observation['credited'] = (observation['signal_deliveries'] == 1 and observation['pending_delivered']
        and observation.get('pending_at_injection') is True and observation['deadline_deferrals'] >= 1
        and observation.get('receipt_present_at_delivery') is True
        and observation.get('delivery_seconds') is not None and observation['delivery_seconds'] <= 0.25
        and observation['descendant_killed'] and observation['descendant_waited']
        and observation['original_group_absent'] and not observation['independent_cleanup_used']
        and observation['original_receipt_complete'] and observation['state_restored']
        and observation['subreaper_restored'] and state.get('deleted') is True
        and state.get('observations') == 1 and evidence.complete)
    if not observation['credited']:
        evidence.incomplete('signal-at-cleanup control failed')
    evidence.finish(observation)
    require(observation['credited'], 'original cleanup signal control failed')
    return {'control': 'cleanup-signal', 'observed': True, 'evidence': evidence.output.name}


def cleanup_controls(api, output, rows, fixture):
    creation = json.loads((output / 'creation-deadline.json').read_bytes())
    require(creation['pending_checked_at_body'] and creation['roots_deleted']
            and creation['observed_deferrals'] == 1, 'creation deadline control missing')
    results = []
    mat = api.materialization
    private_code = mat._private_root.__wrapped__.__code__
    cases = ['caller-exception', 'collector-exception', 'collector-timeout', 'before-logs', 'acquisition-deadline']
    if sys.platform == 'linux':
        cases += ['failed-command', 'live-command-timeout', 'over-limit-receipt']
    for case in cases:
        workspace = Path(tempfile.mkdtemp(prefix='preflight-control-')).resolve()
        evidence = Evidence(output / case)
        state, observed = {}, []
        saved = mat.shutil
        previous_alarm = signal.getsignal(signal.SIGALRM)
        transport = api.GitHub._https_get
        with Timer(15, private_code) as timer:
            fault = {'collector-exception': 'raise', 'collector-timeout': 'timeout'}.get(case)
            try:
                with cleanup_observer(mat, workspace, evidence, timer, state, fault):
                    if case in ('before-logs', 'acquisition-deadline'):
                        transcript = Transcript(rows[:1] if case == 'acquisition-deadline' else [],
                            fixture, transport, timer,
                            'benign-acquisition-deadline' if case == 'acquisition-deadline' else None)
                        prior = {key: os.environ.get(key) for key in ('GH_TOKEN', 'GITHUB_TOKEN')}
                        os.environ['GH_TOKEN'] = 'benign-control-no-network'
                        os.environ.pop('GITHUB_TOKEN', None)
                        try:
                            with transcript.installed(api.GitHub):
                                with mat.materialize_native_tool(expected(api), workspace):
                                    raise AssertionError('unreachable materialization yield')
                        finally:
                            for key, value in prior.items():
                                if value is None:
                                    os.environ.pop(key, None)
                                else:
                                    os.environ[key] = value
                        raise AssertionError('acquisition did not refuse')
                    with mat._private_root(workspace) as root:
                        timer.check()
                        if case in ('failed-command', 'live-command-timeout', 'over-limit-receipt'):
                            commands = mat._Commands(root, mat._environment(root))
                            if case == 'live-command-timeout':
                                signal.setitimer(signal.ITIMER_REAL, 0.25)
                                commands.run(['/usr/bin/python3', '-I', '-S', '-c',
                                              'import time; print("live", flush=True); time.sleep(30)'])
                            else:
                                try:
                                    commands.run(['/usr/bin/python3', '-I', '-S', '-c',
                                                  'import sys; print("benign stdout"); print("benign stderr", file=sys.stderr); sys.exit(7)'])
                                except ValueError:
                                    if case == 'failed-command':
                                        raise
                                receipt = root / 'logs/00001.json'
                                with receipt.open('ab') as stream:
                                    stream.write(b' ' * 65537)
                        elif case == 'caller-exception':
                            raise LookupError('benign caller failure')
            except (LookupError, ValueError, Deadline) as error:
                observed = exception_facts(error)
        require(mat.shutil is saved and api.GitHub._https_get is transport
                and signal.getsignal(signal.SIGALRM) is previous_alarm
                and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), 'control restoration')
        if case == 'acquisition-deadline':
            require(any(x['class'] == 'Deadline' for x in observed)
                    and transcript.real == 0 and transcript.position == 0, 'acquisition deadline not observed')
        require(state['observations'] == 1 and state['deleted'], 'control deletion')
        manifest = {'control': case, 'cleanup': state, 'exception': observed}
        evidence.finish(manifest)
        if case in ('collector-exception', 'collector-timeout', 'over-limit-receipt'):
            require(not evidence.complete, 'control incomplete evidence not detected')
        else:
            require(evidence.complete, 'benign capture incomplete')
        if case == 'failed-command':
            records = [json.loads(x) for x in (evidence.output / 'commands.jsonl').read_bytes().splitlines()]
            require(len(records) == 1 and records[0]['exit_code'] == 7, 'failed exit missing')
        if case == 'live-command-timeout':
            records = [json.loads(x) for x in (evidence.output / 'commands.jsonl').read_bytes().splitlines()]
            require(len(records) == 1 and records[0].get('failure_type') == 'Deadline'
                    and records[0]['exit_code'] is None, 'timeout receipt missing')
            marker = records[0]['process_group_marker']
            data = (evidence.output / 'raw-output.bin').read_bytes()
            group = int(data[marker['offset']:marker['offset'] + marker['retained_bytes']])
            try:
                os.killpg(group, 0)
            except ProcessLookupError:
                pass
            else:
                raise ValueError('control child group remains')
            require(b'live\n' in data, 'timeout did not reach live child')
        workspace.rmdir()
        results.append({'control': case, 'observed': True, 'evidence': evidence.output.name})
    if sys.platform == 'linux':
        results.append(cleanup_signal_control(api, output))
    results.append(json.loads((output / 'creation-deadline.json').read_bytes()))
    return {'controls': results, 'adapter_controls': adapter_controls(api, rows, fixture),
            'linux_original_commands_observed': sys.platform == 'linux',
            'all_required_controls': sys.platform == 'linux'}


def acquisition_negatives(api, rows, fixture, output):
    results = []
    for mutation, count, reason in [
            ('wrong-descriptor', 10, 'native acquisition rejected: runtime descriptor digest differs'),
            ('moved-main', 11, 'native acquisition rejected: policy main changed'),
            ('corrupt-input', 10, 'tool files rejected: digest mismatch for requirements.in')]:
        saved = api.GitHub._https_get
        with Timer(120) as timer:
            transcript = Transcript(rows[:11], fixture, saved, timer, mutation)
            try:
                with transcript.installed(api.GitHub):
                    api.acquisition.acquire_tool_release(now=datetime.now(timezone.utc),
                        expected_selection=expected(api, wrong=mutation == 'wrong-descriptor'))
            except ValueError as error:
                facts = exception_facts(error)
            else:
                raise ValueError('negative acquisition accepted')
        item = {'control': mutation, 'events': transcript.events, 'consumed': transcript.position,
                'exception': facts, 'restored': api.GitHub._https_get is saved,
                'credited': transcript.position == count and any(x.get('policy_reason') == reason for x in facts)}
        try:
            item['restoration'] = restored_acquisition(api, saved, api.materialization.shutil)
        except Exception as error:
            item['restoration'] = {'credited': False, 'exception': exception_facts(error)}
        item['credited'] = item['credited'] and item['restoration']['credited']
        raw = encoded(item)
        require(len(raw) <= MIB, 'negative receipt bound')
        (output / (mutation + '.json')).write_bytes(raw)
        results.append(item)
        require(item['credited'] and item['restored'], 'negative predicate was not observed')
    return results


def restored_acquisition(api, transport, original_shutil):
    require(api.GitHub._https_get is transport and api.materialization.shutil is original_shutil,
            'restoration identity missing')
    with Timer(120):
        client = api.GitHub()
        require(client._https_get.__func__ is transport, 'fresh instance transport identity')
        main = client.obj('/repos/nold-ai/.github/git/ref/heads/main')
        public = {'ref': main.get('ref'), 'object': {'type': main.get('object', {}).get('type'),
                                                   'sha': main.get('object', {}).get('sha')}}
        require(public == {'ref': 'refs/heads/main', 'object': {'type': 'commit',
                'sha': '640549e62fb3ca001499e71d4cf935aa8c0a0192'}}
                and public['object']['sha'] != I, 'original main unavailable or changed')
        try:
            api.acquisition.acquire_tool_release(now=datetime.now(timezone.utc), expected_selection=expected(api))
        except ValueError as error:
            facts = exception_facts(error)
        else:
            raise ValueError('ordinary acquisition accepted synthetic selection')
    reasons = {x.get('policy_reason') for x in facts}
    boundaries = {x.get('boundary_reason') for x in facts}
    functions = {frame['function'] for item in facts for frame in item['frames']}
    if 'native acquisition rejected: active selection differs' in reasons:
        classification = 'selection_refusal'
    elif 'immutable-contents-unavailable' in boundaries and {
            'acquire_tool_release', '_selection', 'immutable_contents'} <= functions:
        classification = 'unavailable_context_refusal'
    else:
        classification = 'unclassified_failure'
    return {'adapter_installed': False, 'identities_restored': True, 'fresh_instance_original': True,
            'main_public_fields': public, 'main_public_fields_sha256': sha(encoded(public)),
            'exception': facts, 'classification': classification,
            'credited': classification != 'unclassified_failure',
            'request_count': 'unobserved; separate main read plus unchanged pre-tool acquisition bound',
            'protected_selection_authenticated': False}


def tool_facts(tool, evidence, policy):
    value = asdict(tool)
    for key in ('python', 'site_packages', 'core_root', 'modules_root', 'uv', 'gh'):
        value[key] = str(value[key])
    value['selection']['expires_at'] = value['selection']['expires_at'].isoformat()
    release = policy / '.github/native-tools/dev786'
    pins = {}
    for name in ('locked.txt', 'build-locked.txt'):
        for package, version in re.findall(r'^([A-Za-z0-9_.-]+)==([^\s;]+)', (release / name).read_text(), re.M):
            normalized = re.sub(r'[-_.]+', '-', package).lower()
            require(normalized not in pins or pins[normalized] == version, 'conflicting pins')
            pins[normalized] = version
    require(len(pins) == 57 and dict(tool.inventory) == pins, 'yield inventory mismatch')
    named = {
        'core': ['src/specfact_cli/cli.py', 'src/specfact_cli/registry/module_packages.py',
                 'scripts/requirements_proof_executor.py', 'scripts/requirements_proof_provenance.py',
                 'scripts/requirements_proof_pytest_plugin.py', 'ci/module-fixture.lock.json'],
        'modules': ['packages/specfact-requirements/module-package.yaml',
                    'packages/specfact-requirements/src/specfact_requirements/__init__.py',
                    'packages/specfact-requirements/src/specfact_requirements/requirements/__init__.py',
                    'packages/specfact-requirements/src/specfact_requirements/requirements/app.py',
                    'packages/specfact-requirements/src/specfact_requirements/requirements/commands.py'],
    }
    value['named_source_bytes'] = []
    for role, names in named.items():
        root = tool.core_root if role == 'core' else tool.modules_root
        for name in names:
            path = root / name
            require(path.resolve(strict=True) == path, 'named source symlink')
            fact, _ = evidence.read(path)
            value['named_source_bytes'].append(fact)
    for role in ('python', 'uv', 'gh'):
        fact, _ = evidence.read(getattr(tool, role).resolve(strict=True))
        value[role + '_installed_bytes'] = fact
    return value


def actual(api, policy, output, rows, fixture, account):
    require(sys.platform == 'linux' and platform.machine() == 'x86_64', 'Linux runner required')
    os_release = platform.freedesktop_os_release()
    require(os_release.get('ID') == 'ubuntu' and os_release.get('VERSION_ID') == '24.04', 'Ubuntu 24.04 required')
    require(os.environ.get('GITHUB_REPOSITORY') == 'nold-ai/.github'
            and os.environ.get('GITHUB_REF') == 'refs/heads/codex/dev786-native-materialization-preflight',
            'fixed auxiliary workflow scope')
    controls = json.loads((output / 'controls.json').read_bytes())
    require(controls['all_required_controls']
            and controls['harness_sha256'] == sha(Path(__file__).read_bytes())
            and controls['inputs_after'] == frozen_inputs(policy), 'Linux controls missing or stale')
    evidence = Evidence(output / 'materialization')
    manifest = {'outcome': 'SETUP_FAILED', 'policy_commit': P, 'modules': api.identities,
                'runner': {'os': platform.system(), 'distribution': os_release['ID'], 'distribution_version': os_release['VERSION_ID'],
                           'machine': platform.machine(), 'kernel': platform.release(),
                           'python': sys.version, 'executable': sys.executable,
                           'image_os': os.environ.get('ImageOS'), 'image_version': os.environ.get('ImageVersion')},
                'harness_sha256': sha(Path(__file__).read_bytes()), 'inputs_before': frozen_inputs(policy)}
    transport, saved_shutil = api.GitHub._https_get, api.materialization.shutil
    workspace = Path(tempfile.mkdtemp(prefix='native-preflight-workspace-')).resolve()
    state, transcript, yielded = {}, None, False
    try:
        manifest['negative_controls'] = acquisition_negatives(api, rows, fixture, output)
        manifest['adapter_controls'] = adapter_controls(api, rows, fixture)
        mat = api.materialization
        _check_current_boundary(account, api)
        prepared = _prepare_original_r(account, api)
        _proof_require(account.metadata_bytes + getattr(account.preparation, 'metadata_bytes', 0) <= 8 * MIB - 65536)
        account.phase = _OriginalPhase.PREPARED
        with Timer(1200, mat._private_root.__wrapped__.__code__) as timer:
            transcript = Transcript(rows, fixture, transport, timer)
            with transcript.installed(api.GitHub):
                with cleanup_observer(mat, workspace, evidence, timer, state):
                    with mat.materialize_native_tool(expected(api), workspace) as tool:
                        timer.check()
                        require(transcript.position == 18 and transcript.real == 14, 'positive transcript incomplete')
                        _original15(account, prepared, tool, timer)
                        manifest['tool'] = tool_facts(tool, evidence, policy)
                        timer.check()
                        yielded = True
        require(api.GitHub._https_get is transport and mat.shutil is saved_shutil, 'parent restoration')
        require(state['observations'] == 1 and state['deleted'], 'owned cleanup incomplete')
        require(len(evidence.source_counts) == 2 and evidence.source_counts == evidence.blob_counts
                and evidence.command_count == 24 + sum(evidence.source_counts.values()), 'command coverage')
        manifest['outcome'] = 'DEVELOPMENT_MATERIALIZATION_OBSERVED' if evidence.complete else 'EVIDENCE_INCOMPLETE'
    except BaseException as error:
        if account.primary_error is None:
            account.primary_error = error
        account.stopped = True
        manifest['exception'] = exception_facts(error)
        if yielded or not evidence.complete:
            manifest['outcome'] = 'EVIDENCE_INCOMPLETE'
    finally:
        account.unwound = True
        if not account.stopped:
            account.phase = _OriginalPhase.UNWOUND
        signal.setitimer(signal.ITIMER_REAL, 0)
        manifest['cleanup'] = state
        manifest['yielded'] = yielded
        manifest['transport'] = transcript.events if transcript else []
        manifest['last_completed_transport_ordinal'] = transcript.position if transcript else 0
        manifest['restored'] = api.GitHub._https_get is transport and api.materialization.shutil is saved_shutil
        if transcript is not None:
            try:
                manifest['ordinary_restoration'] = restored_acquisition(api, transport, saved_shutil)
                if not manifest['ordinary_restoration']['credited']:
                    evidence.incomplete('ordinary restoration unclassified')
                    manifest['outcome'] = 'EVIDENCE_INCOMPLETE'
            except BaseException as error:
                manifest['ordinary_restoration'] = {'credited': False, 'exception': exception_facts(error)}
                evidence.incomplete('ordinary restoration failed')
                manifest['outcome'] = 'EVIDENCE_INCOMPLETE'
        if list(workspace.iterdir()) or state.get('deletion_failure'):
            manifest['outcome'] = 'CLEANUP_FAILED'
        else:
            workspace.rmdir()
        try:
            manifest['inputs_after'] = frozen_inputs(policy)
        except BaseException as error:
            evidence.incomplete('post-operation input identity ' + type(error).__name__)
            manifest['outcome'] = 'EVIDENCE_INCOMPLETE'
        if not manifest['restored']:
            manifest['outcome'] = 'EVIDENCE_INCOMPLETE'
        try:
            evidence.finish(manifest)
        except BaseException as error:
            evidence.complete = False
            manifest['outcome'] = 'EVIDENCE_INCOMPLETE'
            (evidence.output / 'manifest.json').write_bytes(encoded({
                'outcome': 'EVIDENCE_INCOMPLETE', 'finalization_failure': type(error).__name__,
                'cleanup': state, 'collector_read_bytes': evidence.read_bytes, 'restored': manifest['restored']}))
    account.restored = manifest['restored'] and state.get('deleted', False)
    try:
        _check_current_boundary(account, api)
    except BaseException as error:
        _proof_failed(account, error)
    return manifest['outcome'] == 'DEVELOPMENT_MATERIALIZATION_OBSERVED' and evidence.complete


def creation_control(api, output):
    workspace = Path(tempfile.mkdtemp(prefix='preflight-creation-control-')).resolve()
    mat = api.materialization
    saved = mat.shutil
    events, yielded, checked = [], [], False
    def at_creation(event, args):
        if event == 'tempfile.mkdtemp' and not events:
            candidate = Path(args[0])
            if candidate.parent == workspace and candidate.name.startswith('native-tool-'):
                events.append(str(candidate))
                signal.raise_signal(signal.SIGALRM)
    sys.addaudithook(at_creation)
    try:
        with Timer(10, mat._private_root.__wrapped__.__code__) as timer:
            try:
                with mat._private_root(workspace) as root:
                    yielded.append(str(root))
                    checked = True
                    timer.check()
                    raise AssertionError('expired creation deadline accepted')
            except Deadline:
                pass
        require(len(events) == 1 and events == yielded and timer.deferred == 1
                and checked and timer.expired, 'creation deferral not observed')
        require(not list(workspace.iterdir()) and mat.shutil is saved, 'creation cleanup or restoration')
        result = {'control': 'creation-deadline', 'audit_event': 'tempfile.mkdtemp',
                  'actual_signal': 'SIGALRM', 'observed_deferrals': timer.deferred,
                  'pending_checked_at_body': checked, 'roots_deleted': True, 'root': events[0]}
        (output / 'creation-deadline.json').write_bytes(encoded(result))
    finally:
        workspace.rmdir()


def export_bytes(path, maximum):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, 'export file bound or kind')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
    current = path.lstat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(identity(before) == identity(opened) == identity(after) == identity(current)
            and len(raw) == before.st_size, 'export changed')
    return raw


def publish_safe(output):
    allowed_dirs = {'caller-exception', 'collector-exception', 'collector-timeout', 'before-logs',
                    'failed-command', 'live-command-timeout', 'over-limit-receipt', 'acquisition-deadline',
                    'cleanup-signal', 'materialization'}
    allowed_files = {'creation-deadline.json', 'controls.json', 'wrong-descriptor.json',
                     'moved-main.json', 'corrupt-input.json', 'actual-failure.json'}
    payloads, withheld, total, control_total, capture_reads, metadata_reads = [], [], 0, 0, 0, 0
    require(output.is_dir() and not output.is_symlink(), 'export parent kind')
    for entry in output.iterdir():
        if entry.name == 'export':
            continue
        require(not entry.is_symlink(), 'export source symlink')
        if entry.name in allowed_dirs and entry.is_dir():
            paths = list(entry.iterdir())
            require({p.name for p in paths} <= {'manifest.json', 'environments.json', 'commands.jsonl', 'raw-output.bin'},
                    'unknown diagnostic file')
        else:
            require(entry.name in allowed_files and entry.is_file(), 'unknown diagnostic entry')
            paths = [entry]
        for path in paths:
            require(path.is_file() and not path.is_symlink(), 'export file kind')
            require(len(payloads) < 63, 'export file count')
            size = path.stat().st_size
            total += size
            if entry.name != 'materialization':
                control_total += size
            require(total <= 48*MIB-65536 and control_total <= 8*MIB, 'export raw budget')
            payloads.append(path)
            if path.name == 'manifest.json':
                require(size <= 16*MIB, 'manifest read bound')
                metadata_reads += size
                capture_reads += json.loads(export_bytes(path, 16*MIB)).get('collector_read_bytes', 0)
    destination = output / 'export'
    destination.mkdir(mode=0o700, exist_ok=True)
    require(not destination.is_symlink(), 'export directory kind')
    prior_reads = 0
    previous = destination / 'export.json'
    if previous.exists():
        previous_raw = export_bytes(previous, 65536)
        prior_reads = json.loads(previous_raw).get('export_read_bytes', 0) + len(previous_raw)
    for path in destination.iterdir():
        require(path.is_file() and not path.is_symlink(), 'existing export kind')
        path.unlink()
    secrets = [v.encode() for k, v in os.environ.items()
               if re.search(r'TOKEN|SECRET|PASSWORD|CREDENTIAL|COOKIE', k, re.I) and len(v) >= 8]
    reads, records = metadata_reads + prior_reads, []
    for path in payloads:
        if capture_reads + reads + path.stat().st_size > 512*MIB:
            withheld.append({'file': str(path.relative_to(output)), 'reason': 'combined read cap'})
            continue
        raw = export_bytes(path, 48*MIB)
        reads += len(raw)
        if any(secret in raw for secret in secrets) or re.search(
                rb'(?i)(?:authorization\s*:\s*bearer |github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9]+|X-Amz-Signature=|sig=)', raw):
            withheld.append({'file': str(path.relative_to(output)), 'reason': 'secret match'})
            continue
        name = str(path.relative_to(output)).replace('/', '--')
        (destination / name).write_bytes(raw)
        records.append({'file': name, 'bytes': len(raw), 'sha256': sha(raw)})
    summary = {'development_diagnostics_only': True, 'withheld': withheld,
               'public_evidence_complete': not withheld, 'files': records,
               'raw_payload_bytes': sum(x['bytes'] for x in records),
               'collector_plus_export_read_bytes': capture_reads + reads, 'export_read_bytes': reads}
    (destination / 'export.json').write_bytes(encoded(summary))
    require(sum(p.stat().st_size for p in destination.iterdir()) <= 48*MIB, 'final export cap')
    return not withheld


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('creation-control', 'controls', 'actual'))
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    policy, output = args.policy.resolve(strict=True), args.output.absolute()
    api = load_policy(policy)
    fixture, rows = fixtures(), schedule(policy)
    if args.mode == 'creation-control':
        output.mkdir(mode=0o700)
        try:
            creation_control(api, output)
        except BaseException as error:
            (output / 'creation-deadline.json').write_bytes(encoded({
                'outcome': 'EVIDENCE_INCOMPLETE', 'exception': exception_facts(error),
                'pending_checked_at_body': False, 'roots_deleted': False, 'observed_deferrals': 0}))
            publish_safe(output)
            raise
        print('Original private-root creation deadline and cleanup observed.')
        return 0
    if args.mode == 'controls':
        try:
            result = cleanup_controls(api, output, rows, fixture)
            result.update(modules=api.identities, inputs_after=frozen_inputs(policy), harness_sha256=sha(Path(__file__).read_bytes()))
            (output / 'controls.json').write_bytes(encoded(result))
        except BaseException as error:
            (output / 'controls.json').write_bytes(encoded({
                'all_required_controls': False, 'outcome': 'EVIDENCE_INCOMPLETE',
                'exception': exception_facts(error)}))
            raise
        finally:
            publish_safe(output)
        print('Benign controls observed. Linux command controls required.' if not result['all_required_controls']
              else 'Benign controls observed, including original Linux command cleanup.')
        return 0
    original = _OwnerOutcome(_OwnerState.NOT_STARTED, None, None)
    published = _OwnerOutcome(_OwnerState.NOT_STARTED, None, None)
    packet = _Original15Packet(False, 'Incomplete', (), (), None)
    primary = None
    root_path = output.parent / ('original15-' + os.urandom(12).hex())
    root = _OwnedRoot(root_path, -1, 0, 0, os.getuid(), stat.S_IFDIR | 0o700)
    account = _AttemptAccount(root, time.monotonic_ns() + 3600_000_000_000, ())
    account.policy, account.original_output = policy, output
    account.export_path = root_path.with_name(root_path.name + '-export')
    account.api = api
    actual_started = False
    try:
        root_path.mkdir(mode=0o700, exist_ok=False)
        descriptor = os.open(root_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        account.root = _OwnedRoot(root_path, descriptor, 0, 0, os.getuid(), stat.S_IFDIR | 0o700)
        value = os.fstat(descriptor)
        account.root = _OwnedRoot(root_path, descriptor, value.st_dev, value.st_ino, value.st_uid, value.st_mode)
        secrets = tuple(v.encode() for k, v in os.environ.items()
                        if re.search(r'TOKEN|SECRET|PASSWORD|CREDENTIAL|COOKIE', k, re.I) and len(v) >= 8)
        require(len(secrets) <= 32 and all(len(v) <= 4096 for v in secrets), 'secret boundary')
        account.secrets = secrets
        if hasattr(api, 'GitHub'):
            account.saved_transport = api.GitHub._https_get
            account.saved_materializer = api.materialization.materialize_native_tool
        actual_started = True
        original = _OwnerOutcome(_OwnerState.RETURNED,
                                 actual(api, policy, output, rows, fixture, account), None)
    except BaseException as error:
        primary = error
        if actual_started:
            original = _OwnerOutcome(_OwnerState.RAISED, None, error)
        if account.primary_error is None:
            account.primary_error = error
    finally:
        try:
            published = _OwnerOutcome(_OwnerState.RETURNED, publish_safe(output), None)
        except BaseException as error:
            published = _OwnerOutcome(_OwnerState.RAISED, None, error)
            if primary is None:
                primary = error
            if account.primary_error is None:
                account.primary_error = error
        finally:
            try:
                packet = _finish_original15(account, original, published)
            except BaseException as error:
                if primary is None:
                    primary = error
    if primary is not None:
        raise primary
    return 0 if original.value is True and published.value is True and packet.complete else 1



class _OriginalStage(Enum):
    PLANNER = 'planner'
    EXECUTOR = 'executor'
    RECONCILER = 'reconciler'
    BINDER = 'binder'


@dataclass(frozen=True)
class _PreparedPaths:
    root: Path
    out: Path
    home: Path
    tmp: Path


@dataclass(frozen=True)
class _OriginalVector:
    stage: _OriginalStage
    argv: tuple[bytes, ...]
    environment: tuple[tuple[bytes, bytes], ...]
    cwd: bytes
    expected_exit: int
    seconds: int


@dataclass(frozen=True)
class _DirectResult:
    stage: _OriginalStage
    vector: _OriginalVector
    pid: int | None
    started: float
    deadline: float
    ended: float
    waitid: tuple[int, int, int] | None
    wait_status: int | None
    stdout: bytes
    stderr: bytes
    cleanup_complete: bool
    deadline_seen: bool
    reason: str


class _OriginalStageError(RuntimeError):
    pass


def _original_vectors(tool, prepared: _PreparedPaths) -> tuple[_OriginalVector, ...]:
    raise NotImplementedError('NEW original vectors missing')


def _run_original_stage(account, tool, prepared: _PreparedPaths, timer,
                        stage: _OriginalStage) -> _DirectResult:
    raise NotImplementedError('NEW original row lifetime missing')


class _SourceRole(Enum):
    PLAN = 'plan.json'
    PLANNING_REPORT = 'planning-report.json'
    PLANNING_SUMMARY = 'planning-summary.md'
    JUNIT = 'requirements-proof.xml'
    REPORT = 'local-red-report.json'
    UNBOUND_REPORT = 'local-red-unbound-report.json'
    RED_SUMMARY = 'local-red-summary.md'
    SOURCE_00 = 'source-00'
    SOURCE_01 = 'source-01'
    SOURCE_02 = 'source-02'
    SOURCE_03 = 'source-03'
    SOURCE_04 = 'source-04'
    SOURCE_05 = 'source-05'
    SOURCE_06 = 'source-06'
    SOURCE_07 = 'source-07'
    SOURCE_08 = 'source-08'
    SOURCE_09 = 'source-09'
    SOURCE_10 = 'source-10'
    SOURCE_11 = 'source-11'
    SOURCE_12 = 'source-12'
    SOURCE_13 = 'source-13'
    SOURCE_14 = 'source-14'
    SOURCE_15 = 'source-15'
    SOURCE_16 = 'source-16'
    SOURCE_17 = 'source-17'
    SOURCE_18 = 'source-18'
    SOURCE_19 = 'source-19'
    SOURCE_20 = 'source-20'
    SOURCE_21 = 'source-21'
    SOURCE_22 = 'source-22'
    SOURCE_23 = 'source-23'
    SOURCE_24 = 'source-24'
    SOURCE_25 = 'source-25'
    SOURCE_26 = 'source-26'
    SOURCE_27 = 'source-27'
    SOURCE_28 = 'source-28'
    SOURCE_29 = 'source-29'
    SOURCE_30 = 'source-30'
    SOURCE_31 = 'source-31'
    SOURCE_32 = 'source-32'
    SUBJECT_0_REQUIREMENT = 'subject-0-requirement'
    SUBJECT_0_GITPYTHON = 'subject-0-gitpython'
    SUBJECT_0_GITDB = 'subject-0-gitdb'
    SUBJECT_0_SMMAP = 'subject-0-smmap'
    SUBJECT_0_INIT = 'subject-0-init'
    SUBJECT_0_BASE = 'subject-0-base'
    SUBJECT_1_REQUIREMENT = 'subject-1-requirement'
    SUBJECT_1_GITPYTHON = 'subject-1-gitpython'
    SUBJECT_1_GITDB = 'subject-1-gitdb'
    SUBJECT_1_SMMAP = 'subject-1-smmap'
    SUBJECT_1_INIT = 'subject-1-init'
    SUBJECT_1_BASE = 'subject-1-base'
    SUBJECT_2_REQUIREMENT = 'subject-2-requirement'
    SUBJECT_2_GITPYTHON = 'subject-2-gitpython'
    SUBJECT_2_GITDB = 'subject-2-gitdb'
    SUBJECT_2_SMMAP = 'subject-2-smmap'
    SUBJECT_2_INIT = 'subject-2-init'
    SUBJECT_2_BASE = 'subject-2-base'


_FIXED_SOURCES = (
    ('P', '.github/scripts/native_requirements_bootstrap.py', '41b6c601923c676e01c64dc6e34dbec0ab6b9586036b180d855a4aba8210b1c4'),
    ('P', '.github/scripts/native_requirements_acquisition.py', 'eca68d533288503dea824c5419c4aa7f019f9c094c965752127e0c19c5ff1efe'),
    ('P', '.github/scripts/late_cycle_admission.py', '57d0149537c0d69078b4aa490510da434ede292e71de9d55abd2743f9ba78b64'),
    ('P', '.github/scripts/native_requirements_materialization.py', '029634a7336e5738a369cd1f2a5cbbf1bda1595cfd6564c043c77aceecb0e4bf'),
    ('P', '.github/native-tools/dev786/build-locked.txt', '928e25d0f4f7dfb58c42fe6fccb53048c244ceb18ec9529639bdfc00ce280dc7'),
    ('P', '.github/native-tools/dev786/build-requirements.in', 'd419d33b0b94793ff3265c6edb9d33340f1f36d2b43d0186a5c4d6525e2955df'),
    ('P', '.github/native-tools/dev786/locked.txt', 'a4dc12334a3c6ea6090dfa8c32181024338ebad4c24124410dc5a0ea8fd1e341'),
    ('P', '.github/native-tools/dev786/requirements.in', 'fec04cc26882cc777b6f6c2c1c23d2716eaacc13079316e0c6a2fd5f86aceb5f'),
    ('P', '.github/native-tools/dev786/tool-files.json', '969cabb52fc6db85de46967f62ffe4f0f9b0ca50a80b5a3e46255a89b51f78ad'),
    ('P', '.github/native-tools/dev786/runtime.json', '7d8c44bbac4faeca5fdfb34bca673d12691022c17bfc42912ed8c8785525882f'),
    ('R', 'tests/unit/scripts/test_dependency_compatibility_workflow.py', '416e367877990ebb2d809e11847c363cd599c32f32d014a818f09053d5fab7fa'),
    ('R', 'tests/unit/scripts/test_dependency_trust_review.py', 'bb20822cb58c8f773f8ed7a54628feef2e1eadbf5cc5c53936422223986ee7ac'),
    ('R', 'tests/unit/scripts/test_security_audit_gate.py', '5100ceaa78a4381b8565f5a3c996e8d8b15ceda44d18de9ebcf04eb0561f81a3'),
    ('R', 'tests/unit/security/test_frozen_gitpython_compatibility.py', 'c1d428aba630c5f4abd4f236c10540632fb86e9c0e93ea1a9ba91809dbe415af'),
    ('R', 'tests/unit/security/test_release_dependency_selection.py', 'f713acdfeba8235bd5f7e2c22b7a29585d61693798972b6e9a24a31423e7a4e6'),
    ('R', 'scripts/requirements_proof_pytest_plugin.py', '31a1a8e3f7cf4e9d35612e4395c03298be85262da2bcc91b33008919f2a24de8'),
    ('R', 'openspec/changes/security-dependencies-0-55-11-dev/requirements-evidence.yaml', '6a1f812cc9a0be0adf260cdfb48dda0a5af3c41b5827259459373123861e9e20'),
    ('R', 'openspec/changes/security-dependencies-0-55-11-dev/requirements-proof/review-evidence.json', 'a5664876536b22616c93489ceb4baacd9ba07515f83216e2441289aaf3606707'),
    ('R', 'requirements/ci/locked.txt', '0bf003b492508a171177f2ba386126b76200262e7e49c3d1a25e1c8139250266'),
    ('R', 'uv.lock', '850b941d7d7dabf102d39ce92fb23d7586d183384fac03c140ceae0a07d169b7'),
    ('C', 'src/specfact_cli/cli.py', '191b16df14c9875a4f265ed5a6c86f3d3e9888780930cb0ab7b944f7865cac00'),
    ('C', 'src/specfact_cli/registry/module_packages.py', 'ee47ead2c731d80888f18fa604c3193c54cf43dc7c1513c08fd54063b78e8b9b'),
    ('C', 'scripts/requirements_proof_executor.py', '1217ad0a1dcee26818c47e68019cb6ce11e2d700d83a260d197c8fbb1c0403bd'),
    ('C', 'scripts/requirements_proof_provenance.py', '5bad94f58f6741cd070e6e9f98a95c88d412365a437e0499e30545603cd9f846'),
    ('C', 'scripts/requirements_proof_pytest_plugin.py', '31a1a8e3f7cf4e9d35612e4395c03298be85262da2bcc91b33008919f2a24de8'),
    ('C', 'ci/module-fixture.lock.json', 'f6ce6abcbe24d27b3f2b3596d5533650198afc61e00de1c662faf7d239679de0'),
    ('M', 'packages/specfact-requirements/module-package.yaml', '385ccff7adca9639188ce80185456d66b5e3ab90973b02c6f230eef271d1c412'),
    ('M', 'packages/specfact-requirements/src/specfact_requirements/__init__.py', '1dd57eb29db513d20619506a9eac55b0f2427a51163113857721159e853ce158'),
    ('M', 'packages/specfact-requirements/src/specfact_requirements/requirements/__init__.py', '8838258e7a346f9c9006d9ae211aa053b2bd4424827d5e821a7d758864da07f7'),
    ('M', 'packages/specfact-requirements/src/specfact_requirements/requirements/app.py', '74ac669cb34e040bb6d286ad0d05fdd3dcd014dd0ce99ca3dd5a7957d879de12'),
    ('M', 'packages/specfact-requirements/src/specfact_requirements/requirements/commands.py', '65350ba69469798ccfd07587e979c3ca1b9c61382dd42ae27f7a02cbe4ba96db'),
    ('M', 'packages/specfact-requirements/src/specfact_requirements/requirements/evidence.py', 'f5a34c6fa21d6d1c6428d54da1a9b6ce61bee6d2c2d8d190a8751a7eca25bc3e'),
    ('M', 'packages/specfact-requirements/src/specfact_requirements/requirements/lifecycle.py', '9352b1acde9f520e577657b5812e9b129a8b018ddd76113684b829e7b395d654'),
)

_FIXED_CASES = (
    ('tests/unit/scripts/test_security_audit_gate.py::test_committed_otel_exception_is_exact_and_time_bounded[exact-cve]', 'tests.unit.scripts.test_security_audit_gate', 'test_committed_otel_exception_is_exact_and_time_bounded[exact-cve]', 'tests/unit/scripts/test_security_audit_gate.py', 272, ('assert gate_mod.main(["--exceptions", str(exceptions)]) == scenario.expected', 'AssertionError: assert 1 == 0')),
    ('tests/unit/scripts/test_security_audit_gate.py::test_committed_otel_exception_is_exact_and_time_bounded[exact-ghsa]', 'tests.unit.scripts.test_security_audit_gate', 'test_committed_otel_exception_is_exact_and_time_bounded[exact-ghsa]', 'tests/unit/scripts/test_security_audit_gate.py', 272, ('assert gate_mod.main(["--exceptions", str(exceptions)]) == scenario.expected', 'AssertionError: assert 1 == 0')),
    ('tests/unit/scripts/test_security_audit_gate.py::test_committed_otel_exception_is_exact_and_time_bounded[expiry-day]', 'tests.unit.scripts.test_security_audit_gate', 'test_committed_otel_exception_is_exact_and_time_bounded[expiry-day]', 'tests/unit/scripts/test_security_audit_gate.py', 272, ('assert gate_mod.main(["--exceptions", str(exceptions)]) == scenario.expected', 'AssertionError: assert 1 == 0')),
    ('tests/unit/security/test_release_dependency_selection.py::test_public_declarations_require_reviewed_security_floor[gitpython-floor]', 'tests.unit.security.test_release_dependency_selection', 'test_public_declarations_require_reviewed_security_floor[gitpython-floor]', 'tests/unit/security/test_release_dependency_selection.py', 61, ('assert requirement in project["project"]["dependencies"]', 'gitpython>=3.2.1')),
    ('tests/unit/security/test_release_dependency_selection.py::test_public_declarations_require_reviewed_security_floor[pycparser-floor]', 'tests.unit.security.test_release_dependency_selection', 'test_public_declarations_require_reviewed_security_floor[pycparser-floor]', 'tests/unit/security/test_release_dependency_selection.py', 61, ('assert requirement in project["project"]["dependencies"]', 'pycparser>=3.12,!=3.0.*')),
    ('tests/unit/scripts/test_dependency_compatibility_workflow.py::test_resolver_selection_excludes_only_frozen_release_cases', 'tests.unit.scripts.test_dependency_compatibility_workflow', 'test_resolver_selection_excludes_only_frozen_release_cases', 'tests/unit/scripts/test_dependency_compatibility_workflow.py', 97, ('assert len(deselections) == len(FROZEN_RELEASE_SELECTORS) + 2', 'AssertionError: assert 2 == (7 + 2)')),
    ('tests/unit/security/test_frozen_gitpython_compatibility.py::test_submodule_creation_validates_checkout_before_clone[absolute-metadata]', 'tests.unit.security.test_frozen_gitpython_compatibility', 'test_submodule_creation_validates_checkout_before_clone[absolute-metadata]', 'tests/unit/security/test_frozen_gitpython_compatibility.py', 166, ('assert result == {', "{'clone_calls': 1} != {'clone_calls': 0}", "{'boundary_reached': True} != {'boundary_reached': False}", "{'rejected': False} != {'rejected': True}")),
    ('tests/unit/security/test_frozen_gitpython_compatibility.py::test_submodule_creation_validates_checkout_before_clone[git-metadata]', 'tests.unit.security.test_frozen_gitpython_compatibility', 'test_submodule_creation_validates_checkout_before_clone[git-metadata]', 'tests/unit/security/test_frozen_gitpython_compatibility.py', 166, ('assert result == {', "{'clone_calls': 1} != {'clone_calls': 0}", "{'boundary_reached': True} != {'boundary_reached': False}", "{'rejected': False} != {'rejected': True}")),
    ('tests/unit/security/test_frozen_gitpython_compatibility.py::test_submodule_creation_validates_checkout_before_clone[git-short-name]', 'tests.unit.security.test_frozen_gitpython_compatibility', 'test_submodule_creation_validates_checkout_before_clone[git-short-name]', 'tests/unit/security/test_frozen_gitpython_compatibility.py', 166, ('assert result == {', "{'clone_calls': 1} != {'clone_calls': 0}", "{'boundary_reached': True} != {'boundary_reached': False}", "{'rejected': False} != {'rejected': True}")),
    ('tests/unit/scripts/test_dependency_trust_review.py::test_pycparser_has_current_exact_version_review_record', 'tests.unit.scripts.test_dependency_trust_review', 'test_pycparser_has_current_exact_version_review_record', 'tests/unit/scripts/test_dependency_trust_review.py', 49, ('assert pycparser["version"] == "3.12"', "assert '2.22' == '3.12'")),
    ('tests/unit/security/test_release_dependency_selection.py::test_reviewed_tooling_versions_match_frozen_export[gitpython-3.2.1]', 'tests.unit.security.test_release_dependency_selection', 'test_reviewed_tooling_versions_match_frozen_export[gitpython-3.2.1]', 'tests/unit/security/test_release_dependency_selection.py', 32, ('assert packages[0]["version"] == version', "assert '3.2.0' == '3.2.1'")),
    ('tests/unit/security/test_release_dependency_selection.py::test_reviewed_tooling_versions_match_frozen_export[packaging-26.3]', 'tests.unit.security.test_release_dependency_selection', 'test_reviewed_tooling_versions_match_frozen_export[packaging-26.3]', 'tests/unit/security/test_release_dependency_selection.py', 32, ('assert packages[0]["version"] == version', "assert '26.2' == '26.3'")),
    ('tests/unit/security/test_release_dependency_selection.py::test_reviewed_tooling_versions_match_frozen_export[pycparser-3.12]', 'tests.unit.security.test_release_dependency_selection', 'test_reviewed_tooling_versions_match_frozen_export[pycparser-3.12]', 'tests/unit/security/test_release_dependency_selection.py', 32, ('assert packages[0]["version"] == version', "assert '2.22' == '3.12'")),
    ('tests/unit/security/test_release_dependency_selection.py::test_reviewed_tooling_versions_match_frozen_export[python-discovery-1.6.1]', 'tests.unit.security.test_release_dependency_selection', 'test_reviewed_tooling_versions_match_frozen_export[python-discovery-1.6.1]', 'tests/unit/security/test_release_dependency_selection.py', 32, ('assert packages[0]["version"] == version', "assert '1.6.0' == '1.6.1'")),
    ('tests/unit/security/test_release_dependency_selection.py::test_reviewed_tooling_versions_match_frozen_export[virtualenv-21.14.12]', 'tests.unit.security.test_release_dependency_selection', 'test_reviewed_tooling_versions_match_frozen_export[virtualenv-21.14.12]', 'tests/unit/security/test_release_dependency_selection.py', 32, ('assert packages[0]["version"] == version', "assert '21.11.0' == '21.14.12'")),
)


class _OriginalPhase(Enum):
    NEW = 'new'
    PREPARED = 'prepared'
    IN_ROWS = 'in_rows'
    LIVE_COMPLETE = 'live_complete'
    UNWOUND = 'unwound'
    CLOSED = 'closed'
    FAILED = 'failed'


class _OwnerState(Enum):
    NOT_STARTED = 'not_started'
    RETURNED = 'returned'
    RAISED = 'raised'


@dataclass(frozen=True)
class _OwnerOutcome:
    state: _OwnerState
    value: bool | None
    error: BaseException | None


@dataclass(frozen=True)
class _Junit15Facts:
    selectors: tuple[str, ...]
    failures: int
    errors: int
    passes: int
    skips: int
    toolchain: tuple[tuple[str, str], ...]


@dataclass
class _OriginalProducts:
    plan: _CompleteOwnedRead | None = None
    planning_report: _CompleteOwnedRead | None = None
    planning_summary: _CompleteOwnedRead | None = None
    junit: _CompleteOwnedRead | None = None
    junit_facts: _Junit15Facts | None = None
    unbound_report: _CompleteOwnedRead | None = None
    red_summary: _CompleteOwnedRead | None = None
    bound_report: _CompleteOwnedRead | None = None


@dataclass(frozen=True)
class _BoundaryFacts:
    policy_main: str
    policy_parents: tuple[str, str]
    policy_tree: str
    core_main: str
    core_dev: str


@dataclass(frozen=True)
class _OriginalJoinFacts:
    integrity_complete: bool
    collector_plus_export_read_bytes: int
    payload_bytes: int
    files: tuple[tuple[str, int, str], ...]


@dataclass(frozen=True)
class _RootCleanup:
    role: str
    attempted: bool
    descriptor_closed: bool
    deleted: bool
    reason: str


@dataclass(frozen=True)
class _Original15Packet:
    complete: bool
    outcome: str
    cleanup: tuple[_RootCleanup, ...]
    diagnostics: tuple[str, ...]
    export_path: Path | None


class _OriginalProofError(RuntimeError):
    pass


class _OriginalProofNotImplemented(RuntimeError):
    pass


@dataclass(frozen=True)
class _OwnedRoot:
    path: Path
    descriptor: int
    device: int
    inode: int
    uid: int
    mode: int


@dataclass
class _AttemptAccount:
    root: _OwnedRoot
    deadline_ns: int
    secrets: tuple[bytes, ...]
    spent_bytes: int = 0
    read_bytes: int = 0
    retained_bytes: int = 0
    retained_members: int = 0
    metadata_visits: int = 0
    stopped: bool = False
    row_seconds: float = 0.0
    stream_bytes: int = 0
    retained_stream_bytes: int = 0
    last_direct: _DirectResult | None = None
    preparation: _OriginalRPreparation | None = None
    policy: Path | None = None
    original_output: Path | None = None
    export_path: Path | None = None
    phase: _OriginalPhase = _OriginalPhase.NEW
    products: _OriginalProducts = field(default_factory=_OriginalProducts)
    boundary_before: _BoundaryFacts | None = None
    boundary_after: _BoundaryFacts | None = None
    old_join: _OriginalJoinFacts | None = None
    live_entered: bool = False
    live_complete: bool = False
    unwound: bool = False
    final_started_ns: int | None = None
    final_deadline_ns: int | None = None
    finish_started: bool = False
    finish_complete: bool = False
    final_packet: _Original15Packet | None = None
    primary_error: BaseException | None = None
    api: object | None = None
    saved_transport: object | None = None
    saved_materializer: object | None = None
    restored: bool = False
    boundary_records: tuple[bytes, ...] = ()
    direct_results: tuple[_DirectResult, ...] = ()
    source_roots: tuple[Path, ...] = ()
    source_before: tuple[_CompleteOwnedRead, ...] = ()
    source_after: tuple[_CompleteOwnedRead, ...] = ()
    subjects: tuple[tuple, ...] = ()
    subject_roots: tuple[Path, ...] = ()
    tool_identity: tuple[tuple, ...] = ()
    live_metadata: tuple[bytes, ...] = ()
    metadata_bytes: int = 0
    closure_bytes: int = 0


@dataclass(frozen=True)
class _FileIdentity:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    links: int
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True)
class _CompleteOwnedRead:
    role: _SourceRole
    data: bytes
    sha256: str
    before: _FileIdentity
    opened: _FileIdentity
    after: _FileIdentity
    current: _FileIdentity


class _OwnedReadError(RuntimeError):
    pass


def _owned_require(condition: bool) -> None:
    if not condition:
        raise _OwnedReadError('Owned read refused')


def _owned_integer(value: int, upper: int, lower: int = 0) -> bool:
    return type(value) is int and lower <= value <= upper


def _owned_clock(account: _AttemptAccount) -> None:
    _owned_require(time.monotonic_ns() < account.deadline_ns)


def _owned_visit(account: _AttemptAccount) -> None:
    _owned_clock(account)
    _owned_require(account.metadata_visits < 64000)
    account.metadata_visits += 1


def _owned_root_check(account: _AttemptAccount) -> None:
    root = account.root
    path = Path(root.path.anchor)
    for component in root.path.parts[1:]:
        path = path / component
        _owned_visit(account)
        value = os.lstat(path)
        _owned_require(stat.S_ISDIR(value.st_mode))
    _owned_require((value.st_dev, value.st_ino, value.st_uid, value.st_mode)
                   == (root.device, root.inode, root.uid, root.mode))
    _owned_visit(account)
    value = os.fstat(root.descriptor)
    _owned_require((value.st_dev, value.st_ino, value.st_uid, value.st_mode)
                   == (root.device, root.inode, root.uid, root.mode))


def _owned_file_identity(value: os.stat_result) -> _FileIdentity:
    _owned_require(all(_owned_integer(number, 2**64 - 1) for number in (
        value.st_dev, value.st_ino, value.st_nlink, value.st_size)))
    _owned_require(all(_owned_integer(number, 2**32 - 1) for number in (
        value.st_mode, value.st_uid, value.st_gid)))
    _owned_require(all(_owned_integer(number, 2**63 - 1, -(2**63)) for number in (
        value.st_mtime_ns, value.st_ctime_ns)))
    _owned_require(stat.S_ISREG(value.st_mode) and value.st_uid == os.getuid()
                   and value.st_nlink == 1 and value.st_mode & 0o077 == 0
                   and value.st_size <= 8 * MIB)
    return _FileIdentity(value.st_dev, value.st_ino, value.st_mode, value.st_uid,
                         value.st_gid, value.st_nlink, value.st_size,
                         value.st_mtime_ns, value.st_ctime_ns)


def _read_owned(account: _AttemptAccount, role: _SourceRole) -> _CompleteOwnedRead:
    admitted = 0
    try:
        _owned_require(type(account) is _AttemptAccount)
        _owned_require(type(account.stopped) is bool and not account.stopped)
        _owned_require(type(role) is _SourceRole)
        if role.name.startswith(('SOURCE_', 'SUBJECT_')):
            return _read_fixed_source(account, role)
        _owned_require(type(account.root) is _OwnedRoot)
        root = account.root
        _owned_require(type(root.path) is type(Path()))
        _owned_require(_owned_integer(root.descriptor, 2**31 - 1))
        _owned_require(all(_owned_integer(number, 2**64 - 1)
                           for number in (root.device, root.inode)))
        _owned_require(all(_owned_integer(number, 2**32 - 1)
                           for number in (root.uid, root.mode)))
        _owned_require(root.uid == os.getuid() and root.mode == stat.S_IFDIR | 0o700)
        _owned_require(_owned_integer(account.deadline_ns, 2**63 - 1, 1))
        _owned_require(_owned_integer(account.spent_bytes, 255 * MIB)
                       and _owned_integer(account.read_bytes, 255 * MIB)
                       and account.read_bytes <= account.spent_bytes
                       and _owned_integer(account.retained_bytes, 16 * MIB)
                       and _owned_integer(account.retained_members, 64)
                       and _owned_integer(account.metadata_visits, 64000))
        _owned_require(type(account.secrets) is tuple and len(account.secrets) <= 32)
        _owned_require(all(type(secret) is bytes and 8 <= len(secret) <= 4096
                           for secret in account.secrets))
        name = str(root.path)
        depth = len(root.path.parts) - 1
        _owned_require(root.path.is_absolute() and root.path.anchor == '/'
                       and 1 <= depth <= 64 and len(os.fsencode(name)) <= 4096
                       and os.path.normpath(name) == name
                       and all(part not in ('.', '..') for part in root.path.parts[1:]))
        _owned_require(account.metadata_visits + 2 * depth + 6 <= 64000)
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        _owned_clock(account)
        _owned_root_check(account)
        _owned_visit(account)
        before = _proof_file_identity(os.stat(role.value, dir_fd=root.descriptor,
                                              follow_symlinks=False), role)
        size = before.size
        work = (len(account.secrets) + 4) * (size + 1)
        _owned_require(account.spent_bytes + work <= 255 * MIB
                       and account.retained_bytes + size <= 16 * MIB
                       and account.retained_members + 1 <= 64)
        admitted = work
        _owned_clock(account)
        descriptor = os.open(role.value, flags, dir_fd=root.descriptor)
        try:
            _owned_visit(account)
            opened = _proof_file_identity(os.fstat(descriptor), role)
            _owned_require(opened == before)
            _owned_clock(account)
            data = os.read(descriptor, size + 1)
            account.read_bytes += len(data)
            _owned_require(len(data) == size)
            _owned_clock(account)
            digest = hashlib.sha256(data).hexdigest()
            for secret in account.secrets:
                _owned_clock(account)
                _owned_require(secret not in data)
            _owned_clock(account)
            _owned_require(re.search(
                rb'(?i)(?:authorization\s*:\s*bearer |github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9]+|X-Amz-Signature=|sig=)',
                data) is None)
            _owned_visit(account)
            after = _proof_file_identity(os.fstat(descriptor), role)
            _owned_require(after == before)
            _owned_root_check(account)
            _owned_visit(account)
            current = _proof_file_identity(os.stat(role.value, dir_fd=root.descriptor,
                                                   follow_symlinks=False), role)
            _owned_require(current == before)
        finally:
            os.close(descriptor)
        _owned_clock(account)
        result = _CompleteOwnedRead(role, data, digest, before, opened, after, current)
        account.spent_bytes += (len(account.secrets) + 4) * size
        account.retained_bytes += size
        account.retained_members += 1
        return result
    except BaseException:
        if type(account) is _AttemptAccount:
            account.stopped = True
            if admitted:
                account.spent_bytes += admitted
        raise _OwnedReadError('Owned read refused') from None


@dataclass
class _OriginalRChild:
    path: Path
    created: bool = False
    descriptor: int | None = None
    device: int | None = None
    inode: int | None = None
    uid: int | None = None
    mode: int | None = None


@dataclass
class _OriginalRPreparation:
    started_ns: int
    deadline_ns: int
    root: _OriginalRChild | None = None
    home: _OriginalRChild | None = None
    tmp: _OriginalRChild | None = None
    template: _OriginalRChild | None = None
    repository_metadata: bytes | None = None
    parent_metadata: bytes | None = None
    commit_metadata: bytes | None = None
    complete: bool = False


@dataclass(frozen=True)
class _PreparedOriginalR:
    root: Path
    out: Path
    home: Path
    tmp: Path
    commit: str
    parent: str
    tree: str
    parent_tree: str
    raw_commit_sha256: str
    sources: tuple[tuple[str, str], ...]


class _OriginalRPreparationError(RuntimeError):
    pass


class _OriginalRNotImplemented(RuntimeError):
    pass


def _prepare_original_r(account, api):
    raise _OriginalRNotImplemented('NEW original R preparation is not implemented')



def _proof_require(condition):
    if not condition:
        raise _OriginalProofError('Fixed original15 refused')


def _proof_failed(account, error):
    if type(account) is _AttemptAccount:
        account.stopped = True
        account.live_complete = False
        account.phase = _OriginalPhase.FAILED
        if account.primary_error is None:
            account.primary_error = error


def _proof_final_clock(account):
    now = time.monotonic_ns()
    if account.final_started_ns is None:
        _proof_require(account.final_deadline_ns is None)
        account.final_started_ns = now
        account.final_deadline_ns = min(account.deadline_ns, now + 60_000_000_000)
    _proof_require(type(account.final_deadline_ns) is int
                   and account.final_deadline_ns <= account.final_started_ns + 60_000_000_000
                   and now < min(account.deadline_ns, account.final_deadline_ns))


def _proof_charge(account, amount, *, closure=False):
    _proof_require(type(amount) is int and amount >= 0)
    if account.unwound or account.finish_started:
        _proof_final_clock(account)
    else:
        _owned_clock(account)
    limit = 256 * MIB if closure else 255 * MIB
    _proof_require(account.spent_bytes + amount <= limit)
    if closure:
        _proof_require(account.closure_bytes + amount <= MIB)
        account.closure_bytes += amount
    account.spent_bytes += amount


def _proof_safe(account, raw):
    _proof_require(not any(secret in raw for secret in account.secrets)
                   and re.search(rb'(?i)(?:authorization\s*:\s*bearer |github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9]+|X-Amz-Signature=|sig=)', raw) is None)


def _proof_file_identity(value, role):
    if role is not _SourceRole.JUNIT:
        return _owned_file_identity(value)
    _owned_require(stat.S_ISREG(value.st_mode) and value.st_uid == os.getuid()
                   and value.st_nlink == 1 and value.st_mode & 0o077 == 0
                   and 0 <= value.st_size <= 10 * MIB)
    return _FileIdentity(value.st_dev, value.st_ino, value.st_mode, value.st_uid,
                         value.st_gid, value.st_nlink, value.st_size,
                         value.st_mtime_ns, value.st_ctime_ns)


def _read_fixed_source(account, role):
    if role.name.startswith('SOURCE_'):
        index = int(role.name.removeprefix('SOURCE_'))
        label, relative, expected_digest = _FIXED_SOURCES[index]
        _proof_require(len(account.source_roots) == 4 and not account.stopped)
        root = account.source_roots[('P', 'C', 'M', 'R').index(label)]
    else:
        _, number, member = role.name.split('_')
        _proof_require(len(account.subject_roots) == 3 and not account.stopped)
        root = account.subject_roots[int(number)]
        relative = {'REQUIREMENT': 'gitpython.txt',
                    'GITPYTHON': 'delivery-package/gitpython-3.2.0.dist-info/METADATA',
                    'GITDB': 'delivery-package/gitdb-4.0.12.dist-info/METADATA',
                    'SMMAP': 'delivery-package/smmap-5.0.3.dist-info/METADATA',
                    'INIT': 'delivery-package/git/__init__.py',
                    'BASE': 'delivery-package/git/objects/submodule/base.py'}[member]
        expected_digest = None
    _proof_require(root.is_absolute() and root.resolve(strict=True) == root)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    parents = [descriptor]
    try:
        for part in relative.split('/')[:-1]:
            _owned_visit(account)
            descriptor = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            parents.append(descriptor)
        name = relative.split('/')[-1]
        def identity(value):
            _proof_require(stat.S_ISREG(value.st_mode) and value.st_uid == os.getuid()
                           and value.st_nlink >= 1
                           and (role.name.startswith('SUBJECT_') or value.st_nlink == 1)
                           and not value.st_mode & 0o022
                           and 0 <= value.st_size <= 4 * MIB)
            return _FileIdentity(value.st_dev, value.st_ino, value.st_mode, value.st_uid,
                                 value.st_gid, value.st_nlink, value.st_size,
                                 value.st_mtime_ns, value.st_ctime_ns)
        _owned_visit(account)
        before = identity(os.stat(name, dir_fd=descriptor, follow_symlinks=False))
        _proof_require(account.retained_bytes + before.size <= 16 * MIB)
        _proof_charge(account, (len(account.secrets) + 4) * (before.size + 1))
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        try:
            _owned_visit(account)
            opened = identity(os.fstat(fd))
            _proof_require(opened == before)
            raw = os.read(fd, before.size + 1)
            account.read_bytes += len(raw)
            _proof_require(len(raw) == before.size)
            _proof_safe(account, raw)
            _owned_visit(account)
            after = identity(os.fstat(fd))
            _owned_visit(account)
            current = identity(os.stat(name, dir_fd=descriptor, follow_symlinks=False))
            _proof_require(before == opened == after == current and (expected_digest is None or sha(raw) == expected_digest))
        finally:
            os.close(fd)
        _owned_clock(account)
        account.retained_bytes += len(raw)
        return _CompleteOwnedRead(role, raw, sha(raw), before, opened, after, current)
    finally:
        for fd in reversed(parents):
            os.close(fd)


def _junit_original15(account, member):
    try:
        _proof_require(not account.stopped and type(member) is _CompleteOwnedRead
                       and member.role is _SourceRole.JUNIT
                       and member.before == member.opened == member.after == member.current
                       and member.before.size == len(member.data))
        _proof_charge(account, 8 * (len(member.data) + 1))
        _proof_require(sha(member.data) == member.sha256)
        parser = expat.ParserCreate()
        stack, cases = [], []
        elements = 0
        current = None
        suite_seen = False
        root_seen = False
        def forbidden(*args):
            raise _OriginalProofError('Fixed XML declaration refused')
        def declaration(version, encoding, standalone):
            _proof_require(version == '1.0' and encoding == 'utf-8' and standalone == -1)
        def start(name, attrs):
            nonlocal elements, current, suite_seen, root_seen
            elements += 1
            _proof_require(elements <= 20000 and len(stack) < 32 and len(attrs) <= 32
                           and all(len(k.encode()) <= 4096 and len(v.encode()) <= 4096
                                   for k, v in attrs.items()))
            parent = stack[-1] if stack else None
            if name == 'testsuites':
                _proof_require(parent is None and not root_seen)
                root_seen = True
            elif name == 'testsuite':
                _proof_require(parent == 'testsuites' and not suite_seen
                               and attrs.get('name') == 'pytest'
                               and all(attrs.get(k) == v for k, v in
                                       (('tests', '15'), ('failures', '15'), ('errors', '0'), ('skipped', '0'))))
                suite_seen = True
            elif name == 'testcase':
                _proof_require(parent == 'testsuite' and current is None and len(cases) < 15)
                current = {'attrs': attrs, 'properties': {}, 'failure': [], 'message': None, 'groups': 0}
            elif name == 'properties':
                _proof_require(parent == 'testcase' and current['groups'] == 0)
                current['groups'] += 1
            elif name == 'property':
                _proof_require(parent == 'properties' and set(attrs) == {'name', 'value'}
                               and attrs['name'] not in current['properties'] and attrs['value'])
                current['properties'][attrs['name']] = attrs['value']
            elif name == 'failure':
                _proof_require(parent == 'testcase' and current['message'] is None)
                current['message'] = attrs.get('message', '')
            elif name in ('system-out', 'system-err'):
                _proof_require(parent in ('testcase', 'testsuite'))
            else:
                forbidden()
            stack.append(name)
        def end(name):
            nonlocal current
            _proof_require(stack and stack.pop() == name)
            if name == 'testcase':
                cases.append(current)
                current = None
        def data(text):
            if stack and stack[-1] == 'failure':
                current['failure'].append(text)
            elif stack and stack[-1] not in ('system-out', 'system-err'):
                _proof_require(not text.strip())
        parser.StartElementHandler, parser.EndElementHandler = start, end
        parser.CharacterDataHandler = data
        parser.XmlDeclHandler = declaration
        parser.StartDoctypeDeclHandler = forbidden
        parser.EntityDeclHandler = forbidden
        parser.ExternalEntityRefHandler = forbidden
        parser.ProcessingInstructionHandler = forbidden
        parser.Parse(member.data, True)
        _proof_require(root_seen and suite_seen and not stack and len(cases) == 15)
        for case, expected_case in zip(cases, _FIXED_CASES):
            selector, classname, name, source, line, markers = expected_case
            _proof_require(case['attrs'].get('classname') == classname and case['attrs'].get('name') == name
                           and case['properties'] == {'specfact.selector': selector, 'specfact.runner': 'pytest',
                               'specfact.python': '3.12.15', 'specfact.pytest': '9.1.1'}
                           and case['message'] is not None and 'AssertionError' in case['message'])
            body = ''.join(case['failure'])
            lines = [part.strip() for part in body.splitlines() if part.strip()]
            _proof_require(lines and lines[-1] == f'{source}:{line}: AssertionError'
                           and 'AssertionError' in body and all(marker in body for marker in markers))
        _owned_clock(account)
        return _Junit15Facts(tuple(case[0] for case in _FIXED_CASES), 15, 0, 0, 0,
                             (('runner', 'pytest'), ('python', '3.12.15'), ('pytest', '9.1.1')))
    except BaseException as error:
        _proof_failed(account, error)
        raise _OriginalProofError('Fixed original15 XML refused') from None


def _check_products(account, stage):
    try:
        _proof_require(type(account) is _AttemptAccount and not account.stopped
                       and type(stage) is _OriginalStage)
        products = account.products
        def parsed(member):
            _proof_charge(account, 5 * (len(member.data) + 1))
            return sys.modules['late_cycle_admission'].json_object(member.data)
        if stage is _OriginalStage.PLANNER:
            _proof_require(products.plan is None and products.planning_report is None)
            plan = _read_owned(account, _SourceRole.PLAN)
            report = _read_owned(account, _SourceRole.PLANNING_REPORT)
            _proof_require(plan.sha256 == '8d24130f0cb8bfb70bd9f6d157b646cad15a210af3b93609b64582bf11d53900'
                           and report.sha256 == '7da297b8feb57bb9b813f6b5336d9bfa0d8a3303e7dcb61b8613619ead4d4fbb')
            parsed(plan)
            parsed(report)
            summary = _read_owned(account, _SourceRole.PLANNING_SUMMARY)
            products.plan, products.planning_report, products.planning_summary = plan, report, summary
        elif stage is _OriginalStage.EXECUTOR:
            _proof_require(products.plan is not None and products.junit is None)
            member = _read_owned(account, _SourceRole.JUNIT)
            facts = _junit_original15(account, member)
            products.junit, products.junit_facts = member, facts
        elif stage is _OriginalStage.RECONCILER:
            _proof_require(products.junit_facts is not None and products.unbound_report is None)
            member = _read_owned(account, _SourceRole.REPORT)
            report = parsed(member)
            proof = report['execution_proof']
            _proof_require(proof['junit_digest'] == 'sha256:' + products.junit.sha256)
            proof['junit_digest'] = 'sha256:' + '0' * 64
            normalized = encoded(report)
            _proof_require(sha(normalized) == '245a767e3054d1fbfe0a05c533be971d6adccb309fd330904554831a20a57690')
            _proof_charge(account, len(member.data))
            _proof_require(account.retained_bytes + len(member.data) <= 16 * MIB)
            _owned_root_check(account)
            fd = os.open(_SourceRole.UNBOUND_REPORT.value,
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                         dir_fd=account.root.descriptor)
            try:
                _proof_require(os.write(fd, member.data) == len(member.data))
            finally:
                os.close(fd)
            account.retained_bytes += len(member.data)
            frozen = _read_owned(account, _SourceRole.UNBOUND_REPORT)
            _proof_charge(account, len(member.data))
            _proof_require(frozen.data == member.data)
            summary = _read_owned(account, _SourceRole.RED_SUMMARY)
            products.unbound_report, products.red_summary = frozen, summary
        else:
            _proof_require(products.unbound_report is not None and products.bound_report is None)
            member = _read_owned(account, _SourceRole.REPORT)
            bound, original = parsed(member), parsed(products.unbound_report)
            proof = bound['execution_proof']
            additions = {'source_tree': 'baeb88acf0d2a5015810ad12dbfccfa7fdf9a21e', 'merge_base': C,
                         'test_file_digests': {path: 'sha256:' + digest for label, path, digest in _FIXED_SOURCES
                                               if label == 'R' and path.startswith('tests/')},
                         'toolchain_identity': {'runner': 'pytest', 'python': '3.12.15', 'pytest': '9.1.1'}}
            for key, expected_value in additions.items():
                _proof_require(key not in original['execution_proof'] and proof.pop(key) == expected_value)
            _proof_require(bound == original)
            products.bound_report = member
    except BaseException as error:
        _proof_failed(account, error)
        raise _OriginalProofError('Fixed original15 products refused') from None


def _check_current_boundary(account, api):
    try:
        _proof_require(type(account) is _AttemptAccount and not account.stopped)
        if account.unwound:
            _proof_final_clock(account)
        expiry = datetime(2026, 11, 4, 23, tzinfo=timezone.utc)
        _proof_require(datetime.now(timezone.utc) < expiry)
        _proof_require((account.boundary_after if account.unwound else account.boundary_before) is None)
        if account.saved_transport is not None:
            _proof_require(api.GitHub._https_get is account.saved_transport)
        client = api.GitHub()
        if account.saved_transport is not None:
            _proof_require(client._https_get.__func__ is account.saved_transport)
        policy_main = '640549e62fb3ca001499e71d4cf935aa8c0a0192'
        paths = ('/repos/nold-ai/.github', '/repos/nold-ai/specfact-cli',
                 '/repos/nold-ai/.github/git/ref/heads/main',
                 '/repos/nold-ai/.github/git/commits/' + policy_main,
                 '/repos/nold-ai/specfact-cli/git/ref/heads/main',
                 '/repos/nold-ai/specfact-cli/git/ref/heads/dev')
        values, records = [], []
        for path in paths:
            _proof_charge(account, 0)
            _proof_require(account.spent_bytes + (len(account.secrets) + 3) * 4 * MIB <= 255 * MIB)
            raw = client.get(path)
            _proof_require(type(raw) is bytes)
            account.read_bytes += len(raw)
            _proof_charge(account, (len(account.secrets) + 3) * len(raw))
            _proof_require(len(raw) <= 4 * MIB and account.metadata_bytes + getattr(account.preparation, 'metadata_bytes', 0) + len(raw) <= 8 * MIB - 65536)
            _proof_safe(account, raw)
            values.append(sys.modules['late_cycle_admission'].json_object(raw))
            records.append(raw)
            account.metadata_bytes += len(raw)
        for value, name, number in zip(values[:2], ('nold-ai/.github', 'nold-ai/specfact-cli'),
                                       (1110267669, 1085706003)):
            _proof_require(type(value.get('id')) is int and value['id'] == number
                           and value.get('full_name') == name and value['owner'].get('login') == 'nold-ai'
                           and type(value['owner'].get('id')) is int and value['owner']['id'] == 225190663)
        for value, branch, commit in ((values[2], 'main', policy_main),
                                      (values[4], 'main', '5262efb0881e4fac7697d629b0530250342bc656'),
                                      (values[5], 'dev', C)):
            _proof_require(value.get('ref') == 'refs/heads/' + branch
                           and value['object'].get('type') == 'commit' and value['object'].get('sha') == commit)
        commit = values[3]
        parents = ('9f952f1bc591b9d58403a8a362ce9fe21fdfe47d', P)
        tree = '2d27c800651b3e1b30d46078594a61937410f4cc'
        _proof_require(commit.get('sha') == policy_main and commit['tree'].get('sha') == tree
                       and tuple(p['sha'] for p in commit['parents']) == parents
                       and type(commit.get('verification')) is dict)
        _proof_require(datetime.now(timezone.utc) < expiry)
        _proof_charge(account, 0)
        facts = _BoundaryFacts(policy_main, parents, tree, values[4]['object']['sha'], values[5]['object']['sha'])
        if account.unwound:
            account.boundary_after = facts
        else:
            account.boundary_before = facts
        account.boundary_records += tuple(records)
        return facts
    except BaseException as error:
        _proof_failed(account, error)
        raise _OriginalProofError('Fixed current boundary refused') from None


def _verify_original_r_live(account, prepared, tool, timer):
    raise NotImplementedError('Fixed live R verification awaits shared preparation owner integration')


def _original15(account, prepared, tool, timer):
    saved_umask = None
    try:
        _proof_require(type(account) is _AttemptAccount and not account.stopped
                       and account.phase is _OriginalPhase.PREPARED and not account.live_entered
                       and type(prepared) is _PreparedOriginalR
                       and type(account.preparation) is _OriginalRPreparation and account.preparation.complete
                       and account.boundary_before is not None and account.api is not None
                       and account.api.materialization.materialize_native_tool is account.saved_materializer
                       and type(tool) is account.api.materialization.NativeTool)
        account.live_entered = True
        account.phase = _OriginalPhase.IN_ROWS
        owner_end = timer.end
        def safe_point():
            timer.check()
            _proof_require(not account.stopped and not timer.pending and not timer.expired
                           and timer.end == owner_end and time.monotonic() < owner_end)
            _owned_clock(account)
        safe_point()
        _proof_require(prepared.root == account.preparation.root.path
                       and prepared.out == account.root.path and prepared.home == account.preparation.home.path
                       and prepared.tmp == account.preparation.tmp.path
                       and prepared.commit == '4ae6175a4d337296d0347e73b66c9da1f0e43f7f'
                       and prepared.parent == C and prepared.tree == 'baeb88acf0d2a5015810ad12dbfccfa7fdf9a21e'
                       and prepared.parent_tree == '24112d8c9983333f9059283965230348f718b74c'
                       and prepared.raw_commit_sha256 == '43f81bdc267a38928838620dd35a741e6329d46243fc78a9160a7a7ee3913a2e'
                       and prepared.sources == tuple((path, digest) for label, path, digest in _FIXED_SOURCES if label == 'R'))
        account.source_roots = (account.policy, tool.core_root, tool.modules_root, prepared.root)
        def sources():
            for name in MODULES:
                module = sys.modules[name]
                expected_path = account.policy / '.github/scripts' / (name + '.py')
                _proof_require(module.__file__ == str(expected_path) and module.__spec__.origin == str(expected_path)
                               and expected_path.resolve(strict=True) == expected_path)
            return tuple(_read_owned(account, _SourceRole[f'SOURCE_{i:02d}']) for i in range(33))
        account.source_before = sources()
        def caches():
            records = []
            for label, root in zip(('C', 'M', 'R'), account.source_roots[1:]):
                def walk(directory, depth, in_cache=False):
                    _proof_require(depth <= 64)
                    with os.scandir(directory) as entries:
                        for entry in entries:
                            safe_point()
                            _owned_visit(account)
                            if entry.is_dir(follow_symlinks=False):
                                if entry.name != '.git':
                                    walk(Path(entry.path), depth + 1,
                                         in_cache or entry.name in ('__pycache__', '.pytest_cache'))
                            elif in_cache or entry.name.endswith('.pyc'):
                                _proof_require(entry.is_file(follow_symlinks=False))
                                value = entry.stat(follow_symlinks=False)
                                _proof_require(value.st_size <= 8 * MIB and value.st_uid == os.getuid())
                                _proof_charge(account, 2 * (value.st_size + 1))
                                fd = os.open(entry.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                                try:
                                    before = os.fstat(fd)
                                    _proof_require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                                                   == (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns))
                                    raw = os.read(fd, value.st_size + 1)
                                    account.read_bytes += len(raw)
                                    after = os.fstat(fd)
                                    _proof_require(len(raw) == value.st_size
                                                   and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                                                   == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))
                                finally:
                                    os.close(fd)
                                records.append((label, str(Path(entry.path).relative_to(root)), len(raw), sha(raw)))
                walk(root, 0)
            raw = encoded(records)
            _proof_charge(account, len(raw))
            _proof_require(account.metadata_bytes + getattr(account.preparation, 'metadata_bytes', 0) + len(raw) <= 8 * MIB - 65536)
            account.metadata_bytes += len(raw)
            return raw
        account.live_metadata += (caches(),)
        source_raw = {m.role: m.data for m in account.source_before}
        pins = {}
        for index in (4, 6):
            for package, version in re.findall(rb'^([A-Za-z0-9_.-]+)==([^\s;]+)',
                                                source_raw[_SourceRole[f'SOURCE_{index:02d}']], re.M):
                name = re.sub(rb'[-_.]+', b'-', package).lower().decode()
                version = version.decode()
                _proof_require(name not in pins or pins[name] == version)
                pins[name] = version
        _proof_require(len(pins) == 57 and tool.inventory == tuple(sorted(pins.items()))
                       and pins['gitpython'] == '3.2.1' and pins['pytest'] == '9.1.1'
                       and tool.manifest_sha256 == RELEASE['tool-files.json']
                       and tool.runtime_descriptor_sha256 == RELEASE['runtime.json'])
        _proof_charge(account, 5 * len(source_raw[_SourceRole.SOURCE_09]))
        descriptor = sys.modules['late_cycle_admission'].json_object(source_raw[_SourceRole.SOURCE_09])
        diagnostics = dict(tool.diagnostic_identity)
        _proof_require(len(diagnostics) == len(tool.diagnostic_identity)
                       and diagnostics['core.commit'] == C
                       and diagnostics['core.tree'] == '24112d8c9983333f9059283965230348f718b74c'
                       and diagnostics['modules.commit'] == M
                       and diagnostics['modules.tree'] == '5d0b8e66c6cd467e6b1ad9d582e24c66b907e205')
        _proof_require(tool.python.name == 'python' and tool.python.parent.name == 'bin'
                       and tool.site_packages == tool.python.parent.parent / 'lib/python3.12/site-packages'
                       and tool.site_packages.resolve(strict=True) == tool.site_packages
                       and shutil.which('uv', path=str(tool.uv.parent) + ':/usr/bin:/bin') == str(tool.uv))
        git = Path(shutil.which('git', path='/usr/bin:/bin')).resolve(strict=True)
        _proof_require(diagnostics['git_path'] == str(git)
                       and re.fullmatch(r'git version \d+\.\d+[^\r\n]*', diagnostics['git_version']) is not None)
        binary_rows = []
        for role, spelling in (('python', tool.python), ('uv', tool.uv), ('gh', tool.gh), ('git', git)):
            safe_point()
            resolved = spelling.resolve(strict=True)
            _owned_visit(account)
            before = resolved.lstat()
            fields = lambda v: (v.st_dev, v.st_ino, v.st_mode, v.st_uid, v.st_gid,
                                v.st_nlink, v.st_size, v.st_mtime_ns, v.st_ctime_ns)
            _proof_require(stat.S_ISREG(before.st_mode) and before.st_mode & 0o111
                           and not before.st_mode & 0o022 and 0 < before.st_size <= 64 * MIB)
            _proof_charge(account, 2 * before.st_size)
            fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            digest, total = hashlib.sha256(), 0
            try:
                _owned_visit(account)
                _proof_require(fields(os.fstat(fd)) == fields(before))
                while total < before.st_size:
                    safe_point()
                    raw = os.read(fd, min(65536, before.st_size - total))
                    account.read_bytes += len(raw)
                    _proof_require(bool(raw))
                    total += len(raw)
                    digest.update(raw)
                _owned_visit(account)
                _proof_require(fields(os.fstat(fd)) == fields(before))
            finally:
                os.close(fd)
            _owned_visit(account)
            _proof_require(fields(resolved.lstat()) == fields(before))
            expected_digest = diagnostics['git_sha256'] if role == 'git' else descriptor['assets'][role]['binary_sha256']
            _proof_require(digest.hexdigest() == expected_digest)
            if role != 'git':
                _proof_require(diagnostics[role + '.binary_sha256'] == expected_digest)
            binary_rows.append((role, str(spelling), str(resolved), expected_digest, fields(before)))
        account.tool_identity = tuple(binary_rows)
        vectors = _original_vectors(tool, prepared)
        _proof_require(len(vectors) == 4 and tuple(v.stage for v in vectors) == tuple(_OriginalStage)
                       and tuple(v.expected_exit for v in vectors) == (0, 1, 0, 0)
                       and tuple(v.seconds for v in vectors) == (120, 660, 120, 120))
        _verify_original_r_live(account, prepared, tool, timer)
        safe_point()
        saved_umask = os.umask(0o077)
        for vector in vectors:
            safe_point()
            _proof_require(len(account.direct_results) == list(_OriginalStage).index(vector.stage))
            result = _run_original_stage(account, tool, prepared, timer, vector.stage)
            safe_point()
            _proof_require(type(result) is _DirectResult and account.last_direct is result
                           and result.stage is vector.stage and result.vector == vector
                           and result.cleanup_complete and not result.deadline_seen
                           and result.waitid is not None and result.waitid[1:] == (os.CLD_EXITED, vector.expected_exit)
                           and result.wait_status is not None and os.WIFEXITED(result.wait_status)
                           and os.WEXITSTATUS(result.wait_status) == vector.expected_exit
                           and result.started <= result.ended < result.deadline <= owner_end)
            account.direct_results += (result,)
            _check_products(account, vector.stage)
            if vector.stage is _OriginalStage.EXECUTOR:
                _capture_original_subjects(account, prepared)
            safe_point()
        account.source_after = sources()
        _proof_require(tuple((m.role, m.sha256, m.before) for m in account.source_before)
                       == tuple((m.role, m.sha256, m.before) for m in account.source_after))
        for role, spelling, resolved, digest, identity in account.tool_identity:
            safe_point()
            _owned_visit(account)
            _proof_require(str(Path(spelling).resolve(strict=True)) == resolved
                           and fields(Path(resolved).lstat()) == identity)
        _proof_require(tool.inventory == tuple(sorted(pins.items())))
        _verify_original_r_live(account, prepared, tool, timer)
        safe_point()
        account.live_metadata += (caches(),)
        account.live_metadata += (encoded({'binary_identities': account.tool_identity,
                                          'inventory': tool.inventory,
                                          'native_subject_distinction': 'Native GitPython 3.2.1; three original targets 3.2.0'}),)
        _proof_charge(account, len(account.live_metadata[-1]))
        account.metadata_bytes += len(account.live_metadata[-1])
        _proof_require(account.metadata_bytes + getattr(account.preparation, 'metadata_bytes', 0) <= 8 * MIB - 65536)
        account.live_complete = True
        account.phase = _OriginalPhase.LIVE_COMPLETE
    except BaseException as error:
        _proof_failed(account, error)
        raise _OriginalProofError('Fixed original15 live proof refused') from None
    finally:
        if saved_umask is not None:
            os.umask(saved_umask)


def _capture_original_subjects(account, prepared):
    _proof_require(not account.subject_roots and not account.subjects)
    roots = []
    with os.scandir(prepared.tmp) as entries:
        for entry in entries:
            _owned_visit(account)
            if entry.name.startswith('pytest-of-'):
                _proof_require(entry.is_dir(follow_symlinks=False))
                roots.append(Path(entry.path))
    _proof_require(len(roots) == 1)
    sessions = []
    with os.scandir(roots[0]) as entries:
        for entry in entries:
            _owned_visit(account)
            if re.fullmatch(r'pytest-\d+', entry.name):
                _proof_require(entry.is_dir(follow_symlinks=False))
                sessions.append(Path(entry.path))
    _proof_require(len(sessions) == 1)
    prefix = 'test_submodule_creation_validates_checkout_before_clone'[:30]
    cases = {}
    with os.scandir(sessions[0]) as entries:
        for entry in entries:
            _owned_visit(account)
            if re.fullmatch(re.escape(prefix) + r'\d+', entry.name):
                _proof_require(entry.is_dir(follow_symlinks=False))
                cases[entry.name] = Path(entry.path)
    _proof_require(set(cases) == {prefix + str(i) for i in range(3)})
    account.subject_roots = tuple(cases[prefix + str(i)] for i in range(3))
    locked = next(member.data for member in account.source_before if member.role is _SourceRole.SOURCE_18).decode()
    requirement = ''
    for package in ('gitdb', 'gitpython', 'smmap'):
        entries = re.findall(rf'(?m)^{package}==([^\s]+) \\\n((?:[ \t]+--hash=sha256:[0-9a-f]{{64}}(?: \\)?\n)+)', locked)
        _proof_require(len(entries) == 1)
        version, hashes = entries[0]
        requirement += f'{package}=={version} \\\n{hashes}'
    records = []
    for index in range(3):
        members = tuple(_read_owned(account, _SourceRole[f'SUBJECT_{index}_{name}'])
                        for name in ('REQUIREMENT', 'GITPYTHON', 'GITDB', 'SMMAP', 'INIT', 'BASE'))
        _proof_require(members[0].data == requirement.encode())
        for member, name, version in zip(members[1:4], ('gitpython', 'gitdb', 'smmap'), ('3.2.0', '4.0.12', '5.0.3')):
            _proof_charge(account, 3 * len(member.data))
            text = member.data.decode('utf-8')
            names = re.findall(r'^Name: (.+)$', text, re.M)
            versions = re.findall(r'^Version: (.+)$', text, re.M)
            _proof_require(len(names) == 1 and re.sub('[-_.]+', '-', names[0]).lower() == name
                           and versions == [version])
        records.append((index, str(account.subject_roots[index]), requirement,
                        tuple((member.role.name, len(member.data), member.sha256, asdict(member.before))
                              for member in members),
                        (('gitpython', '3.2.0'), ('gitdb', '4.0.12'), ('smmap', '5.0.3'))))
    account.subjects = tuple(records)


def _finish_original15(account, original, published):
    _proof_require(type(account) is _AttemptAccount and not account.finish_started)
    account.finish_started = True
    diagnostics, cleanup = [], []
    export_fd = footer_fd = None
    footer_started = False
    complete = False
    files = []
    def fault(code, error=None):
        nonlocal complete
        complete = False
        account.stopped = True
        account.live_complete = False
        if code not in diagnostics and len(diagnostics) < 24:
            diagnostics.append(code)
        if error is not None and account.primary_error is None:
            account.primary_error = error
    def owner_valid(outcome):
        return (type(outcome) is _OwnerOutcome and
                ((outcome.state is _OwnerState.NOT_STARTED and outcome.value is None and outcome.error is None)
                 or (outcome.state is _OwnerState.RETURNED and type(outcome.value) is bool and outcome.error is None)
                 or (outcome.state is _OwnerState.RAISED and outcome.value is None
                     and isinstance(outcome.error, BaseException))))
    def footer(value):
        raw = encoded(value)
        _proof_require(len(raw) <= 65536)
        _proof_charge(account, (len(account.secrets) + 2) * len(raw), closure=True)
        _proof_safe(account, raw)
        return raw
    try:
        _proof_final_clock(account)
        _proof_require(owner_valid(original) and owner_valid(published))
        if account.primary_error is None:
            account.primary_error = original.error or published.error
        _proof_require(account.export_path is not None and account.original_output is not None
                       and account.export_path.parent == account.root.path.parent
                       and account.export_path not in (account.original_output, account.root.path)
                       and account.export_path.parent.resolve(strict=True) == account.export_path.parent)
        account.export_path.mkdir(mode=0o700, exist_ok=False)
        export_fd = os.open(account.export_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        export_identity = os.fstat(export_fd)
        current = account.export_path.lstat()
        _proof_require((current.st_dev, current.st_ino) == (export_identity.st_dev, export_identity.st_ino)
                       and current.st_uid == os.getuid() and current.st_mode == stat.S_IFDIR | 0o700)
        footer_fd = os.open('closure.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                            0o600, dir_fd=export_fd)
        raw = footer({'complete': False, 'outcome': 'Incomplete', 'cleanup': []})
        _proof_require(os.write(footer_fd, raw) == len(raw))
        footer_started = True
        if published.state is _OwnerState.RETURNED and published.value is True:
            account.old_join = _OriginalJoinFacts(False, 0, 0, ())
            old_fd = None
            try:
                _proof_final_clock(account)
                old_path = account.original_output / 'export'
                _proof_require(old_path.resolve(strict=True) == old_path)
                old_fd = os.open(old_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                old_identity = os.fstat(old_fd)
                _proof_require(stat.S_ISDIR(old_identity.st_mode) and old_identity.st_uid == os.getuid()
                               and not old_identity.st_mode & 0o077)
                def read_member(name, limit, keep=False):
                    _proof_final_clock(account)
                    _owned_visit(account)
                    before = os.stat(name, dir_fd=old_fd, follow_symlinks=False)
                    _proof_require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                                   and before.st_nlink == 1 and not before.st_mode & 0o022
                                   and 0 <= before.st_size <= limit)
                    _proof_charge(account, (len(account.secrets) + 3) * (before.st_size + 1))
                    fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=old_fd)
                    identity = lambda v: (v.st_dev, v.st_ino, v.st_mode, v.st_uid, v.st_gid,
                                          v.st_nlink, v.st_size, v.st_mtime_ns, v.st_ctime_ns)
                    total, digest, chunks, tail = 0, hashlib.sha256(), [], b''
                    try:
                        _owned_visit(account)
                        _proof_require(identity(os.fstat(fd)) == identity(before))
                        while total < before.st_size:
                            _proof_final_clock(account)
                            chunk = os.read(fd, min(65536, before.st_size - total))
                            account.read_bytes += len(chunk)
                            _proof_require(bool(chunk))
                            total += len(chunk)
                            digest.update(chunk)
                            _proof_charge(account, (len(account.secrets) + 2) * len(tail))
                            _proof_safe(account, tail + chunk)
                            tail = (tail + chunk)[-8192:]
                            if keep:
                                chunks.append(chunk)
                        _owned_visit(account)
                        _proof_require(identity(os.fstat(fd)) == identity(before))
                        _owned_visit(account)
                        _proof_require(identity(os.stat(name, dir_fd=old_fd, follow_symlinks=False)) == identity(before))
                    finally:
                        os.close(fd)
                    return total, digest.hexdigest(), b''.join(chunks) if keep else None
                summary_size, summary_digest, summary_raw = read_member('export.json', 65536, True)
                _proof_charge(account, 5 * summary_size)
                summary = sys.modules['late_cycle_admission'].json_object(summary_raw)
                _proof_require(set(summary) == {'development_diagnostics_only', 'withheld',
                    'public_evidence_complete', 'files', 'raw_payload_bytes',
                    'collector_plus_export_read_bytes', 'export_read_bytes'}
                    and summary['development_diagnostics_only'] is True
                    and summary['withheld'] == [] and summary['public_evidence_complete'] is True
                    and type(summary['files']) is list and len(summary['files']) <= 63
                    and _owned_integer(summary['raw_payload_bytes'], 48 * MIB - 65536)
                    and _owned_integer(summary['collector_plus_export_read_bytes'], 512 * MIB)
                    and _owned_integer(summary['export_read_bytes'], summary['collector_plus_export_read_bytes']))
                allowed_dirs = ('caller-exception', 'collector-exception', 'collector-timeout', 'before-logs',
                                'failed-command', 'live-command-timeout', 'over-limit-receipt',
                                'acquisition-deadline', 'cleanup-signal', 'materialization')
                allowed = {'creation-deadline.json', 'controls.json', 'wrong-descriptor.json',
                           'moved-main.json', 'corrupt-input.json', 'actual-failure.json'}
                allowed.update(directory + '--' + member for directory in allowed_dirs
                               for member in ('manifest.json', 'environments.json', 'commands.jsonl', 'raw-output.bin'))
                records, names, total = [], set(), 0
                for record in summary['files']:
                    _proof_require(type(record) is dict and set(record) == {'file', 'bytes', 'sha256'})
                    name = record['file']
                    _proof_require(type(name) is str and name in allowed and name not in names
                                   and _owned_integer(record['bytes'], 48 * MIB)
                                   and type(record['sha256']) is str
                                   and re.fullmatch('[0-9a-f]{64}', record['sha256']) is not None)
                    names.add(name)
                    limit = 16 * MIB if name.endswith('--manifest.json') else 48 * MIB
                    size, digest, _ = read_member(name, limit)
                    _proof_require((size, digest) == (record['bytes'], record['sha256']))
                    total += size
                    _proof_require(total + summary_size <= 48 * MIB)
                    records.append((name, size, digest))
                actual_names = set()
                with os.scandir(old_fd) as entries:
                    for entry in entries:
                        _owned_visit(account)
                        _proof_require(len(actual_names) < 64 and entry.is_file(follow_symlinks=False))
                        actual_names.add(entry.name)
                _proof_require(actual_names == names | {'export.json'} and total == summary['raw_payload_bytes']
                               and 'materialization--manifest.json' in names
                               and account.read_bytes + summary['collector_plus_export_read_bytes'] <= 768 * MIB)
                after = old_path.lstat()
                _proof_require((after.st_dev, after.st_ino) == (old_identity.st_dev, old_identity.st_ino))
                account.old_join = _OriginalJoinFacts(True, summary['collector_plus_export_read_bytes'],
                                                      total, tuple(records))
            except BaseException as error:
                fault('old-export-refused', error)
            finally:
                if old_fd is not None:
                    try:
                        os.close(old_fd)
                    except BaseException as error:
                        fault('old-export-close-failed', error)
        else:
            fault('old-publication-incomplete')
        complete = (not account.stopped and original.state is _OwnerState.RETURNED
                    and original.value is True and published.state is _OwnerState.RETURNED
                    and published.value is True and account.live_complete and account.live_entered
                    and account.unwound and account.restored and account.phase is _OriginalPhase.UNWOUND
                    and account.boundary_before is not None and account.boundary_after == account.boundary_before
                    and account.old_join is not None and account.old_join.integrity_complete
                    and len(account.direct_results) == 4 and len(account.source_before) == 33
                    and len(account.source_after) == 33 and len(account.subjects) == 3)
        if complete:
            _proof_require(account.api is not None
                           and account.api.GitHub._https_get is account.saved_transport
                           and account.api.materialization.materialize_native_tool is account.saved_materializer)
        if account.live_entered:
            _proof_charge(account, 4 * (sum(len(raw) for raw in account.live_metadata + account.boundary_records)
                                        + getattr(account.preparation, 'metadata_bytes', 0) + 65536))
            retained_rows = account.direct_results
            if (type(account.last_direct) is _DirectResult
                    and not any(row is account.last_direct for row in retained_rows)):
                _proof_require(len(retained_rows) < 4)
                retained_rows += (account.last_direct,)
            members = [(member.role.value, member.data) for member in (
                account.products.plan, account.products.planning_report, account.products.planning_summary,
                account.products.junit, account.products.unbound_report, account.products.red_summary) if member is not None]
            if account.products.bound_report is not None:
                members.append((_SourceRole.REPORT.value, account.products.bound_report.data))
            for row in retained_rows:
                members.extend(((row.stage.value + '.stdout', row.stdout), (row.stage.value + '.stderr', row.stderr)))
            identity = {'scope': 'Fixed source and original control-flow inference; not authenticated origin',
                        'source_before': [(m.role.name, m.sha256, asdict(m.before)) for m in account.source_before],
                        'source_after': [(m.role.name, m.sha256, asdict(m.before)) for m in account.source_after],
                        'subjects': account.subjects,
                        'preparation': {'complete': account.preparation.complete,
                            'repository': base64.b64encode(account.preparation.repository_metadata or b'').decode(),
                            'parent': base64.b64encode(account.preparation.parent_metadata or b'').decode(),
                            'commit': base64.b64encode(account.preparation.commit_metadata or b'').decode(),
                            'commands': [(base64.b64encode(c.receipt).decode(),
                                          base64.b64encode(c.stdout).decode(), base64.b64encode(c.stderr).decode())
                                         for c in getattr(account.preparation, 'commands', ())],
                            'scans': getattr(account.preparation, 'scans', ())},
                        'boundary_records': [base64.b64encode(raw).decode() for raw in account.boundary_records],
                        'live_metadata': [base64.b64encode(raw).decode() for raw in account.live_metadata],
                        'rows': [{'stage': r.stage.value, 'argv': [os.fsdecode(v) for v in r.vector.argv],
                                  'environment': [(os.fsdecode(k), os.fsdecode(v)) for k, v in r.vector.environment],
                                  'cwd': os.fsdecode(r.vector.cwd), 'waitid': r.waitid, 'wait_status': r.wait_status,
                                  'started': r.started, 'ended': r.ended, 'deadline': r.deadline,
                                  'cleanup_complete': r.cleanup_complete, 'deadline_seen': r.deadline_seen}
                                 for r in retained_rows],
                        'old_export': str(account.original_output / 'export'),
                        'old_join': asdict(account.old_join) if account.old_join is not None else None}
            identity_raw = encoded(identity)
            _proof_require(account.metadata_bytes + getattr(account.preparation, 'metadata_bytes', 0) + len(identity_raw) <= 8 * MIB - 65536)
            account.metadata_bytes += len(identity_raw)
            members.append(('identity.json', identity_raw))
            for name, raw in members:
                _proof_final_clock(account)
                _proof_charge(account, (len(account.secrets) + 2) * len(raw))
                _proof_safe(account, raw)
                if name.endswith(('.stdout', '.stderr')):
                    _proof_require(len(raw) <= 8 * MIB and account.retained_stream_bytes + len(raw) <= 16 * MIB)
                    account.retained_stream_bytes += len(raw)
                else:
                    _proof_require(account.retained_bytes + len(raw) <= 16 * MIB)
                    account.retained_bytes += len(raw)
                _proof_require(len(files) + (len(account.old_join.files) if account.old_join else 0) + 2 < 128
                               and sum(item[1] for item in files) + len(raw)
                               + (account.old_join.payload_bytes if account.old_join else 0) + 65536 <= 160 * MIB)
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=export_fd)
                try:
                    _proof_require(os.write(fd, raw) == len(raw))
                finally:
                    os.close(fd)
                files.append((name, len(raw), sha(raw)))
    except BaseException as error:
        fault('finalization-refused', error)
    finally:
        preparation = account.preparation
        if preparation is not None and type(preparation) is not _OriginalRPreparation:
            fault('preparation-shape-refused')
            preparation = None
        children = (('R', preparation.root if preparation else None),
                    ('HOME', preparation.home if preparation else None),
                    ('TMP', preparation.tmp if preparation else None),
                    ('TEMPLATE', preparation.template if preparation else None), ('OUT', account.root))
        child_retained = False
        for role, child in children:
            deleted, closed, reason = False, False, 'not-created'
            if child is None:
                cleanup.append(_RootCleanup(role, True, True, True, reason))
                continue
            if type(child) is not (_OwnedRoot if role == 'OUT' else _OriginalRChild):
                fault('scratch-shape-refused')
                child_retained = True
                cleanup.append(_RootCleanup(role, True, False, False, 'shape-refused'))
                continue
            fd = child.descriptor
            if fd == -1:
                fd = None
            try:
                _proof_final_clock(account)
                _proof_require(role == 'OUT' or child.created)
                _proof_require(all(value is not None for value in (child.device, child.inode, child.uid, child.mode)))
                _proof_require(role != 'OUT' or not child_retained)
                _proof_require(role == 'OUT' or child.path.parent == account.root.path)
                _proof_require(child.path.parent.resolve(strict=True) == child.path.parent)
                _owned_visit(account)
                value = child.path.lstat()
                expected_identity = (child.device, child.inode, child.uid, child.mode)
                actual_identity = lambda v: (v.st_dev, v.st_ino, v.st_uid, v.st_mode)
                _proof_require(actual_identity(value) == expected_identity and child.uid == os.getuid()
                               and child.mode == stat.S_IFDIR | 0o700)
                if fd is not None:
                    _owned_visit(account)
                    _proof_require(actual_identity(os.fstat(fd)) == expected_identity)
                def inspect(directory, depth):
                    _proof_require(depth <= 64)
                    with os.scandir(directory) as entries:
                        for entry in entries:
                            _proof_final_clock(account)
                            _proof_require(account.metadata_visits + 2 <= 64000)
                            account.metadata_visits += 2
                            if entry.is_dir(follow_symlinks=False):
                                inspect(Path(entry.path), depth + 1)
                inspect(child.path, 0)
                _proof_require(shutil.rmtree.avoids_symlink_attacks if hasattr(shutil.rmtree, 'avoids_symlink_attacks')
                               else sys.platform in ('linux', 'darwin'))
                shutil.rmtree(child.path)
                _proof_final_clock(account)
                _owned_visit(account)
                _proof_require(not os.path.lexists(child.path))
                deleted, reason = True, 'deleted'
            except BaseException as error:
                reason = 'deletion-refused'
                fault('scratch-cleanup-incomplete', error)
                if role != 'OUT':
                    child_retained = True
            finally:
                if role != 'OUT' and not child.created and fd is not None:
                    reason = 'unowned-descriptor'
                    fault('scratch-close-incomplete')
                elif fd is None:
                    closed = True
                else:
                    try:
                        os.close(fd)
                        closed = True
                    except BaseException as error:
                        reason = 'descriptor-close-failed'
                        fault('scratch-close-incomplete', error)
                cleanup.append(_RootCleanup(role, True, closed, deleted, reason))
        try:
            _proof_final_clock(account)
            _proof_require(datetime.now(timezone.utc) < datetime(2026, 11, 4, 23, tzinfo=timezone.utc))
            _proof_require(footer_started and all(item.deleted and item.descriptor_closed for item in cleanup))
            if account.old_join is not None:
                _proof_require(account.read_bytes + account.old_join.collector_plus_export_read_bytes <= 768 * MIB)
            value = {'complete': complete, 'outcome': 'CompleteFixedSourcePacketAwaitingRootReview' if complete else 'Incomplete',
                     'cleanup': [asdict(item) for item in cleanup], 'diagnostics': diagnostics, 'files': files,
                     'new_read_bytes': account.read_bytes, 'new_work_bytes': account.spent_bytes}
            raw = footer(value)
            _proof_require(os.fstat(export_fd).st_ino == export_identity.st_ino
                           and account.export_path.lstat().st_ino == export_identity.st_ino)
            os.lseek(footer_fd, 0, os.SEEK_SET)
            os.ftruncate(footer_fd, 0)
            _proof_require(os.write(footer_fd, raw) == len(raw))
            _proof_final_clock(account)
            _proof_require(datetime.now(timezone.utc) < datetime(2026, 11, 4, 23, tzinfo=timezone.utc))
        except BaseException as error:
            fault('closure-incomplete', error)
        finally:
            for fd in (footer_fd, export_fd):
                if fd is not None:
                    try:
                        os.close(fd)
                    except BaseException as error:
                        fault('export-close-incomplete', error)
    account.finish_complete = complete
    account.phase = _OriginalPhase.CLOSED if complete else _OriginalPhase.FAILED
    account.final_packet = _Original15Packet(complete,
        'CompleteFixedSourcePacketAwaitingRootReview' if complete else 'Incomplete', tuple(cleanup),
        tuple(diagnostics), account.export_path if footer_started else None)
    return account.final_packet


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print('Preflight stopped. Exception class ' + type(error).__name__)
        raise SystemExit(1)
