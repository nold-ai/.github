from __future__ import annotations

import argparse
import ast
import base64
import dis
import hashlib
import importlib.util
import json
import math
import os
import platform
import re
import resource
import select
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
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
                'sha': '9f952f1bc591b9d58403a8a362ce9fe21fdfe47d'}}
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


def actual(api, policy, output, rows, fixture):
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
        with Timer(1200, mat._private_root.__wrapped__.__code__) as timer:
            transcript = Transcript(rows, fixture, transport, timer)
            with transcript.installed(api.GitHub):
                with cleanup_observer(mat, workspace, evidence, timer, state):
                    with mat.materialize_native_tool(expected(api), workspace) as tool:
                        timer.check()
                        require(transcript.position == 18 and transcript.real == 14, 'positive transcript incomplete')
                        manifest['tool'] = tool_facts(tool, evidence, policy)
                        timer.check()
                        yielded = True
        require(api.GitHub._https_get is transport and mat.shutil is saved_shutil, 'parent restoration')
        require(state['observations'] == 1 and state['deleted'], 'owned cleanup incomplete')
        require(len(evidence.source_counts) == 2 and evidence.source_counts == evidence.blob_counts
                and evidence.command_count == 24 + sum(evidence.source_counts.values()), 'command coverage')
        manifest['outcome'] = 'DEVELOPMENT_MATERIALIZATION_OBSERVED' if evidence.complete else 'EVIDENCE_INCOMPLETE'
    except BaseException as error:
        manifest['exception'] = exception_facts(error)
        if yielded or not evidence.complete:
            manifest['outcome'] = 'EVIDENCE_INCOMPLETE'
    finally:
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
    try:
        success = actual(api, policy, output, rows, fixture)
    except BaseException as error:
        (output / 'actual-failure.json').write_bytes(encoded({
            'outcome': 'EVIDENCE_INCOMPLETE', 'exception': exception_facts(error)}))
        raise
    finally:
        export_complete = publish_safe(output)
    return 0 if success and export_complete else 1


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
    def __init__(self, result: _DirectResult):
        super().__init__('Original row refused')
        self.result = result


class _OriginalRowRefusal(RuntimeError):
    pass


def _original_vectors(tool, prepared: _PreparedPaths) -> tuple[_OriginalVector, ...]:
    paths = (tool.python, tool.site_packages, tool.core_root, tool.modules_root, tool.uv,
             prepared.root, prepared.out, prepared.home, prepared.tmp)
    for path in paths:
        if (type(path) is not type(Path()) or not path.is_absolute() or path.anchor != '/'
                or any(part in ('.', '..') for part in path.parts)
                or os.path.normpath(str(path)) != str(path)):
            raise ValueError('original-vector-path')
        raw = os.fsencode(path)
        if len(raw) > 4096 or b'\0' in raw:
            raise ValueError('original-vector-path')
    py, site, core, modules, uv, root, out, home, tmp = map(os.fsencode, paths)
    environment = ((b'HOME', home), (b'TMPDIR', tmp),
                   (b'PATH', os.fsencode(tool.uv.parent) + b':/usr/bin:/bin'),
                   (b'LC_ALL', b'C.UTF-8'),
                   (b'VIRTUAL_ENV', os.fsencode(tool.python.parent.parent)),
                   (b'SPECFACT_MODULES_REPO', modules),
                   (b'SPECFACT_MODULES_ROOTS', modules + b'/packages'))
    common = (py, b'-I', b'-S', b'-c')
    cli = common + (
        b'import sys; site_packages, trusted_core = sys.argv[1:3]; del sys.argv[1:3]; sys.path.append(site_packages); sys.path.insert(0, trusted_core); from specfact_cli.cli import cli_main; cli_main()',
        site, core + b'/src')
    script = common + (
        b'import runpy, sys; sys.path.append(sys.argv.pop(1)); script = sys.argv.pop(1); runpy.run_path(script, run_name="__main__")',
        site)
    base = b'9b5ad1e78430cc0b061cb16de42f73de96f4f312'
    source = b'4ae6175a4d337296d0347e73b66c9da1f0e43f7f'
    change = b'openspec/changes/security-dependencies-0-55-11-dev'
    vectors = (
        cli + (b'requirements', b'evidence', b'--repo-root', root, b'--base-ref', base,
               b'--required-maturity', b'test-authored', b'--review-evidence',
               root + b'/' + change + b'/requirements-proof/review-evidence.json',
               b'--plan-output', out + b'/plan.json', b'--output', out + b'/planning-report.json',
               b'--summary', out + b'/planning-summary.md'),
        script + (core + b'/scripts/requirements_proof_executor.py', b'--plan', out + b'/plan.json',
                  b'--repo-root', root, b'--junit', out + b'/requirements-proof.xml'),
        cli + (b'requirements', b'reconcile', b'--plan', out + b'/plan.json', b'--junit',
               out + b'/requirements-proof.xml', b'--run-stage', b'red', b'--source-ref', source,
               b'--output', out + b'/local-red-report.json', b'--summary', out + b'/local-red-summary.md'),
        script + (core + b'/scripts/requirements_proof_provenance.py', b'--bind-red-proof',
                  out + b'/local-red-report.json', b'--junit', out + b'/requirements-proof.xml',
                  b'--repo-root', root, b'--base-ref', base),
    )
    return tuple(_OriginalVector(stage, argv, environment, root, code, seconds)
                 for stage, argv, code, seconds in zip(
                     _OriginalStage, vectors, (0, 1, 0, 0), (120, 660, 120, 120)))


def _run_original_stage(account, tool, prepared: _PreparedPaths, timer,
                        stage: _OriginalStage) -> _DirectResult:
    started = time.monotonic()
    try:
        if type(account) is not _AttemptAccount or type(stage) is not _OriginalStage:
            raise ValueError('original-row-shape')
        vector = _original_vectors(tool, prepared)[tuple(_OriginalStage).index(stage)]
    except BaseException:
        if type(account) is _AttemptAccount:
            account.stopped = True
        raise
    deadline = owner_end = started
    saved = None
    installed = False
    reason = primary = None
    deadline_seen = False
    row_pid = row_wait = row_status = None
    row_cleanup = False
    execution_ended = None
    chunks = [[], []]
    sizes = [0, 0]
    outputs = [b'', b'']
    copied = 0
    scanned = 0
    retained_before = account.retained_stream_bytes
    child = None
    pid = None
    terminal = status = None
    owned = False
    leader_start = None
    pipes = []
    probing = True

    def refuse(value):
        raise _OriginalRowRefusal(value)

    def remember(error):
        nonlocal reason, primary, deadline_seen
        if isinstance(error, Deadline):
            deadline_seen = True
            value = 'deadline'
        elif type(error) is _OriginalRowRefusal:
            value = error.args[0]
            if probing and value in ('ownership', 'proc', 'cleanup', 'launch'):
                value = 'prerequisite'
        else:
            if primary is None:
                primary = error
            value = 'exception'
        if reason is None:
            reason = value
        account.stopped = True

    def clock_check(strict=False):
        nonlocal deadline_seen
        if timer.end != owner_end:
            remember(_OriginalRowRefusal('prerequisite'))
        try:
            timer.check()
        except Deadline:
            deadline_seen = True
        if (timer.pending or timer.expired or time.monotonic() >= deadline
                or time.monotonic_ns() >= account.deadline_ns):
            deadline_seen = True
        if deadline_seen:
            remember(_OriginalRowRefusal('deadline'))
        if strict and reason is not None:
            refuse(reason)

    def alarm(number, frame):
        nonlocal deadline_seen
        try:
            saved(number, frame)
        except Deadline:
            deadline_seen = True

    def preexec():
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        signal.pthread_sigmask(signal.SIG_SETMASK, set())
        for kind, ceiling in ((resource.RLIMIT_CPU, 240), (resource.RLIMIT_AS, 2147483648),
                              (resource.RLIMIT_FSIZE, 268435456), (resource.RLIMIT_NPROC, 128),
                              (resource.RLIMIT_CORE, 0)):
            soft, hard = resource.getrlimit(kind)
            hard = ceiling if hard == resource.RLIM_INFINITY else min(hard, ceiling)
            soft = hard if soft == resource.RLIM_INFINITY else min(soft, hard)
            resource.setrlimit(kind, (soft, hard))
        child_pid = os.getpid()
        if child_pid <= 1 or os.getpgrp() != child_pid or os.getsid(0) != child_pid:
            raise RuntimeError('original-child-session')
        if time.monotonic() >= deadline or time.monotonic_ns() >= account.deadline_ns:
            raise RuntimeError('original-child-deadline')

    def outstanding():
        return (len(account.secrets) + 2) * sum(sizes) - copied - scanned

    def visit(end):
        clock_check()
        if time.monotonic() >= end:
            refuse('cleanup')
        if account.metadata_visits >= 20000:
            refuse('budget')
        account.metadata_visits += 1

    def observe():
        nonlocal owned, terminal
        clock_check()
        if not owned:
            refuse('ownership')
        try:
            fact = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError:
            owned = False
            refuse('ownership')
        except OSError:
            if probing:
                refuse('prerequisite')
            raise
        if fact is not None and fact.si_pid:
            current = (fact.si_pid, fact.si_code, fact.si_status)
            if (fact.si_pid != pid or fact.si_code not in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED)
                    or terminal is not None and current != terminal):
                owned = False
                refuse('ownership')
            terminal = current
        clock_check()
        return terminal

    def identity():
        nonlocal owned
        observe()
        try:
            valid = pid > 1 and os.getpgid(pid) == pid and os.getsid(pid) == pid
        except ProcessLookupError:
            valid = False
        if not valid:
            owned = False
            refuse('ownership')

    def group_empty(end):
        nonlocal leader_start, owned
        visit(end)
        visits = numeric = 0
        found = False
        empty = True
        try:
            with os.scandir('/proc') as entries:
                while True:
                    visit(end)
                    visits += 1
                    if visits > 20000:
                        refuse('budget')
                    try:
                        entry = next(entries)
                    except StopIteration:
                        break
                    if not entry.name.isascii() or not entry.name.isdecimal():
                        continue
                    numeric += 1
                    if numeric > 20000 or len(entry.name) > 10:
                        refuse('proc')
                    visit(end)
                    before = account.spent_bytes
                    if before + outstanding() + 8193 > 255 * MIB:
                        refuse('budget')
                    descriptor = None
                    try:
                        descriptor = os.open('/proc/' + entry.name + '/stat',
                                             os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                        clock_check()
                        if time.monotonic() >= end:
                            refuse('cleanup')
                        raw = os.read(descriptor, 8193)
                        account.read_bytes += len(raw)
                        account.spent_bytes += len(raw)
                        if not raw or len(raw) > 8192:
                            refuse('proc')
                        close = raw.rfind(b')')
                        opening = raw.find(b' (')
                        if opening < 1 or close <= opening + 1 or raw[close + 1:close + 2] != b' ':
                            refuse('proc')
                        fields = raw[close + 2:].split()
                        if len(fields) < 20 or fields[0] not in (
                                b'R', b'S', b'D', b'Z', b'T', b't', b'X', b'x', b'K', b'W', b'P', b'I'):
                            refuse('proc')
                        observed_pid = int(raw[:opening])
                        group, session, start = int(fields[2]), int(fields[3]), int(fields[19])
                        if observed_pid != int(entry.name) or min(observed_pid, group, session, start) < 0:
                            refuse('proc')
                        if observed_pid == pid:
                            found = True
                            if (group != pid or session != pid
                                    or leader_start is not None and start != leader_start):
                                owned = False
                                refuse('ownership')
                            leader_start = start
                        if group == pid:
                            if session != pid:
                                refuse('proc')
                            if not (observed_pid == pid and terminal is not None and fields[0] == b'Z'):
                                empty = False
                    except BaseException:
                        account.spent_bytes = max(account.spent_bytes, before + 8193)
                        raise
                    finally:
                        if descriptor is not None:
                            previous_error = sys.exception()
                            try:
                                os.close(descriptor)
                            except BaseException as error:
                                account.spent_bytes = max(account.spent_bytes, before + 8193)
                                if previous_error is not None:
                                    remember(previous_error)
                                    remember(error)
                                    raise previous_error
                                raise
                    clock_check()
            if not found:
                owned = False
                refuse('ownership')
            return empty and terminal is not None
        except (OSError, ValueError, IndexError):
            refuse('proc')

    def drain(end):
        if probing or reason is not None or not pipes:
            return False
        clock_check(True)
        progressed = False
        ready, _, _ = select.select([pipe.fileno() for _, pipe in pipes], [], [], 0)
        for index, pipe in tuple(pipes):
            if pipe.fileno() not in ready:
                continue
            clock_check(True)
            if time.monotonic() >= end:
                refuse('cleanup')
            capacity = min(8 * MIB - sizes[index], 16 * MIB - account.stream_bytes,
                           16 * MIB - retained_before - sum(sizes))
            available = 255 * MIB - account.spent_bytes - outstanding()
            count = min(65536, capacity + 1, available // (len(account.secrets) + 3))
            if count <= 0:
                refuse('budget')
            before = account.spent_bytes
            try:
                raw = os.read(pipe.fileno(), count)
            except BlockingIOError:
                continue
            except BaseException:
                account.spent_bytes = max(account.spent_bytes, before + (len(account.secrets) + 3) * count)
                raise
            account.read_bytes += len(raw)
            account.stream_bytes += len(raw)
            account.spent_bytes += len(raw)
            progressed = True
            if len(raw) > capacity:
                refuse('stream-limit')
            if raw:
                chunks[index].append(raw)
                sizes[index] += len(raw)
            else:
                pipe.close()
                pipes.remove((index, pipe))
            clock_check(True)
        return progressed

    def pause(end):
        clock_check()
        delay = min(.05, max(0.0, end - time.monotonic()))
        if delay:
            time.sleep(delay)
        clock_check()

    def signal_group(number):
        identity()
        os.killpg(pid, number)
        clock_check()

    def cleanup():
        nonlocal status, owned
        began = time.monotonic()
        term_end, kill_end, reap_end = began + 5, began + 10, began + 15
        clean = False
        failed = False
        try:
            clock_check()
            identity()
            clean = group_empty(term_end)
            scan_due = time.monotonic() + 0.5
            if not clean:
                signal_group(signal.SIGTERM)
                while time.monotonic() < term_end:
                    observe()
                    drain(term_end)
                    if time.monotonic() >= scan_due:
                        clean = group_empty(term_end)
                        scan_due = time.monotonic() + 0.5
                        if clean:
                            break
                    pause(term_end)
        except BaseException as error:
            if not (type(error) is _OriginalRowRefusal and error.args == ('cleanup',)
                    and time.monotonic() >= term_end):
                failed = True
                remember(error)
        if not clean and owned:
            try:
                if time.monotonic() >= kill_end:
                    refuse('cleanup')
                signal_group(signal.SIGKILL)
                scan_due = time.monotonic()
                while not failed and time.monotonic() < kill_end:
                    observe()
                    drain(kill_end)
                    if time.monotonic() >= scan_due:
                        clean = group_empty(kill_end)
                        scan_due = time.monotonic() + 0.5
                        if clean:
                            break
                    pause(kill_end)
            except BaseException as error:
                failed = True
                remember(error)
        if not clean:
            remember(_OriginalRowRefusal('cleanup'))
        while owned and status is None and time.monotonic() < reap_end:
            try:
                observe()
            except BaseException as error:
                failed = True
                remember(error)
            if not owned:
                break
            try:
                found, value = os.waitpid(pid, os.WNOHANG)
                if found:
                    status = value
                    owned = False
                    child.returncode = os.waitstatus_to_exitcode(value)
                    consistent = (found == pid and terminal is not None and (
                        terminal[1] == os.CLD_EXITED and os.WIFEXITED(value)
                        and os.WEXITSTATUS(value) == terminal[2]
                        or terminal[1] in (os.CLD_KILLED, os.CLD_DUMPED) and os.WIFSIGNALED(value)
                        and os.WTERMSIG(value) == terminal[2]
                        and bool(os.WCOREDUMP(value)) == (terminal[1] == os.CLD_DUMPED)))
                    if not consistent:
                        failed = True
                        remember(_OriginalRowRefusal('ownership'))
                    break
                drain(reap_end)
                pause(reap_end)
            except ChildProcessError:
                owned = False
                failed = True
                remember(_OriginalRowRefusal('ownership'))
            except BaseException as error:
                failed = True
                remember(error)
                if type(error) is _OriginalRowRefusal and error.args[0] == 'ownership':
                    break
                pause(reap_end)
        if status is None:
            failed = True
            remember(_OriginalRowRefusal('cleanup'))
        while pipes and reason is None and time.monotonic() < reap_end:
            try:
                progressed = drain(reap_end)
                if pipes and not progressed:
                    pause(reap_end)
            except BaseException as error:
                remember(error)
                break
        if pipes and reason is None:
            remember(_OriginalRowRefusal('cleanup'))
        return clean and not failed and status is not None

    try:
        if (type(account.stopped) is not bool or account.stopped
                or not _owned_integer(account.deadline_ns, 2**63 - 1, 1)
                or not _owned_integer(account.spent_bytes, 255 * MIB)
                or not _owned_integer(account.read_bytes, 255 * MIB)
                or account.read_bytes > account.spent_bytes
                or not _owned_integer(account.retained_bytes, 16 * MIB)
                or not _owned_integer(account.retained_members, 64)
                or not _owned_integer(account.metadata_visits, 20000)
                or not _owned_integer(account.stream_bytes, 16 * MIB)
                or not _owned_integer(account.retained_stream_bytes, 16 * MIB)
                or type(account.row_seconds) not in (int, float)
                or not math.isfinite(account.row_seconds) or not 0 <= account.row_seconds <= 1020
                or type(account.secrets) is not tuple or len(account.secrets) > 32
                or any(type(secret) is not bytes or not 8 <= len(secret) <= 4096
                       for secret in account.secrets)):
            refuse('budget')
        if (account.spent_bytes >= 255 * MIB or account.metadata_visits >= 20000
                or account.stream_bytes >= 16 * MIB or account.retained_stream_bytes >= 16 * MIB):
            refuse('budget')
        if (type(timer) is not Timer or type(timer.end) not in (int, float)
                or not math.isfinite(timer.end)):
            refuse('prerequisite')
        owner_end = timer.end
        deadline = min(started + vector.seconds, owner_end, started + 1020 - account.row_seconds,
                       account.deadline_ns / 1_000_000_000)
        saved = signal.getsignal(signal.SIGALRM)
        if (getattr(saved, '__self__', None) is not timer
                or getattr(saved, '__func__', None) is not Timer.alarm):
            refuse('prerequisite')
        clock_check(True)
        if (sys.platform != 'linux' or threading.current_thread() is not threading.main_thread()
                or threading.active_count() != 1 or not callable(getattr(os, 'waitid', None))
                or not all(hasattr(os, name) for name in ('P_PID', 'WEXITED', 'WNOHANG', 'WNOWAIT'))
                or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL
                or signal.SIGALRM in signal.pthread_sigmask(signal.SIG_BLOCK, set())):
            refuse('prerequisite')
        installed = True
        signal.signal(signal.SIGALRM, alarm)
        visit(deadline)
        try:
            with os.scandir('/proc/self/task') as tasks:
                count = 0
                while True:
                    visit(deadline)
                    try:
                        task = next(tasks)
                    except StopIteration:
                        break
                    count += 1
                    if count > 1 or not task.name.isdecimal():
                        refuse('prerequisite')
                if count != 1:
                    refuse('prerequisite')
        except OSError:
            refuse('prerequisite')
        for probing in (True, False):
            child = None
            pid = terminal = status = leader_start = None
            owned = False
            pipes = []
            try:
                clock_check(True)
                argv = (os.fsencode(sys.executable), b'-I', b'-S', b'-c', b'pass') if probing else vector.argv
                try:
                    child = subprocess.Popen(argv, shell=False, close_fds=True, pass_fds=(),
                                             start_new_session=True, stdin=subprocess.DEVNULL,
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                             env=dict(vector.environment), cwd=vector.cwd, preexec_fn=preexec)
                except (OSError, subprocess.SubprocessError):
                    refuse('prerequisite' if probing else 'launch')
                pid = child.pid
                owned = True
                if not probing:
                    row_pid = pid
                identity()
                if not probing:
                    pipes = list(enumerate((child.stdout, child.stderr)))
                    for _, pipe in pipes:
                        os.set_blocking(pipe.fileno(), False)
                clock_check(True)
                while terminal is None:
                    clock_check(True)
                    progressed = drain(deadline)
                    observe()
                    if terminal is None and not progressed:
                        pause(deadline)
                clock_check(True)
                if probing:
                    first = terminal
                    if observe() != first or first[1:] != (os.CLD_EXITED, 0):
                        refuse('prerequisite')
                elif terminal[1:] != (os.CLD_EXITED, vector.expected_exit):
                    refuse('exit')
            except BaseException as error:
                remember(error)
            finally:
                if not probing:
                    execution_ended = time.monotonic()
                complete = False
                if child is not None:
                    try:
                        complete = cleanup()
                    except BaseException as error:
                        remember(error)
                    finally:
                        for pipe in (child.stdin, child.stdout, child.stderr):
                            if pipe is not None:
                                try:
                                    pipe.close()
                                except BaseException as error:
                                    complete = False
                                    remember(error)
                        if status is None:
                            # An implicit destructor reap would bypass the recorded ownership failure.
                            child._child_created = False
                if not probing:
                    row_wait, row_status, row_cleanup = terminal, status, complete
                elif not complete:
                    remember(_OriginalRowRefusal('prerequisite'))
            if reason is not None:
                break
        if reason is None:
            clock_check(True)
            for index in range(2):
                size = sizes[index]
                outputs[index] = b''.join(chunks[index])
                account.spent_bytes += size
                copied += size
                chunks[index].clear()
                for secret in account.secrets:
                    clock_check(True)
                    account.spent_bytes += size
                    scanned += size
                    if secret in outputs[index]:
                        refuse('stream-limit')
                clock_check(True)
                account.spent_bytes += size
                scanned += size
                if re.search(
                        rb'(?i)(?:authorization\s*:\s*bearer |github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9]+|X-Amz-Signature=|sig=)',
                        outputs[index]) is not None:
                    refuse('stream-limit')
            clock_check(True)
    except BaseException as error:
        remember(error)
    finally:
        if execution_ended is None:
            execution_ended = time.monotonic()
        if type(account.row_seconds) in (int, float) and math.isfinite(account.row_seconds):
            account.row_seconds += max(0.0, execution_ended - started)
        if installed:
            try:
                clock_check()
            except BaseException as error:
                remember(error)
            finally:
                for _ in range(2):
                    try:
                        signal.signal(signal.SIGALRM, saved)
                    except BaseException as error:
                        remember(error)
                    if signal.getsignal(signal.SIGALRM) is saved:
                        break
                try:
                    clock_check()
                except BaseException as error:
                    remember(error)
        if reason is not None:
            outputs = [b'', b'']
            chunks[0].clear()
            chunks[1].clear()
        else:
            account.retained_stream_bytes = retained_before + sum(sizes)
        result = _DirectResult(stage, vector, row_pid, started, deadline, time.monotonic(),
                               row_wait, row_status, outputs[0], outputs[1], row_cleanup,
                               deadline_seen, reason or 'complete')
        account.last_direct = result
    if primary is not None:
        raise primary
    if reason is not None:
        raise _OriginalStageError(result)
    return result


class _SourceRole(Enum):
    PLAN = 'plan.json'


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
    _owned_require(account.metadata_visits < 20000)
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
        _owned_require(type(role) is _SourceRole and role is _SourceRole.PLAN)
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
                       and _owned_integer(account.metadata_visits, 20000))
        _owned_require(type(account.secrets) is tuple and len(account.secrets) <= 32)
        _owned_require(all(type(secret) is bytes and 8 <= len(secret) <= 4096
                           for secret in account.secrets))
        name = str(root.path)
        depth = len(root.path.parts) - 1
        _owned_require(root.path.is_absolute() and root.path.anchor == '/'
                       and 1 <= depth <= 64 and len(os.fsencode(name)) <= 4096
                       and os.path.normpath(name) == name
                       and all(part not in ('.', '..') for part in root.path.parts[1:]))
        _owned_require(account.metadata_visits + 2 * depth + 6 <= 20000)
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        _owned_clock(account)
        _owned_root_check(account)
        _owned_visit(account)
        before = _owned_file_identity(os.stat('plan.json', dir_fd=root.descriptor,
                                              follow_symlinks=False))
        size = before.size
        work = (len(account.secrets) + 4) * (size + 1)
        _owned_require(account.spent_bytes + work <= 255 * MIB
                       and account.retained_bytes + size <= 16 * MIB
                       and account.retained_members + 1 <= 64)
        admitted = work
        _owned_clock(account)
        descriptor = os.open('plan.json', flags, dir_fd=root.descriptor)
        try:
            _owned_visit(account)
            opened = _owned_file_identity(os.fstat(descriptor))
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
            after = _owned_file_identity(os.fstat(descriptor))
            _owned_require(after == before)
            _owned_root_check(account)
            _owned_visit(account)
            current = _owned_file_identity(os.stat('plan.json', dir_fd=root.descriptor,
                                                   follow_symlinks=False))
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


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print('Preflight stopped. Exception class ' + type(error).__name__)
        raise SystemExit(1)
