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
    pass


def _original_vectors(tool, prepared: _PreparedPaths) -> tuple[_OriginalVector, ...]:
    raise NotImplementedError('NEW original vectors missing')


def _run_original_stage(account, tool, prepared: _PreparedPaths, timer,
                        stage: _OriginalStage) -> _DirectResult:
    raise NotImplementedError('NEW original row lifetime missing')


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
    preparation: _OriginalRPreparation | None = None


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
class _OriginalRGit:
    argv: tuple[str, ...]
    started_ns: int
    deadline_ns: int
    process: object | None = None
    pid: int | None = None
    waitid: tuple[int, int, int] | None = None
    wait_status: int | None = None
    ended_ns: int | None = None
    stdout: bytes = b''
    stderr: bytes = b''
    receipt: bytes = b''
    cleanup_complete: bool = False
    reason: str = 'incomplete'


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
    commands: tuple[_OriginalRGit, ...] = ()
    scans: tuple[tuple[int, int], ...] = ()
    metadata_bytes: int = 0
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


_ORIGINAL_R = '4ae6175a4d337296d0347e73b66c9da1f0e43f7f'
_ORIGINAL_R_TREE = 'baeb88acf0d2a5015810ad12dbfccfa7fdf9a21e'
_ORIGINAL_C_TREE = '24112d8c9983333f9059283965230348f718b74c'
_ORIGINAL_R_RAW = '43f81bdc267a38928838620dd35a741e6329d46243fc78a9160a7a7ee3913a2e'
_ORIGINAL_R_SOURCES = (
    ('tests/unit/scripts/test_dependency_compatibility_workflow.py', '416e367877990ebb2d809e11847c363cd599c32f32d014a818f09053d5fab7fa'),
    ('tests/unit/scripts/test_dependency_trust_review.py', 'bb20822cb58c8f773f8ed7a54628feef2e1eadbf5cc5c53936422223986ee7ac'),
    ('tests/unit/scripts/test_security_audit_gate.py', '5100ceaa78a4381b8565f5a3c996e8d8b15ceda44d18de9ebcf04eb0561f81a3'),
    ('tests/unit/security/test_frozen_gitpython_compatibility.py', 'c1d428aba630c5f4abd4f236c10540632fb86e9c0e93ea1a9ba91809dbe415af'),
    ('tests/unit/security/test_release_dependency_selection.py', 'f713acdfeba8235bd5f7e2c22b7a29585d61693798972b6e9a24a31423e7a4e6'),
    ('scripts/requirements_proof_pytest_plugin.py', '31a1a8e3f7cf4e9d35612e4395c03298be85262da2bcc91b33008919f2a24de8'),
    ('openspec/changes/security-dependencies-0-55-11-dev/requirements-evidence.yaml', '6a1f812cc9a0be0adf260cdfb48dda0a5af3c41b5827259459373123861e9e20'),
    ('openspec/changes/security-dependencies-0-55-11-dev/requirements-proof/review-evidence.json', 'a5664876536b22616c93489ceb4baacd9ba07515f83216e2441289aaf3606707'),
    ('requirements/ci/locked.txt', '0bf003b492508a171177f2ba386126b76200262e7e49c3d1a25e1c8139250266'),
    ('uv.lock', '850b941d7d7dabf102d39ce92fb23d7586d183384fac03c140ceae0a07d169b7'),
)


def _original_r_require(condition):
    if not condition:
        raise _OriginalRPreparationError('Original R preparation refused')


@contextmanager
def _original_r_registration():
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def _prepare_original_r(account, api):
    started = time.monotonic_ns()
    try:
        _original_r_require(type(account) is _AttemptAccount
                            and type(account.stopped) is bool and not account.stopped
                            and account.preparation is None)
        _original_r_require(_owned_integer(account.deadline_ns, 2**63 - 1, 1))
        preparation = _OriginalRPreparation(started, min(started + 360_000_000_000,
                                                        account.deadline_ns))
        account.preparation = preparation
        _original_r_require(type(account.root) is _OwnedRoot
                            and type(account.root.path) is type(Path())
                            and account.root.path.is_absolute()
                            and account.root.path.anchor == '/'
                            and 1 <= len(account.root.path.parts) - 1 <= 64
                            and os.path.normpath(str(account.root.path)) == str(account.root.path)
                            and len(os.fsencode(account.root.path)) <= 4096
                            and '\0' not in str(account.root.path)
                            and _owned_integer(account.root.descriptor, 2**31 - 1)
                            and account.root.uid == os.getuid()
                            and account.root.mode == stat.S_IFDIR | 0o700)
        _original_r_require(all(_owned_integer(value, upper) for value, upper in (
            (account.root.device, 2**64 - 1), (account.root.inode, 2**64 - 1),
            (account.root.uid, 2**32 - 1), (account.root.mode, 2**32 - 1),
            (account.spent_bytes, 255 * MIB), (account.read_bytes, 255 * MIB),
            (account.retained_bytes, 16 * MIB), (account.retained_members, 64),
            (account.metadata_visits, 20000))))
        _original_r_require(account.read_bytes <= account.spent_bytes
                            and type(account.secrets) is tuple and len(account.secrets) <= 32
                            and all(type(value) is bytes and 8 <= len(value) <= 4096
                                    for value in account.secrets))
        _original_r_require(sys.platform == 'linux'
                            and threading.current_thread() is threading.main_thread()
                            and threading.active_count() == 1
                            and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL
                            and callable(getattr(os, 'waitid', None))
                            and all(hasattr(os, name) for name in
                                    ('P_PID', 'WEXITED', 'WNOHANG', 'WNOWAIT', 'O_NOFOLLOW'))
                            and signal.SIGALRM not in signal.pthread_sigmask(signal.SIG_BLOCK, set()))
        remaining = (preparation.deadline_ns - time.monotonic_ns()) / 1_000_000_000
        _original_r_require(remaining > 0)

        with Timer(remaining) as timer:
            def clock():
                timer.check()
                _original_r_require(time.monotonic_ns() < preparation.deadline_ns
                                    and time.monotonic_ns() < account.deadline_ns)

            def visit(end=None):
                if end is None:
                    clock()
                else:
                    _original_r_require(time.monotonic_ns() < end)
                _original_r_require(account.metadata_visits < 20000)
                account.metadata_visits += 1

            def charge(size):
                _original_r_require(type(size) is int and size >= 0
                                    and account.spent_bytes + size <= 255 * MIB)
                account.spent_bytes += size

            def sensitive(raw):
                for value in account.secrets:
                    _original_r_require(value not in raw)
                _original_r_require(re.search(
                    rb'(?i)(?:authorization\s*:\s*bearer |github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9]+|X-Amz-Signature=|sig=)',
                    raw) is None)

            def retain(raw):
                _original_r_require(preparation.metadata_bytes + len(raw) <= 8 * MIB)
                preparation.metadata_bytes += len(raw)

            clock()
            _owned_root_check(account)
            visit()
            with os.scandir('/proc/self/task') as tasks:
                visit()
                _original_r_require(next(tasks, None) is not None)
                visit()
                _original_r_require(next(tasks, None) is None)
            for name, relative in (('root', 'original-r'), ('home', 'home'),
                                   ('tmp', 'tmp'), ('template', 'git-template')):
                clock()
                child = _OriginalRChild(account.root.path / relative)
                setattr(preparation, name, child)
                visit()
                with _original_r_registration():
                    os.mkdir(relative, mode=0o700, dir_fd=account.root.descriptor)
                    child.created = True
                    value = os.stat(relative, dir_fd=account.root.descriptor, follow_symlinks=False)
                    child.device, child.inode, child.uid, child.mode = (
                        value.st_dev, value.st_ino, value.st_uid, value.st_mode)
                    _original_r_require(value.st_mode == stat.S_IFDIR | 0o700
                                        and value.st_uid == os.getuid())
                    child.descriptor = os.open(relative, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                               dir_fd=account.root.descriptor)
                clock()
                visit()
                value = os.fstat(child.descriptor)
                _original_r_require((value.st_dev, value.st_ino, value.st_uid, value.st_mode)
                                    == (child.device, child.inode, child.uid, child.mode))

            root = preparation.root.path
            environment = {'HOME': str(preparation.home.path), 'TMPDIR': str(preparation.tmp.path),
                           'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
                           'GIT_TERMINAL_PROMPT': '0', 'GIT_CONFIG_NOSYSTEM': '1'}

            def children_check():
                for child in (preparation.root, preparation.home, preparation.tmp, preparation.template):
                    expected = (child.device, child.inode, child.uid, child.mode)
                    visit()
                    value = os.stat(child.path, follow_symlinks=False)
                    _original_r_require((value.st_dev, value.st_ino, value.st_uid, value.st_mode) == expected)
                    visit()
                    value = os.fstat(child.descriptor)
                    _original_r_require((value.st_dev, value.st_ino, value.st_uid, value.st_mode) == expected)

            def metadata(path, slot):
                clock()
                maximum = (len(account.secrets) + 5) * (4 * MIB + 1)
                before = account.spent_bytes
                _original_r_require(before + maximum <= 255 * MIB)
                try:
                    raw = transport.get(path)
                    with _original_r_registration():
                        _original_r_require(type(raw) is bytes and len(raw) <= 4 * MIB)
                        account.read_bytes += len(raw)
                        charge((len(account.secrets) + 5) * len(raw))
                    sensitive(raw)
                    value = sys.modules['late_cycle_admission'].json_object(raw)
                    retain(raw)
                    setattr(preparation, slot, raw)
                    clock()
                    return value
                except BaseException:
                    account.spent_bytes = max(account.spent_bytes, before + maximum)
                    raise

            def commit_metadata(value, commit, tree):
                _original_r_require(type(value) is dict and value.get('sha') == commit
                                    and type(value.get('tree')) is dict
                                    and value['tree'].get('sha') == tree
                                    and type(value.get('parents')) is list
                                    and len(value['parents']) <= 16)
                for parent in value['parents']:
                    _original_r_require(type(parent) is dict and type(parent.get('sha')) is str
                                        and re.fullmatch('[0-9a-f]{40}', parent['sha']) is not None)
                verification = value.get('verification')
                _original_r_require(type(verification) is dict
                                    and all(field in verification for field in
                                            ('verified', 'reason', 'signature', 'payload'))
                                    and type(verification.get('verified')) is bool
                                    and type(verification.get('reason')) is str
                                    and 0 < len(verification['reason']) <= 128
                                    and all(verification.get(field) is None
                                            or type(verification.get(field)) is str
                                            for field in ('signature', 'payload')))
                return verification

            transport = api.GitHub()
            base = '/repos/nold-ai/specfact-cli'
            repository = metadata(base, 'repository_metadata')
            _original_r_require(type(repository.get('id')) is int and repository['id'] == 1085706003
                                and repository.get('full_name') == 'nold-ai/specfact-cli'
                                and repository.get('name') == 'specfact-cli'
                                and type(repository.get('owner')) is dict)
            owner = repository['owner']
            _original_r_require(type(owner.get('id')) is int and owner['id'] == 225190663
                                and owner.get('login') == 'nold-ai')
            parent = metadata(base + '/git/commits/' + C, 'parent_metadata')
            commit_metadata(parent, C, _ORIGINAL_C_TREE)
            commit = metadata(base + '/git/commits/' + _ORIGINAL_R, 'commit_metadata')
            verification = commit_metadata(commit, _ORIGINAL_R, _ORIGINAL_R_TREE)
            _original_r_require([item['sha'] for item in commit['parents']] == [C]
                                and verification['verified'] is True and verification['reason'] == 'valid'
                                and type(verification.get('signature')) is str and verification['signature']
                                and type(verification.get('payload')) is str and verification['payload'])

            def git(*arguments):
                clock()
                children_check()
                began = time.monotonic_ns()
                end = min(preparation.deadline_ns - 15_000_000_000, account.deadline_ns - 15_000_000_000,
                          began + (300 if arguments[0] == 'fetch' else 360) * 1_000_000_000)
                _original_r_require(began < end)
                record = _OriginalRGit(('/usr/bin/git', *arguments), began, end)
                _original_r_require(len(preparation.commands) < 96
                                    and preparation.metadata_bytes + 65536 <= 8 * MIB
                                    and account.spent_bytes + 131072 <= 255 * MIB)
                preparation.commands += (record,)
                child = None
                owned = False
                group_closed = False
                terminal = None
                reaped_consistently = False
                pipes = []
                chunks = [[], []]
                sizes = [0, 0]
                limits = []
                failure = None
                clean = False
                leader_start = None
                for kind, ceiling in ((resource.RLIMIT_CPU, 240), (resource.RLIMIT_AS, 2147483648),
                                      (resource.RLIMIT_FSIZE, 268435456), (resource.RLIMIT_NPROC, 128),
                                      (resource.RLIMIT_CORE, 0)):
                    soft, hard = resource.getrlimit(kind)
                    hard = ceiling if hard == resource.RLIM_INFINITY else min(hard, ceiling)
                    soft = hard if soft == resource.RLIM_INFINITY else min(soft, hard)
                    limits.append((kind, soft, hard))

                def preexec():
                    signal.signal(signal.SIGALRM, signal.SIG_DFL)
                    signal.pthread_sigmask(signal.SIG_SETMASK, set())
                    for kind, soft, hard in limits:
                        resource.setrlimit(kind, (soft, hard))
                        if resource.getrlimit(kind) != (soft, hard):
                            raise RuntimeError('preparation-child-limit')
                    pid = os.getpid()
                    if pid <= 1 or os.getpgrp() != pid or os.getsid(0) != pid or time.monotonic_ns() >= end:
                        raise RuntimeError('preparation-child-context')

                def observe():
                    nonlocal owned, terminal
                    _original_r_require(owned)
                    try:
                        value = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    except ChildProcessError:
                        owned = False
                        raise
                    if value is not None and value.si_pid:
                        current = (value.si_pid, value.si_code, value.si_status)
                        _original_r_require(value.si_pid == child.pid
                                            and value.si_code in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED)
                                            and (terminal is None or terminal == current))
                        terminal = record.waitid = current

                def identity():
                    nonlocal owned
                    observe()
                    try:
                        valid = child.pid > 1 and os.getpgid(child.pid) == os.getsid(child.pid) == child.pid
                    except ProcessLookupError:
                        valid = False
                    if not valid:
                        owned = False
                    _original_r_require(valid)

                def group_empty(deadline):
                    nonlocal leader_start
                    identity()
                    found = False
                    empty = terminal is not None
                    visit(deadline)
                    with os.scandir('/proc') as entries:
                        while True:
                            visit(deadline)
                            entry = next(entries, None)
                            if entry is None:
                                break
                            if not entry.name.isascii() or not entry.name.isdecimal():
                                continue
                            _original_r_require(len(entry.name) <= 10)
                            visit(deadline)
                            _original_r_require(account.spent_bytes + 3 * 8193 <= 255 * MIB)
                            descriptor = None
                            before = account.spent_bytes
                            try:
                                with _original_r_registration():
                                    descriptor = os.open('/proc/' + entry.name + '/stat',
                                                         os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                                with _original_r_registration():
                                    raw = os.read(descriptor, 8193)
                                    account.read_bytes += len(raw)
                                    charge(3 * len(raw))
                                _original_r_require(0 < len(raw) <= 8192)
                                opening, closing = raw.find(b' ('), raw.rfind(b') ')
                                _original_r_require(opening > 0 and closing > opening)
                                fields = raw[closing + 2:].split()
                                _original_r_require(len(fields) >= 20 and fields[0] in (
                                    b'R', b'S', b'D', b'Z', b'T', b't', b'X', b'x', b'K', b'W', b'P', b'I'))
                                pid = int(raw[:opening])
                                group, session, start = int(fields[2]), int(fields[3]), int(fields[19])
                                _original_r_require(pid == int(entry.name) and min(pid, group, session, start) >= 0)
                                if pid == child.pid:
                                    found = True
                                    _original_r_require(group == session == pid
                                                        and (leader_start is None or start == leader_start))
                                    leader_start = start
                                if group == child.pid:
                                    _original_r_require(session == child.pid)
                                    if not (pid == child.pid and terminal is not None and fields[0] == b'Z'):
                                        empty = False
                            except FileNotFoundError:
                                _original_r_require(int(entry.name) != child.pid)
                            except BaseException:
                                account.spent_bytes = max(account.spent_bytes, before + 3 * 8193)
                                raise
                            finally:
                                if descriptor is not None:
                                    os.close(descriptor)
                    _original_r_require(found)
                    return empty

                def drain():
                    if not pipes:
                        return
                    ready, _, _ = select.select([pipe.fileno() for _, pipe in pipes], [], [], 0)
                    for index, pipe in tuple(pipes):
                        if pipe.fileno() not in ready:
                            continue
                        capacity = min(4 * MIB - sizes[index],
                                       8 * MIB - 65536 - preparation.metadata_bytes)
                        count = min(65536, capacity + 1)
                        _original_r_require(count > 0 and account.spent_bytes
                                            + (len(account.secrets) + 4) * count + 131072 <= 255 * MIB)
                        with _original_r_registration():
                            raw = os.read(pipe.fileno(), count)
                            account.read_bytes += len(raw)
                            charge((len(account.secrets) + 4) * len(raw))
                            _original_r_require(len(raw) <= capacity)
                            if raw:
                                retain(raw)
                                chunks[index].append(raw)
                                sizes[index] += len(raw)
                        if not raw:
                            pipe.close()
                            pipes.remove((index, pipe))

                def group_signal(number):
                    _original_r_require(not group_closed)
                    identity()
                    os.killpg(child.pid, number)

                try:
                    with _original_r_registration():
                        child = subprocess.Popen(record.argv, shell=False, close_fds=True, pass_fds=(),
                                                 start_new_session=True, stdin=subprocess.DEVNULL,
                                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                 env=environment, cwd=root, preexec_fn=preexec)
                        record.process, record.pid = child, child.pid
                        owned = True
                        pipes = list(enumerate((child.stdout, child.stderr)))
                    identity()
                    for _, pipe in pipes:
                        os.set_blocking(pipe.fileno(), False)
                    while terminal is None:
                        clock()
                        _original_r_require(time.monotonic_ns() < end)
                        drain()
                        observe()
                        if terminal is None:
                            time.sleep(min(.01, max(0, (end - time.monotonic_ns()) / 1_000_000_000)))
                except BaseException as error:
                    failure = error
                finally:
                    cleanup_start = time.monotonic_ns()
                    term_end, kill_end, reap_end = (cleanup_start + n * 1_000_000_000 for n in (5, 10, 15))
                    if child is not None and owned:
                        for number, phase_end in ((signal.SIGTERM, term_end), (signal.SIGKILL, kill_end)):
                            try:
                                _original_r_require(time.monotonic_ns() < phase_end)
                                try:
                                    clean = group_empty(phase_end)
                                except BaseException as error:
                                    if failure is None:
                                        failure = error
                                if clean:
                                    break
                                _original_r_require(time.monotonic_ns() < phase_end)
                                group_signal(number)
                                while time.monotonic_ns() < phase_end:
                                    observe()
                                    if failure is None:
                                        drain()
                                    if group_empty(phase_end):
                                        clean = True
                                        break
                                    time.sleep(.02)
                                if clean:
                                    break
                            except BaseException as error:
                                if failure is None:
                                    failure = error
                                if not owned:
                                    break
                        # No group operation is permitted after a waitpid attempt, even if a signal loses its result.
                        group_closed = True
                        while owned and record.wait_status is None and time.monotonic_ns() < reap_end:
                            try:
                                observe()
                                waited, status = os.waitpid(child.pid, os.WNOHANG)
                                if waited:
                                    owned = False
                                    record.wait_status = status
                                    child.returncode = os.waitstatus_to_exitcode(status)
                                    _original_r_require(waited == child.pid and terminal is not None and (
                                        terminal[1] == os.CLD_EXITED and os.WIFEXITED(status)
                                        and os.WEXITSTATUS(status) == terminal[2]
                                        or terminal[1] in (os.CLD_KILLED, os.CLD_DUMPED)
                                        and os.WIFSIGNALED(status) and os.WTERMSIG(status) == terminal[2]
                                        and bool(os.WCOREDUMP(status)) == (terminal[1] == os.CLD_DUMPED)))
                                    reaped_consistently = True
                                    break
                            except ChildProcessError as error:
                                owned = False
                                if failure is None:
                                    failure = error
                            except BaseException as error:
                                if failure is None:
                                    failure = error
                            if owned:
                                time.sleep(.01)
                        try:
                            while pipes and failure is None and time.monotonic_ns() < reap_end:
                                drain()
                                if pipes:
                                    time.sleep(.01)
                        except BaseException as error:
                            if failure is None:
                                failure = error
                    try:
                        record.cleanup_complete = clean and reaped_consistently
                        _original_r_require(record.cleanup_complete and not pipes and failure is None)
                        output = tuple(b''.join(parts) for parts in chunks)
                        for raw in output:
                            sensitive(raw)
                        record.stdout, record.stderr = output
                        clock()
                        _original_r_require(time.monotonic_ns() < end
                                            and child.returncode == 0)
                        record.reason = 'complete'
                    except BaseException as error:
                        if failure is None:
                            failure = error
                    finally:
                        for _, pipe in pipes:
                            try:
                                pipe.close()
                            except BaseException as error:
                                record.cleanup_complete = False
                                if failure is None:
                                    failure = error
                        record.ended_ns = time.monotonic_ns()
                        if failure is not None:
                            record.reason = ('deadline' if isinstance(failure, Deadline)
                                             or time.monotonic_ns() >= end else 'incomplete')
                        before = account.spent_bytes
                        maximum = 131072 + len(record.stdout) + len(record.stderr)
                        _original_r_require(before + maximum <= 255 * MIB)
                        try:
                            receipt = encoded({'argv': record.argv, 'cwd': str(root), 'environment': environment,
                                               'started_ns': record.started_ns, 'deadline_ns': record.deadline_ns,
                                               'ended_ns': record.ended_ns, 'pid': record.pid,
                                               'waitid': record.waitid, 'wait_status': record.wait_status,
                                               'cleanup_complete': record.cleanup_complete, 'reason': record.reason,
                                               'requested_limits': limits,
                                               'stdout_bytes': len(record.stdout), 'stdout_sha256': sha(record.stdout),
                                               'stderr_bytes': len(record.stderr), 'stderr_sha256': sha(record.stderr)})
                            _original_r_require(len(receipt) <= 65536)
                            with _original_r_registration():
                                charge(2 * len(receipt) + len(record.stdout) + len(record.stderr))
                                retain(receipt)
                                record.receipt = receipt
                        except BaseException:
                            account.spent_bytes = max(account.spent_bytes, before + maximum)
                            raise
                _original_r_require(failure is None and record.reason == 'complete')
                return record.stdout

            def config(initial=False):
                raw = git('config', '--no-includes', '--show-origin', '--show-scope', '--null', '--list')
                charge(3 * len(raw))
                if initial:
                    _original_r_require(raw == b'')
                    return
                fields = raw.split(b'\0')
                _original_r_require(fields.pop() == b'' and len(fields) == 12)
                values = {}
                for index in range(0, len(fields), 3):
                    scope, origin, pair = fields[index:index + 3]
                    _original_r_require(scope == b'local' and origin in (
                        b'file:.git/config', b'file:' + os.fsencode(root / '.git/config')))
                    key, separator, value = pair.partition(b'\n')
                    _original_r_require(separator and key not in values)
                    values[key] = value
                _original_r_require(values == {b'core.repositoryformatversion': b'0', b'core.filemode': b'true',
                                               b'core.bare': b'false', b'core.logallrefupdates': b'true'})

            def inventory():
                count = objects = 0

                def walk(descriptor, prefix, depth):
                    nonlocal count, objects
                    _original_r_require(depth <= 64)
                    visit()
                    with os.scandir(descriptor) as entries:
                        while True:
                            visit()
                            entry = next(entries, None)
                            if entry is None:
                                break
                            count += 1
                            _original_r_require(count <= 20000)
                            relative = prefix + entry.name
                            _original_r_require(len(os.fsencode(relative)) <= 4096)
                            visit()
                            value = entry.stat(follow_symlinks=False)
                            _original_r_require(value.st_size >= 0)
                            in_git = relative == '.git' or relative.startswith('.git/')
                            if in_git:
                                _original_r_require(stat.S_ISDIR(value.st_mode) or stat.S_ISREG(value.st_mode))
                                _original_r_require(relative not in (
                                    '.git/info/grafts', '.git/info/sparse-checkout', '.git/info/attributes',
                                    '.git/objects/info/alternates', '.git/objects/info/http-alternates',
                                    '.git/config.worktree', '.git/commondir', '.git/gitdir', '.git/index.lock',
                                    '.git/shallow.lock', '.git/config.lock', '.git/refs/replace', '.git/modules')
                                    and not relative.startswith('.git/hooks/')
                                    and not (relative.startswith('.git/refs/') and stat.S_ISREG(value.st_mode)))
                            _original_r_require(stat.S_ISREG(value.st_mode) or stat.S_ISDIR(value.st_mode)
                                                or not in_git and stat.S_ISLNK(value.st_mode))
                            if relative.startswith('.git/objects/') and stat.S_ISREG(value.st_mode):
                                objects += value.st_size
                                _original_r_require(objects <= 256 * MIB)
                            if stat.S_ISDIR(value.st_mode):
                                owned_descriptor = None
                                try:
                                    visit()
                                    with _original_r_registration():
                                        owned_descriptor = os.open(entry.name,
                                            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                                    walk(owned_descriptor, relative + '/', depth + 1)
                                finally:
                                    if owned_descriptor is not None:
                                        os.close(owned_descriptor)

                walk(preparation.root.descriptor, '', 0)
                preparation.scans += ((count, objects),)

            def read_file(relative, maximum):
                clock()
                parts = relative.split('/')
                _original_r_require(parts and all(part and part not in ('.', '..') for part in parts))
                owned_descriptors = []
                descriptor = preparation.root.descriptor
                try:
                    for component in parts[:-1]:
                        visit()
                        with _original_r_registration():
                            descriptor = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                                 dir_fd=descriptor)
                            owned_descriptors.append(descriptor)
                    visit()
                    before = os.stat(parts[-1], dir_fd=descriptor, follow_symlinks=False)
                    _original_r_require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                                        and before.st_uid == os.getuid() and 0 <= before.st_size <= maximum)
                    charge((len(account.secrets) + 4) * (before.st_size + 1))
                    with _original_r_registration():
                        opened = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                         dir_fd=descriptor)
                        owned_descriptors.append(opened)
                    def identity(value):
                        return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
                                value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
                    visit()
                    _original_r_require(identity(os.fstat(opened)) == identity(before))
                    with _original_r_registration():
                        raw = os.read(opened, before.st_size + 1)
                        account.read_bytes += len(raw)
                    _original_r_require(len(raw) == before.st_size)
                    sensitive(raw)
                    visit()
                    _original_r_require(identity(os.fstat(opened)) == identity(before))
                    visit()
                    _original_r_require(identity(os.stat(parts[-1], dir_fd=descriptor, follow_symlinks=False))
                                        == identity(before))
                    clock()
                    return raw
                finally:
                    close_error = None
                    for descriptor in reversed(owned_descriptors):
                        try:
                            os.close(descriptor)
                        except BaseException as error:
                            if close_error is None:
                                close_error = error
                    if close_error is not None:
                        raise close_error

            config(initial=True)
            git('init', '--template=' + str(preparation.template.path), '.')
            config()
            git('fetch', '--depth=2', '--no-tags', '--no-recurse-submodules',
                'https://github.com/nold-ai/specfact-cli.git', _ORIGINAL_R)
            inventory()
            config()
            _original_r_require(read_file('.git/shallow', 41) == (C + '\n').encode())
            _original_r_require(git('for-each-ref', '--format=%(refname)') == b'')
            git('fsck', '--full', '--strict', '--no-reflogs')
            raw_commit = git('cat-file', 'commit', _ORIGINAL_R)
            charge(5 * len(raw_commit))
            _original_r_require(sha(raw_commit) == _ORIGINAL_R_RAW)
            header, separator, message = raw_commit.partition(b'\n\n')
            _original_r_require(separator)
            lines = header.split(b'\n')
            _original_r_require([line[7:] for line in lines if line.startswith(b'parent ')] == [C.encode()]
                                and lines[0] == b'tree ' + _ORIGINAL_R_TREE.encode())
            payload_lines, signature_lines = [], []
            in_signature = False
            for line in lines:
                if line.startswith(b'gpgsig '):
                    _original_r_require(not signature_lines)
                    signature_lines.append(line[7:])
                    in_signature = True
                elif in_signature and line.startswith(b' '):
                    signature_lines.append(line[1:])
                else:
                    in_signature = False
                    payload_lines.append(line)
            _original_r_require(b'\n'.join(signature_lines).rstrip(b'\n')
                                == verification['signature'].encode().rstrip(b'\n')
                                and b'\n'.join(payload_lines) + b'\n\n' + message
                                == verification['payload'].encode())
            _original_r_require(git('rev-parse', C + '^{tree}') == (_ORIGINAL_C_TREE + '\n').encode())
            _original_r_require(git('rev-parse', _ORIGINAL_R + '^{tree}') == (_ORIGINAL_R_TREE + '\n').encode())
            git('merge-base', '--is-ancestor', C, _ORIGINAL_R)
            _original_r_require(git('rev-list', '--reverse', C + '..' + _ORIGINAL_R)
                                == (_ORIGINAL_R + '\n').encode())
            _original_r_require(git('rev-list', '--parents', '-n', '1', _ORIGINAL_R)
                                == (_ORIGINAL_R + ' ' + C + '\n').encode())
            _original_r_require(git('merge-base', C, _ORIGINAL_R) == (C + '\n').encode())
            changed = git('diff', '--name-status', '-z', '--find-renames', _ORIGINAL_R + '^', _ORIGINAL_R)
            charge(3 * len(changed))
            fields = changed.split(b'\0')
            _original_r_require(fields.pop() == b'')
            index = 0
            while index < len(fields):
                status = fields[index]
                index += 1
                count = 2 if status.startswith((b'R', b'C')) else 1
                _original_r_require(index + count <= len(fields))
                for path in fields[index:index + count]:
                    _original_r_require(path not in (b'pyproject.toml', b'setup.py', b'uv.lock')
                                        and not path.startswith((b'.github/', b'ci/', b'scripts/', b'src/',
                                            b'tools/', b'resources/templates/', b'resources/schemas/',
                                            b'resources/mappings/', b'resources/keys/', b'requirements/',
                                            b'modules/bundle-mapper/')))
                index += count
            tree = git('ls-tree', '-r', '--full-tree', '-z', _ORIGINAL_R)
            charge(4 * len(tree))
            tree_entries = {}
            for line in tree.removesuffix(b'\0').split(b'\0'):
                fields, separator, path = line.partition(b'\t')
                mode, kind, object_id = fields.split(b' ')
                _original_r_require(separator and kind == b'blob' and mode in (b'100644', b'100755', b'120000')
                                    and re.fullmatch(b'[0-9a-f]{40}', object_id) is not None
                                    and path not in tree_entries and not path.startswith(b'/')
                                    and all(part and part not in (b'.', b'..', b'.git') for part in path.split(b'/'))
                                    and path.rsplit(b'/', 1)[-1] != b'.gitmodules')
                tree_entries[path] = (mode, object_id)
            _original_r_require(tree.endswith(b'\0') and len(tree_entries) <= 20000)
            git('checkout', '--detach', _ORIGINAL_R)
            inventory()
            config()
            _original_r_require(read_file('.git/HEAD', 41) == (_ORIGINAL_R + '\n').encode()
                                and read_file('.git/shallow', 41) == (C + '\n').encode())
            _original_r_require(git('rev-parse', 'HEAD') == (_ORIGINAL_R + '\n').encode()
                                and git('for-each-ref', '--format=%(refname)') == b'')
            staged = git('ls-files', '--stage', '-z')
            charge(4 * len(staged))
            actual_index = {}
            for line in staged.removesuffix(b'\0').split(b'\0'):
                fields, separator, path = line.partition(b'\t')
                mode, object_id, stage = fields.split(b' ')
                _original_r_require(separator and stage == b'0' and path not in actual_index)
                actual_index[path] = (mode, object_id)
            _original_r_require(staged.endswith(b'\0') and actual_index == tree_entries)
            flags = git('ls-files', '-v', '-z')
            charge(3 * len(flags))
            _original_r_require(flags.endswith(b'\0') and all(line.startswith(b'H ')
                for line in flags[:-1].split(b'\0')))
            git('diff', '--cached', '--exit-code', '--no-ext-diff', '--no-textconv', _ORIGINAL_R, '--')
            git('diff-files', '--exit-code', '--no-ext-diff', '--no-textconv', '--')
            _original_r_require(git('status', '--porcelain=v1', '-z', '--untracked-files=all', '--ignored=matching') == b'')
            for path, digest in _ORIGINAL_R_SOURCES:
                _original_r_require(os.fsencode(path) in tree_entries
                                    and tree_entries[os.fsencode(path)][0] in (b'100644', b'100755'))
                blob = git('cat-file', 'blob', _ORIGINAL_R + ':' + path)
                source = read_file(path, 4 * MIB)
                charge(3 * len(blob))
                _original_r_require(blob == source and sha(blob) == sha(source) == digest)
            inventory()
            _owned_root_check(account)
            children_check()
            clock()
            result = _PreparedOriginalR(root, account.root.path, preparation.home.path, preparation.tmp.path,
                                        _ORIGINAL_R, C, _ORIGINAL_R_TREE, _ORIGINAL_C_TREE,
                                        _ORIGINAL_R_RAW, _ORIGINAL_R_SOURCES)
        _original_r_require(not timer.expired and not timer.pending
                            and time.monotonic_ns() < preparation.deadline_ns
                            and time.monotonic_ns() < account.deadline_ns)
        preparation.complete = True
        return result
    except BaseException:
        if type(account) is _AttemptAccount:
            account.stopped = True
            if type(account.preparation) is _OriginalRPreparation:
                account.preparation.complete = False
        raise _OriginalRPreparationError('Original R preparation refused') from None



if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print('Preflight stopped. Exception class ' + type(error).__name__)
        raise SystemExit(1)
