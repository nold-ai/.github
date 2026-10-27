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
import stat
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import asdict
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
HELPER_MANIFEST = (('observation.py', 63718, '0ef26b2a26ed050a90636b12c4b05b01d907b3f7ae78bac523e371cf4ebc1d0d', '_dev786_original_replay_observation'), ('replay.py', 59108, 'de4e2aa88d99949e6fa3b4fd47c295c9d08bddba2c089a7ec17b7ba52d9866d3', '_dev786_original_replay_replay'))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


HELPER_LIMITS = ()


def _load_helpers():
    root = Path(__file__).parent
    require(len(HELPER_MANIFEST) == 2 and len(HELPER_LIMITS) == 3, 'missing helper initialization plan')
    read_limit, closure_read, source_limit = HELPER_LIMITS
    require(sum(entry[1] for entry in HELPER_MANIFEST) <= source_limit, 'helper source budget')
    names = ('preflight.py', 'fixtures') + tuple(entry[0] for entry in HELPER_MANIFEST)
    plan = [('directory', 'directory-entry', 255) for _ in range(len(names) + 1)]
    plan.append(('helpers', 'order-compare', sum(len(name) for name in names)))
    for name, size, digest, module_name in HELPER_MANIFEST:
        plan.extend(((name, 'source-read', size + 1), (name, 'source-hash', size),
                     (name, 'identity-compare', 128 + len(name) + len(module_name)),
                     (name, 'source-submit', size)))
    metadata = sum(len(name) + len(operation) + 48 for name, operation, _ in plan)
    plan.append(('initialization', 'receipt-copy', metadata))
    adoption = metadata + sum(len(name) + len(module_name) + 128 for name, _, _, module_name in HELPER_MANIFEST) + 4096
    plan.append(('initialization', 'adoption-compare', adoption))
    plan = tuple(plan)
    envelope = sum(amount for _, _, amount in plan)
    require(envelope + closure_read <= read_limit, 'helper initialization allowance')
    actual = [0] * len(plan)
    consumed = set()

    def debit(name, operation, size):
        for index, (planned_name, planned_operation, requested) in enumerate(plan):
            if index not in consumed and planned_name == name and planned_operation == operation:
                require(0 <= size <= requested, 'helper initialization debit')
                consumed.add(index)
                actual[index] = size
                return index
        raise ValueError('unplanned helper operation')

    sources = []
    registered = []
    try:
        require(stat.S_ISDIR(root.lstat().st_mode), 'helper directory kind')
        seen = set()
        with os.scandir(root) as entries:
            while True:
                index = debit('directory', 'directory-entry', 255)
                entry = next(entries, None)
                actual[index] = 0 if entry is None else len(entry.name)
                if entry is None:
                    break
                require(entry.name in names and entry.name not in seen, 'helper source membership')
                seen.add(entry.name)
        debit('helpers', 'order-compare', sum(len(name) for name in names))
        require(seen == set(names), 'helper source membership')
        require(stat.S_ISDIR((root / 'fixtures').lstat().st_mode), 'fixture directory kind')
        require(stat.S_ISREG((root / 'preflight.py').lstat().st_mode), 'driver source kind')
        for name, size, digest, module_name in HELPER_MANIFEST:
            require(module_name not in sys.modules, 'preloaded helper module')
            path = root / name
            require(stat.S_ISREG(path.lstat().st_mode), 'helper source kind')
            index = debit(name, 'source-read', size + 1)
            with path.open('rb') as stream:
                require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'opened helper source kind')
                raw = stream.read(size + 1)
            actual[index] = len(raw)
            require(len(raw) == size, 'helper source length')
            debit(name, 'source-hash', size)
            calculated = hashlib.sha256(raw).hexdigest()
            debit(name, 'identity-compare', 128 + len(name) + len(module_name))
            require(calculated == digest, 'helper source identity')
            sources.append((path, module_name, raw))
        for path, module_name, raw in sources:
            spec = importlib.util.spec_from_file_location(module_name, path)
            module = importlib.util.module_from_spec(spec)
            if registered:
                module.__dict__['_observation'] = registered[0][1]
                module.__dict__['_driver'] = sys.modules[__name__]
            sys.modules[module_name] = module
            registered.append((module_name, module))
            debit(path.name, 'source-submit', len(raw))
            exec(compile(raw, str(path), 'exec'), module.__dict__)
        observation, replay = (entry[1] for entry in registered)
        debit('initialization', 'receipt-copy', metadata)
        itinerary = tuple(observation.ReadDebit(name, operation, requested, actual[index])
                          for index, (name, operation, requested) in enumerate(plan))
        initialization = observation.InitializationReceipt(
            tuple(observation.FixedHelperIdentity(*entry) for entry in HELPER_MANIFEST), itinerary,
            observation.Usage(traversal_bytes=sum(actual)), observation.Usage(),
            observation.Usage(traversal_bytes=envelope), observation.Usage(traversal_bytes=adoption))
        replay._loaded_initialization = initialization
        return SimpleNamespace(observation=observation, replay=replay, initialization=initialization)
    except BaseException as error:
        for module_name, module in reversed(registered):
            if sys.modules.get(module_name) is module:
                del sys.modules[module_name]
        if isinstance(error, OSError):
            raise ValueError('helper source unavailable') from error
        raise


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


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print('Preflight stopped. Exception class ' + type(error).__name__)
        raise SystemExit(1)
