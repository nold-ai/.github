from __future__ import annotations

import ast
import dataclasses
import dis
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager
from types import MappingProxyType


HERE = Path(__file__).resolve().parent
HELPERS = ("observation.py", "replay.py")
MODULES = ("_dev786_original_replay_observation", "_dev786_original_replay_replay")
STAGE = "synthetic-capture-handoff"
ENVIRONMENT = (
    (b"HOME", b"/owned/home"), (b"TMPDIR", b"/owned/tmp"),
    (b"PATH", b"/owned/bin:/usr/bin:/bin"), (b"LC_ALL", b"C.UTF-8"),
    (b"VIRTUAL_ENV", b"/owned/venv"), (b"SPECFACT_MODULES_REPO", b"/owned/modules"),
    (b"SPECFACT_MODULES_ROOTS", b"/owned/modules/packages"),
)
RAW_ENVIRONMENT = (
    b'["HOME=/owned/home", "TMPDIR=/owned/tmp", "PATH=/owned/bin:/usr/bin:/bin", '
    b'"LC_ALL=C.UTF-8", "VIRTUAL_ENV=/owned/venv", "SPECFACT_MODULES_REPO=/owned/modules", '
    b'"SPECFACT_MODULES_ROOTS=/owned/modules/packages"]'
)
EXEC = (
    b'1700000000.000001 execve("/owned/bin/first", ["/owned/bin/first", "literal,..."], '
    + RAW_ENVIRONMENT + b') = 0\n'
)
EXIT = b'1700000000.000020 exit_group(7) = ?\n'
TERMINAL = b'1700000000.000021 +++ exited with 7 +++\n'
KILLED = b'1700000000.000021 +++ killed by SIGTERM +++\n'
UNSUPPORTED = b'1700000000.000010 future_probe(0) = 0\n'
TRACER = (
    b"/usr/bin/strace", b"-ff", b"-v", b"-s", b"131072", b"-yy", b"-ttt", b"-e",
    b"trace=%process,%file,fchdir,getcwd,close,close_range,dup,dup2,dup3,fcntl,unshare,setsid,setpgid",
    b"-o", b"/owned/traces/trace",
)
BINARY_BYTES = b"Synthetic first executable identity, never executed"
CONTENT_MARKER = b"dev786-harmless-sensitive-content-786"
NAME_MARKER = b"dev786-harmless-sensitive-name-786"
NEW_TYPES = (
    "MemberId", "Complete", "Partial", "Withheld", "StableFinalSize",
    "ObservedLowerBound", "TraceAssociation", "CaptureEnd", "WaitExited",
    "WaitSignaled", "WaitMissing", "Killed", "Usage", "Checkpoint",
    "Book", "Incomplete", "MemberOccurrence", "TaskOccurrence", "OperationReceipt",
    "InitializationReceipt", "ReadDebit", "FixedHelperIdentity",
)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def load_test_file(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError("The fixed existing test support file must be loadable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        if sys.modules.get(name) is module:
            del sys.modules[name]
    return module


def wire(value):
    if dataclasses.is_dataclass(value):
        kind = type(value).__name__
        if kind == "MemberOccurrence":
            return {"scope": value.scope, "role": value.role, "member_id": wire(value.member.member_id),
                    "association": wire(value.association), "prefix": wire(value.prefix)}
        if kind == "TaskOccurrence":
            witness = ({"launch_task": wire(value.witness.task)} if hasattr(value.witness, "task")
                       else {"birth_refs": wire(value.witness)})
            return {"key": wire(value.key), **witness}
        return {field.name: ({"session_id": value.session_id, "operation_sequence": value.operation_sequence}
                            if kind == "Checkpoint" and field.name == "basis"
                            else wire(getattr(value, field.name))) for field in dataclasses.fields(value)}
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (tuple, list)):
        return [wire(item) for item in value]
    if isinstance(value, dict):
        return {key: wire(item) for key, item in value.items()}
    if hasattr(value, "value") and type(value).__module__ == MODULES[0]:
        return value.value
    return value


class StopObservedWork(BaseException):
    pass


class SourceVisits:
    def __init__(self, *modules, watch=(), detail=False):
        self.modules = modules
        self.watch = watch
        self.detail = detail
        self.sites = {}
        self.events = {}
        self.presented_bytes = {}
        self.visited_bytes = {}
        self.occurrences = {}
        self.watched = {}
        self.instructions = {}
        self.iterations = {}
        self.observed_bytes = 0
        for module in modules:
            filename = str(Path(module.__file__).resolve())
            tree = ast.parse(Path(filename).read_bytes())
            self.sites[filename] = {
                (node.lineno, node.end_lineno, node.col_offset, node.end_col_offset): node
                for node in ast.walk(tree) if isinstance(node, (ast.Call, ast.Subscript, ast.For))
            }

    def site(self, frame, expected, *, required=True):
        if frame.f_code not in self.instructions:
            table = {}
            previous = None
            for instruction in dis.get_instructions(frame.f_code, show_caches=True):
                if instruction.opname != "CACHE":
                    previous = instruction
                table[instruction.offset] = previous
            self.instructions[frame.f_code] = table
        instruction = self.instructions[frame.f_code].get(frame.f_lasti)
        if instruction is None:
            raise AssertionError("Required visit has no exact opcode position")
        position = instruction.positions
        coordinates = (position.lineno, position.end_lineno, position.col_offset, position.end_col_offset)
        node = self.sites[frame.f_code.co_filename].get(coordinates)
        if not isinstance(node, expected):
            if not required:
                return None, None
            raise AssertionError(f"Required visit has no exact AST operation: {frame.f_code.co_filename}:{coordinates}")
        return node, (frame.f_code.co_filename, *coordinates, instruction.offset)

    def operand(self, node, frame):
        if isinstance(node, ast.Name):
            if node.id in frame.f_locals:
                return frame.f_locals[node.id]
            if node.id in frame.f_globals:
                return frame.f_globals[node.id]
        elif isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.Attribute):
            value = self.operand(node.value, frame)
            if dataclasses.is_dataclass(value) and node.attr in {field.name for field in dataclasses.fields(value)}:
                return object.__getattribute__(value, node.attr)
            try:
                fields = object.__getattribute__(value, "__dict__")
            except AttributeError:
                fields = {}
            if node.attr in fields:
                return fields[node.attr]
        elif isinstance(node, ast.Subscript):
            value, index = self.operand(node.value, frame), self.operand(node.slice, frame)
            if type(value) in (tuple, list, dict) and not isinstance(index, slice):
                return value[index]
        elif isinstance(node, ast.Slice):
            return slice(*(self.operand(part, frame) if part is not None else None
                           for part in (node.lower, node.upper, node.step)))
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
            value = self.operand(node.operand, frame)
            if type(value) is int:
                return -value if isinstance(node.op, ast.USub) else value
        elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub)):
            left, right = self.operand(node.left, frame), self.operand(node.right, frame)
            if type(left) is int and type(right) is int:
                return left + right if isinstance(node.op, ast.Add) else left - right
        elif isinstance(node, (ast.Tuple, ast.List)):
            return tuple(self.operand(item, frame) for item in node.elts)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "len" and len(node.args) == 1:
            value = self.operand(node.args[0], frame)
            if type(value) in (bytes, bytearray, str, tuple, list, dict):
                return len(value)
        raise AssertionError(f"Required visit input is unresolved: {ast.dump(node, include_attributes=False)}")

    def record(self, frame, labels, operation, raw, extent, visited, expected=ast.Call):
        _, position = self.site(frame, expected)
        if not 0 <= visited <= extent:
            raise AssertionError("Observed byte bounds must describe the actual input extent")
        if not visited:
            return
        key = (tuple(sorted(labels)), operation, *position)
        self.events[key] = self.events.get(key, 0) + 1
        self.presented_bytes[key] = self.presented_bytes.get(key, 0) + extent
        self.visited_bytes[key] = self.visited_bytes.get(key, 0) + visited
        self.observed_bytes += visited
        if self.detail:
            signature = (type(raw).__name__, extent, visited)
            self.occurrences.setdefault(key, []).append(signature)
        for watched in self.watch:
            if raw is watched or isinstance(raw, memoryview) and raw.obj is watched:
                self.watched.setdefault(id(watched), set()).add(key)

    def input_call(self, frame, label, operation, raw):
        if type(raw) not in (bytes, bytearray, str, memoryview):
            raise AssertionError("Required delegated visit has an unsupported input type")
        extent = raw.nbytes if isinstance(raw, memoryview) else len(raw)
        visited_lower_bound = min(1, extent) if label == "regex" else extent
        self.record(frame, (label,), operation, raw, extent, visited_lower_bound)

    def trace(self, frame, event, arg):
        filename = frame.f_code.co_filename
        if filename not in self.sites:
            return None
        frame.f_trace_opcodes = True
        if event == "return":
            for key in tuple(self.iterations):
                if key[0] is frame:
                    del self.iterations[key]
        if event != "opcode":
            return self.trace
        opcode = dis.opname[frame.f_code.co_code[frame.f_lasti]]
        if opcode in ("BINARY_SUBSCR", "BINARY_SLICE"):
            node, _ = self.site(frame, ast.Subscript)
            raw = self.operand(node.value, frame)
            if type(raw) in (bytes, bytearray, str):
                selected = self.operand(node.slice, frame)
                if (isinstance(selected, slice) and type(raw) in (bytes, str)
                        and selected.indices(len(raw)) == (0, len(raw), 1)):
                    return self.trace
                extent = len(range(*selected.indices(len(raw)))) if isinstance(selected, slice) else int(-len(raw) <= selected < len(raw))
                labels = {"copy"} if isinstance(selected, slice) else {"scan"}
                if frame.f_code.co_name in ("_fields", "_string"):
                    labels.add("field" if frame.f_code.co_name == "_fields" else "string")
                self.record(frame, labels, "slice" if isinstance(selected, slice) else "index",
                            raw, extent, extent, ast.Subscript)
        elif opcode == "FOR_ITER" and frame.f_code.co_name == "_fields":
            node, position = self.site(frame, ast.For)
            iterable = node.iter
            if isinstance(iterable, ast.Call) and isinstance(iterable.func, ast.Name) and iterable.func.id == "enumerate":
                iterable = iterable.args[0]
            raw = self.operand(iterable, frame)
            if type(raw) in (bytes, bytearray, str):
                key = (frame, position)
                index = self.iterations.get(key, 0)
                if index < len(raw):
                    self.record(frame, ("field",), "byte-iteration", raw, 1, 1, ast.For)
                    self.iterations[key] = index + 1
                else:
                    self.iterations.pop(key, None)
        elif opcode in ("CALL", "CALL_KW", "CALL_FUNCTION_EX"):
            node, _ = self.site(frame, ast.Call, required=False)
            if node is not None and isinstance(node.func, ast.Name) and node.func.id in ("bytes", "bytearray") and node.args:
                raw = self.operand(node.args[0], frame)
                if type(raw) in (bytes, bytearray, tuple, list) and not (node.func.id == "bytes" and type(raw) is bytes):
                    self.record(frame, ("copy",), node.func.id, raw, len(raw), len(raw))
        return self.trace

    def profile(self, frame, event, function):
        if event != "c_call" or frame.f_code.co_filename not in self.sites:
            return
        receiver = getattr(function, "__self__", None)
        name = getattr(function, "__name__", "")
        if type(receiver) in (bytes, bytearray, str) and name in ("find", "index", "count", "splitlines"):
            node, _ = self.site(frame, ast.Call)
            arguments = [self.operand(item, frame) for item in node.args]
            if name == "splitlines":
                extent = visited = len(receiver)
            else:
                start = arguments[1] if len(arguments) > 1 else None
                stop = arguments[2] if len(arguments) > 2 else None
                extent = len(range(*slice(start, stop).indices(len(receiver))))
                has_input = arguments and (type(arguments[0]) is int or bool(arguments[0]))
                visited = (extent if name == "count" else min(1, extent)) if has_input else 0
            self.record(frame, ("framing",), name, receiver, extent, visited)
        elif isinstance(receiver, re.Pattern) and name in ("fullmatch", "match", "search", "finditer"):
            node, _ = self.site(frame, ast.Call)
            if name == "finditer" or not node.args:
                raise AssertionError("Lazy regex traversal requires a resolved iteration observer")
            self.input_call(frame, "regex", name, self.operand(node.args[0], frame))
        elif (getattr(function, "__module__", "") in ("_hashlib", "_sha256")
              or type(receiver).__module__ in ("_hashlib", "_sha256")) and name not in ("digest", "hexdigest", "copy"):
            raise AssertionError("Native hash work escaped the actual-input delegating observer")

    def __enter__(self):
        self.previous = sys.gettrace()
        self.previous_profile = sys.getprofile()
        self.restores = []
        observer = self
        real_sha256 = hashlib.sha256

        class ObservedHash:
            def __init__(self, actual):
                self.actual = actual

            def update(self, data, /):
                frame = sys._getframe(1)
                if frame.f_code.co_filename in observer.sites:
                    observer.input_call(frame, "hash", "update", data)
                return self.actual.update(data)

            def copy(self):
                return ObservedHash(self.actual.copy())

            def __getattr__(self, name):
                return getattr(self.actual, name)

        def observed_sha256(data=b"", *args, **kwargs):
            frame = sys._getframe(1)
            if frame.f_code.co_filename not in self.sites:
                return real_sha256(data, *args, **kwargs)
            self.input_call(frame, "hash", "sha256", data)
            return ObservedHash(real_sha256(data, *args, **kwargs))

        replacements = [(hashlib, "sha256", real_sha256, observed_sha256)]
        for name in ("fullmatch", "match", "search", "finditer"):
            actual = getattr(re, name)

            def observed_regex(pattern, string, *args, _actual=actual, _name=name, **kwargs):
                frame = sys._getframe(1)
                if frame.f_code.co_filename in self.sites:
                    if _name == "finditer":
                        raise AssertionError("Lazy regex traversal requires a resolved iteration observer")
                    self.input_call(frame, "regex", _name, string)
                return _actual(pattern, string, *args, **kwargs)

            replacements.append((re, name, actual, observed_regex))
        for module, name, actual, replacement in replacements:
            self.restores.append((module, name, actual))
            setattr(module, name, replacement)
            for owned in self.modules:
                for alias, value in tuple(vars(owned).items()):
                    if value is actual:
                        self.restores.append((owned, alias, actual))
                        setattr(owned, alias, replacement)
        sys.setprofile(self.profile)
        sys.settrace(self.trace)
        return self

    def __exit__(self, *unused):
        sys.settrace(self.previous)
        sys.setprofile(self.previous_profile)
        for module, name, actual in reversed(self.restores):
            setattr(module, name, actual)
        self.events = MappingProxyType(self.events)
        self.presented_bytes = MappingProxyType(self.presented_bytes)
        self.visited_bytes = MappingProxyType(self.visited_bytes)
        self.occurrences = MappingProxyType({key: tuple(items) for key, items in self.occurrences.items()})
        self.watched = MappingProxyType({key: frozenset(items) for key, items in self.watched.items()})
        self.sites.clear()
        self.instructions.clear()
        self.iterations.clear()

    def entries(self, label, raw=None):
        selected = {key for key in self.events if label in key[0]}
        return selected if raw is None else selected & self.watched.get(id(raw), set())


@contextmanager
def interrupt_canonical_store(owner, replay, *, after):
    filename = str(Path(replay.__file__).resolve())
    tree = ast.parse(Path(filename).read_bytes())
    assignments = {
        node.lineno: node.value.id for node in ast.walk(tree)
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name)
        and any(isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name)
                and target.value.id == "self" and target.attr == "_state" for target in node.targets)
    }
    unittest.TestCase().assertTrue(assignments, "NEW atomic prepared _State installation must be source-observable")
    observation = {"hit": False, "candidate": None}
    instructions = {}
    pending_after = None

    def trace(frame, event, arg):
        nonlocal pending_after
        if frame.f_code.co_filename != filename or frame.f_locals.get("self") is not owner:
            return None
        frame.f_trace_opcodes = True
        if event != "opcode":
            return trace
        if pending_after is frame:
            pending_after = None
            observation["hit"] = True
            unittest.TestCase().assertIs(owner._snapshot, observation["candidate"])
            raise StopObservedWork()
        if frame.f_code not in instructions:
            instructions[frame.f_code] = {item.offset: item for item in dis.get_instructions(frame.f_code)}
        table = instructions[frame.f_code]
        instruction = table.get(frame.f_lasti)
        if instruction is None or instruction.opname != "STORE_ATTR" or instruction.argval != "_state":
            return trace
        name = assignments.get(instruction.positions.lineno)
        candidate = frame.f_locals.get(name) if name is not None else None
        if candidate is None or candidate.pending is not None or owner._snapshot.pending is None:
            return trace
        if len(candidate.book.stages) != len(owner._snapshot.book.stages) + 1:
            return trace
        observation["candidate"] = candidate
        if after:
            pending_after = frame
        else:
            observation["hit"] = True
            raise StopObservedWork()
        return trace

    previous = sys.gettrace()
    sys.settrace(trace)
    try:
        yield observation
    finally:
        sys.settrace(previous)


LOADER_CHILD = r'''
import dataclasses
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import types

root, action = Path(sys.argv[1]), sys.argv[2]
names = ("_dev786_original_replay_observation", "_dev786_original_replay_replay")
files = ("observation.py", "replay.py")
spec = importlib.util.spec_from_file_location("_dev786_handoff_driver", root / "preflight.py")
driver = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = driver
spec.loader.exec_module(driver)
loader = getattr(driver, "_load_helpers", None)
if not callable(loader):
    print(json.dumps({"state": "NEW_LOADER_UNAVAILABLE"}))
    raise SystemExit(0)
before_path = tuple(sys.path)
executed, registered = [], []
source_work, source_values, directory_entries = [], [], []
real_open, real_iterdir, real_scandir, real_sha256 = Path.open, Path.iterdir, os.scandir, hashlib.sha256
path_iteration = 0
class ObservedSource:
    def __init__(self, stream, name):
        self.stream, self.name = stream, name
    def __enter__(self):
        self.stream.__enter__()
        return self
    def __exit__(self, *args):
        return self.stream.__exit__(*args)
    def __getattr__(self, name):
        return getattr(self.stream, name)
    def read(self, requested=-1):
        raw = self.stream.read(requested)
        source_work.append(["source-read", self.name, requested, len(raw)])
        source_values.append((self.name, raw))
        return raw
def observed_open(path, *args, **kwargs):
    stream = real_open(path, *args, **kwargs)
    return ObservedSource(stream, path.name) if path.parent == root and path.name in files else stream
def observed_iterdir(path):
    global path_iteration
    iterator = real_iterdir(path)
    try:
        while True:
            path_iteration += 1
            try:
                entry = next(iterator)
            except StopIteration:
                return
            finally:
                path_iteration -= 1
            if path == root:
                directory_entries.append(entry.name)
            yield entry
    finally:
        iterator.close()
class ObservedDirectory:
    def __init__(self, iterator, watched):
        self.iterator, self.watched = iterator, watched
    def __enter__(self):
        self.iterator.__enter__()
        return self
    def __exit__(self, *args):
        return self.iterator.__exit__(*args)
    def __iter__(self):
        return self
    def __next__(self):
        entry = next(self.iterator)
        if not path_iteration and self.watched:
            directory_entries.append(os.fsdecode(entry.name))
        return entry
    def close(self):
        return self.iterator.close()
def observed_scandir(path="."):
    if isinstance(path, int):
        current, expected = os.fstat(path), root.stat()
        watched = (current.st_dev, current.st_ino) == (expected.st_dev, expected.st_ino)
    else:
        watched = Path(os.fsdecode(path)) == root
    return ObservedDirectory(real_scandir(path), watched)
def observed_sha256(raw=b"", *args, **kwargs):
    for name, delivered in source_values:
        if raw is delivered:
            source_work.append(["source-hash", name, len(raw), len(raw)])
    return real_sha256(raw, *args, **kwargs)
Path.open, Path.iterdir, os.scandir, hashlib.sha256 = observed_open, observed_iterdir, observed_scandir, observed_sha256
foreign = types.ModuleType("_dev786_handoff_unrelated")
sys.modules[foreign.__name__] = foreign
preloaded = None
if action.startswith("preloaded-"):
    index = 0 if action.endswith("observation") else 1
    preloaded = types.ModuleType(names[index])
    preloaded.__file__ = str(root / files[index])
    sys.modules[names[index]] = preloaded
class StopLoading(BaseException):
    pass
armed = action.startswith("interrupt-")
target = "observation.py" if action.endswith("observation") else "replay.py"
def observe(event, args):
    global armed
    if event == "compile":
        path = Path(args[1])
        if path.parent == root and path.name in files:
            source_work.append(["source-submit", path.name, len(args[0]), len(args[0])])
    if event != "exec":
        return
    path = Path(args[0].co_filename)
    if path.parent != root or path.name not in files:
        return
    executed.append(path.name)
    index = files.index(path.name)
    registered.append(sys.modules.get(names[index]) is not None)
    if armed and path.name == target:
        armed = False
        raise StopLoading()
sys.addaudithook(observe)
try:
    loaded = loader()
except StopLoading:
    rolled_back = all(name not in sys.modules for name in names)
    first = list(executed)
    executed.clear()
    loaded = loader()
    print(json.dumps({"state": "INTERRUPTED_THEN_LOADED", "first": first,
                      "retry": executed, "registered_before_exec": all(registered),
                      "rolled_back": rolled_back, "path_unchanged": tuple(sys.path) == before_path,
                      "unrelated_preserved": sys.modules.get(foreign.__name__) is foreign,
                      "registered": all(sys.modules.get(name) is getattr(loaded, attr)
                                        for name, attr in zip(names, ("observation", "replay")))}))
except ValueError:
    print(json.dumps({"state": "REFUSED", "executed": executed,
                      "source_work": source_work, "directory_entries": directory_entries,
                      "path_unchanged": tuple(sys.path) == before_path,
                      "unrelated_preserved": sys.modules.get(foreign.__name__) is foreign,
                      "preload_preserved": preloaded is None or sys.modules.get(preloaded.__name__) is preloaded,
                      "owned_registrations_absent": all(name not in sys.modules or sys.modules[name] is preloaded
                                                       for name in names)}))
else:
    identities = loaded.initialization.helper_identities
    print(json.dumps({"state": "LOADED", "executed": executed,
                      "registered_before_exec": all(registered),
                      "path_unchanged": tuple(sys.path) == before_path,
                      "registered": all(sys.modules.get(name) is getattr(loaded, attr)
                                        for name, attr in zip(names, ("observation", "replay"))),
                      "files": [getattr(loaded, attr).__file__ for attr in ("observation", "replay")],
                      "initialization_immutable": dataclasses.is_dataclass(loaded.initialization)
                          and loaded.initialization.__dataclass_params__.frozen,
                      "initialization_helpers": [item.name for item in identities],
                      "initialization_reads": loaded.initialization.measured_usage.traversal_bytes,
                      "initialization": dataclasses.asdict(loaded.initialization),
                      "source_work": source_work, "directory_entries": directory_entries}))
finally:
    Path.open, Path.iterdir, os.scandir, hashlib.sha256 = real_open, real_iterdir, real_scandir, real_sha256
'''


CONTROL_CHILD = r'''
import dataclasses
import enum
import importlib.util
import json
from pathlib import Path
import sys

root, owned, policy = map(Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location("_dev786_control_driver", root / "preflight.py")
driver = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = driver
spec.loader.exec_module(driver)
loader = getattr(driver, "_load_helpers", None)
if not callable(loader):
    print(json.dumps({"state": "NEW_LOADER_UNAVAILABLE"}))
    raise SystemExit(0)
loaded = loader()
if not hasattr(loaded.replay, "Replay") or not hasattr(loaded.replay, "OwnedRoots"):
    print(json.dumps({"state": "NEW_CAPTURE_UNAVAILABLE"}))
    raise SystemExit(0)
api = driver.load_policy(policy)
owned.mkdir(mode=0o700)
run = loaded.replay.Replay.open(loaded.replay.OwnedRoots(owned), api,
                               initialization=loaded.initialization)
qualification = run.harmless_controls()
def wire(value):
    if dataclasses.is_dataclass(value):
        kind = type(value).__name__
        if kind == "MemberOccurrence":
            return {"scope": value.scope, "role": value.role, "member_id": wire(value.member.member_id),
                    "association": wire(value.association), "prefix": wire(value.prefix)}
        if kind == "TaskOccurrence":
            witness = ({"launch_task": wire(value.witness.task)} if isinstance(value.witness, loaded.observation.Launch)
                       else {"birth_refs": wire(value.witness)})
            return {"key": wire(value.key), **witness}
        return {field.name: ({"session_id": value.session_id, "operation_sequence": value.operation_sequence}
                            if kind == "Checkpoint" and field.name == "basis"
                            else wire(getattr(value, field.name))) for field in dataclasses.fields(value)}
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (tuple, list)):
        return [wire(item) for item in value]
    if isinstance(value, dict):
        return {key: wire(item) for key, item in value.items()}
    return value
print(json.dumps({"state": "CAPTURED", "platform": sys.platform,
                  "shared_packet_identity": all(isinstance(stage, loaded.observation.Observation)
                                                for stage in qualification.book.stages),
                  "initialization": wire(loaded.initialization),
                  "qualification": wire(qualification)}, sort_keys=True))
'''


class CurrentInspectorNewOutputTests(unittest.TestCase):
    def test_unjoined_normal_and_signal_markers_survive_unsupported_grammar(self):
        support = load_test_file(HERE / "test_observation.py", "_dev786_old_packet_support")
        observer = support.observation
        self.addCleanup(self.remove_owned_observer, observer)
        for terminal, field, expected in ((support.TERMINAL_7, "code", 7),
                                          (KILLED, "signal", "SIGTERM")):
            with self.subTest(terminal=field):
                lines = (support.FIRST_EXEC, UNSUPPORTED, terminal)
                supplied = support.packet("unjoined-marker-new-output", lines, returncode=7)
                if field == "signal":
                    supplied = dataclasses.replace(
                        supplied, end=dataclasses.replace(supplied.end, wait=observer.WaitSignaled("SIGTERM")))
                result = observer.inspect(supplied)
                self.assertEqual(result.status, "incomplete")
                self.assertIn("unsupported-syscall", {reason.code for reason in result.reasons})
                for name in ("tasks", "images", "exec_attempts", "path_uses"):
                    self.assertEqual(getattr(result, name), ())
                self.assertEqual(result.end, supplied.end)
                self.assertTrue(hasattr(result, "terminal_markers"),
                                "NEW unjoined terminal-marker output is required after real inspect")
                self.assertEqual(len(result.terminal_markers), 1)
                marker = result.terminal_markers[0]
                self.assertEqual(getattr(marker.terminal, field), expected)
                self.assertEqual(len(marker.raw_refs), 1)
                support.ObservationBehaviorTests().assert_reference(
                    marker.raw_refs[0], supplied, "trace.100",
                    len(support.FIRST_EXEC) + len(UNSUPPORTED), 3, terminal,
                )

    @staticmethod
    def remove_owned_observer(observer):
        if sys.modules.get(MODULES[0]) is observer:
            del sys.modules[MODULES[0]]


class CaptureHandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configured = os.environ.get("DEV786_PREFLIGHT_INPUTS")
        if not configured or not Path(configured).is_absolute():
            raise AssertionError("Root must supply the existing absolute DEV786_PREFLIGHT_INPUTS")
        cls.adapter = load_test_file(HERE / "test_bundle_loading.py", "_dev786_bundle_test_support")
        cls.control_attempted = False
        cls.owner = Path(tempfile.mkdtemp(prefix="dev786-capture-tests-")).resolve()
        cls.addClassCleanup(cls.cleanup_owned_test_root)
        cls.source = cls.owner / "source"
        cls.source.mkdir(mode=0o700)
        for name in ("build.py", "preflight.py"):
            path = cls.adapter.INPUTS / name
            if path.is_symlink() or not path.is_file():
                raise AssertionError("A real existing builder/driver is required")
            shutil.copyfile(path, cls.source / name)
        driver_tree = ast.parse((cls.source / "preflight.py").read_bytes())
        manifest = cls.adapter.literal(driver_tree, "HELPER_MANIFEST")
        if not isinstance(manifest, tuple) or not manifest:
            raise AssertionError("The actual old baseline must retain its trusted helper manifest")
        for name, size, sha256, module_name in manifest:
            if name not in HELPERS or module_name != MODULES[HELPERS.index(name)]:
                raise AssertionError("Only the two fixed real helper identities are in test scope")
            path = HERE / name
            if path.is_symlink() or not path.is_file():
                raise AssertionError("A declared helper must be real source, never a test placeholder")
            with path.open("rb") as stream:
                raw = stream.read(size + 1)
            if len(raw) != size or digest(raw) != sha256:
                raise AssertionError("The actual source and its reviewed manifest identity differ")
            (cls.source / name).write_bytes(raw)
        fixtures = cls.adapter.INPUTS / "fixtures"
        if fixtures.is_symlink() or {path.name for path in fixtures.iterdir()} != set(cls.adapter.FIXTURES):
            raise AssertionError("The nine fixed fixtures must remain closed")
        (cls.source / "fixtures").mkdir(mode=0o700)
        for name, identity in cls.adapter.FIXTURES.items():
            path = fixtures / name
            if path.is_symlink() or not path.is_file():
                raise AssertionError("The fixed fixture must be a regular file")
            raw = path.read_bytes()
            if (len(raw), digest(raw)) != identity:
                raise AssertionError("A fixed fixture changed")
            (cls.source / "fixtures" / name).write_bytes(raw)
        result = cls.adapter.launch(cls.source / "build.py", cls.owner / "builder")
        if result[0] != 0:
            raise AssertionError(f"Real baseline builder failed before NEW behavior: {result!r}")
        workflow = (cls.source / "native-materialization-preflight.yml").read_text()
        decoder, transport = cls.adapter.generated(workflow)
        payload_manifest, contents = cls.adapter.payloads(decoder, transport)
        cls.bundle = cls.adapter.BundleLoadingTests()
        cls.adapter.BundleLoadingTests.counter = 0
        for name, value in (("owner", cls.owner), ("source", cls.source), ("decoder", decoder),
                            ("transport", transport), ("manifest", payload_manifest),
                            ("contents", contents), ("original_driver", driver_tree),
                            ("helper_manifest", manifest)):
            setattr(cls.bundle, name, value)
        cls.bundle.decoder_harness = cls.owner / "decoder_child.py"
        cls.bundle.decoder_harness.write_text(cls.adapter.DECODER_CHILD)
        cls.loader_child = cls.owner / "loader_child.py"
        cls.loader_child.write_text(LOADER_CHILD)
        cls.control_child = cls.owner / "control_child.py"
        cls.control_child.write_text(CONTROL_CHILD)
        cls.control_cache = None

    @classmethod
    def cleanup_owned_test_root(cls):
        if cls.control_attempted:
            print(f"Actual control evidence retained for root review at {cls.owner}", file=sys.stderr)
        else:
            shutil.rmtree(cls.owner)

    def extracted(self):
        root, result = self.bundle.extract()
        self.assertEqual(result[0], 0, f"The actual baseline decoder must succeed: {result!r}")
        return root

    def require_two_helpers(self):
        actual = self.adapter.literal(self.bundle.original_driver, "HELPER_MANIFEST")
        self.assertEqual(tuple(item[0] for item in actual), HELPERS,
                         "NEW actual bundle must deliver both real helpers")
        self.assertEqual(tuple(item[3] for item in actual), MODULES)
        self.assertEqual({name for name, _, _ in self.bundle.manifest},
                         {"preflight.py", *HELPERS, *("fixtures/" + name for name in self.adapter.FIXTURES)})
        self.assertLessEqual(sum(size for _, size, _ in self.bundle.manifest), 262144)

    def loader_result(self, root, action="normal", poison=False):
        owner = self.bundle.location("new-loader")
        sentinel = owner / "ambient-ran"
        if poison:
            body = f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('executed')\n"
            for name in (*HELPERS, *(name + ".py" for name in MODULES)):
                (owner / name).write_text(body)
        result = self.adapter.launch(self.loader_child, owner, str(root), action)
        self.assertEqual(result[0], 0, f"Loader child failed outside a NEW assertion: {result!r}")
        self.assertEqual(result[2], b"", "A child import error is never a loader refusal")
        self.assertFalse(sentinel.exists(), "An ambient helper executed")
        return json.loads(result[1])

    def assert_loaded(self, value, root):
        self.assertEqual(value["state"], "LOADED", "NEW extracted _load_helpers must initialize both real sources")
        self.assertEqual(value["executed"], list(HELPERS))
        self.assertTrue(value["registered_before_exec"])
        self.assertTrue(value["registered"])
        self.assertTrue(value["path_unchanged"])
        self.assertEqual(value["files"], [str(root / name) for name in HELPERS])
        self.assertTrue(value["initialization_immutable"])
        self.assertEqual(value["initialization_helpers"], list(HELPERS))
        self.assertGreater(value["initialization_reads"], 0)
        initialization = value["initialization"]
        self.assertEqual(initialization["helper_identities"], [
            {"name": name, "byte_length": size, "sha256": sha256, "module_name": module_name}
            for name, size, sha256, module_name in self.bundle.helper_manifest
        ])
        source_work = value["source_work"]
        for name, size, _, _ in self.bundle.helper_manifest:
            expected = [[operation, name, requested, size] for operation, requested in (
                ("source-read", size + 1), ("source-hash", size), ("source-submit", size))]
            self.assertEqual([item for item in source_work if item[1] == name], expected,
                             "Read/hash/source-submission assertions require the real delegated operations")
            for operation, _, requested, delivered in expected:
                debits = [item for item in initialization["bounded_reads"]
                          if item["name"] == name and item["operation"] == operation]
                self.assertEqual(len(debits), 1)
                self.assertEqual((debits[0]["requested_bytes"], debits[0]["delivered_bytes"]), (requested, delivered))
        hash_positions = [index for index, item in enumerate(source_work) if item[0] == "source-hash"]
        submit_positions = [index for index, item in enumerate(source_work) if item[0] == "source-submit"]
        self.assertLess(max(hash_positions), min(submit_positions), "Both sources verify before either submission executes")
        self.assertEqual(set(value["directory_entries"]), {"preflight.py", "fixtures", *HELPERS})
        self.assertLessEqual(len(value["directory_entries"]), 5)
        self.assertGreater(initialization["adoption_reserved"]["traversal_bytes"], 0)
        self.assertGreaterEqual(initialization["prepaid_envelope"]["traversal_bytes"],
                                initialization["measured_usage"]["traversal_bytes"]
                                + initialization["conservative_debit"]["traversal_bytes"]
                                + initialization["adoption_reserved"]["traversal_bytes"])
        for operation in ("identity-compare", "order-compare", "receipt-copy", "directory-entry", "adoption-compare"):
            self.assertTrue(any(item["operation"] == operation and item["requested_bytes"] > 0
                                for item in initialization["bounded_reads"]), "NEW initialization must prepay " + operation)

    def modules(self):
        root = self.extracted()
        name = "_dev786_handoff_pure_driver_" + root.parent.name
        spec = importlib.util.spec_from_file_location(name, root / "preflight.py")
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        driver = importlib.util.module_from_spec(spec)
        sys.modules[name] = driver
        self.addCleanup(lambda: sys.modules.pop(name, None))
        spec.loader.exec_module(driver)
        loader = getattr(driver, "_load_helpers", None)
        self.assertTrue(callable(loader), "NEW no-argument _load_helpers is missing in the real extracted driver")
        before = tuple(sys.path)
        loaded = loader()
        self.assertEqual(tuple(sys.path), before)
        for module_name, attr in zip(MODULES, ("observation", "replay")):
            module = getattr(loaded, attr)
            self.assertIs(sys.modules.get(module_name), module)
            self.addCleanup(self.remove_owned_module, module_name, module)
        for type_name in NEW_TYPES:
            self.assertTrue(hasattr(loaded.observation, type_name), f"NEW capture data type is missing: {type_name}")
        self.assertTrue(callable(getattr(loaded.observation, "_allowance", None)),
                        "NEW shared fixed-limit allowance calculation is missing")
        schemas = {
            "Usage": ("traversal_bytes", "retained", "export_files", "physical_records", "scope_counts", "four_row_members", "four_row_tasks"),
            "Checkpoint": ("session_id", "operation_sequence", "committed", "measured", "conservative", "closure_reserved", "basis", "scope", "allowance"),
            "OperationReceipt": ("before", "measured_delta", "conservative_delta", "unused_allowance", "refusals", "encountered", "newly_charged", "coverage"),
            "MemberOccurrence": ("scope", "role", "member", "association", "prefix"),
            "TaskOccurrence": ("key", "witness"),
            "Book": ("stages", "identities", "products", "operations", "occurrences", "terminal_operations", "original_final", "replay_final", "retrieval", "assessment"),
            "Incomplete": ("reasons",),
            "InitializationReceipt": ("helper_identities", "bounded_reads", "measured_usage", "conservative_debit", "prepaid_envelope", "adoption_reserved"),
            "FixedHelperIdentity": ("name", "byte_length", "sha256", "module_name"),
            "ReadDebit": ("name", "operation", "requested_bytes", "delivered_bytes"),
        }
        for type_name, expected in schemas.items():
            data_type = getattr(loaded.observation, type_name)
            self.assertTrue(dataclasses.is_dataclass(data_type), "NEW immutable accounting record is missing: " + type_name)
            self.assertTrue(data_type.__dataclass_params__.frozen)
            self.assertEqual(tuple(field.name for field in dataclasses.fields(data_type)), expected,
                             "NEW constructor schema differs from the frozen SPEC: " + type_name)
        return loaded

    @staticmethod
    def remove_owned_module(name, module):
        if sys.modules.get(name) is module:
            del sys.modules[name]

    def packet(self, observer, trace=EXEC + EXIT + TERMINAL):
        task = observer.TaskKey(STAGE, 100, 0)
        binary = observer.BinaryIdentity(b"/owned/bin/first", b"/owned/libexec/first",
                                         len(BINARY_BYTES), digest(BINARY_BYTES))
        argv = (b"/owned/bin/first", b"literal,...")
        raw = observer.Complete(observer.MemberId("m0"), "trace.100", trace, len(trace), digest(trace))
        stdout = observer.Complete(observer.MemberId("m1"), "stdout", b"", 0, digest(b""))
        stderr = observer.Complete(observer.MemberId("m2"), "stderr", b"", 0, digest(b""))
        closure = observer.Usage(traversal_bytes=1048576,
                                 retained=(("preparation-restoration-export", 65536),), export_files=1)
        checkpoint = observer.Checkpoint("synthetic-session", 0, observer.Usage(), observer.Usage(),
                                         observer.Usage(), closure, self.empty_book(observer), STAGE, observer.Usage())
        checkpoint = dataclasses.replace(checkpoint, allowance=observer._allowance(STAGE, checkpoint))
        return observer.StagePacket(
            origin=observer.Origin.SYNTHETIC, origin_label="capture-handoff", stage=STAGE,
            launch=observer.Launch(task, argv, ENVIRONMENT, b"/owned/work", binary,
                                   TRACER + argv, ENVIRONMENT, 900, 900, "DEVNULL", True, ()),
            trace_members=(observer.TraceAssociation(raw, task),), stdout=stdout, stderr=stderr,
            tracer_diagnostics=observer.Unknown("shared-stderr-attribution-unknown", ()),
            binary_identities=(binary,),
            end=observer.CaptureEnd("returned", observer.WaitExited(7), observer.Cleanup(True, True)),
            accounting=checkpoint,
        )

    def assert_incomplete(self, result, code):
        self.assertEqual(result.status, "incomplete")
        self.assertEqual(result.origin.value, "Synthetic")
        self.assertIn(code, {reason.code for reason in result.reasons})

    @staticmethod
    def empty_book(ob):
        return ob.Book((), (), (), (), (), (None, None), ob.Unknown("original-not-run", ()),
                       ob.Unknown("replay-not-finished", ()), ob.Unknown("retrieval-not-run", ()), ob.Incomplete(()))

    @staticmethod
    def coordinates(usage):
        result = {name: getattr(usage, name) for name in (
            "traversal_bytes", "export_files", "physical_records", "four_row_members", "four_row_tasks")}
        result.update({("retained", name): value for name, value in usage.retained})
        for scope, members, tasks in usage.scope_counts:
            result[("members", scope)] = members
            result[("tasks", scope)] = tasks
        return {key: value for key, value in result.items() if value != 0}

    def usage_sum(self, ob, *values):
        coordinates = {}
        for value in values:
            for key, count in self.coordinates(value).items():
                coordinates[key] = coordinates.get(key, 0) + count
        return self.usage_from_coordinates(ob, coordinates)

    @staticmethod
    def usage_from_coordinates(ob, coordinates):
        scalars = {key: value for key, value in coordinates.items() if isinstance(key, str)}
        retained = tuple(sorted((key[1], value) for key, value in coordinates.items()
                                if isinstance(key, tuple) and key[0] == "retained" and value))
        scopes = sorted({key[1] for key in coordinates if isinstance(key, tuple) and key[0] in ("members", "tasks")})
        scope_counts = tuple((scope, coordinates.get(("members", scope), 0), coordinates.get(("tasks", scope), 0))
                             for scope in scopes)
        return ob.Usage(**scalars, retained=retained, scope_counts=scope_counts)

    def usage_difference(self, ob, left, right):
        coordinates = self.coordinates(left)
        for key, value in self.coordinates(right).items():
            coordinates[key] = coordinates.get(key, 0) - value
        self.assertTrue(all(value >= 0 for value in coordinates.values()), "Synthetic history must fit one common grant")
        return self.usage_from_coordinates(ob, coordinates)

    def assert_usage(self, actual, expected):
        self.assertEqual(self.coordinates(actual), self.coordinates(expected))

    def new_owner(self, loaded, *, book=None, measured=None, conservative=None):
        ob, rp = loaded.observation, loaded.replay
        for name in ("_Initial", "_Budget"):
            self.assertTrue(callable(getattr(rp, name, None)), f"NEW real replay accounting owner is missing: {name}")
        self._owner_counter = getattr(self, "_owner_counter", 0) + 1
        session = "synthetic-accounting-session-" + str(self._owner_counter)
        initial_book = self.empty_book(ob) if book is None else book
        if initial_book.operations:
            session = initial_book.operations[0].before.session_id
        initial = rp._Initial(session, initial_book, ob.Usage() if measured is None else measured,
                              ob.Usage() if conservative is None else conservative, loaded.initialization)
        owner = rp._Budget(initial)
        for name in ("_operation", "_receive", "_closure", "_adopt_initialization"):
            self.assertTrue(callable(getattr(owner, name, None)), f"NEW lexical real-owner guard is missing: {name}")
        self.assertIsInstance(owner._snapshot.checkpoint, ob.Checkpoint)
        self.assertIsInstance(owner._snapshot.initialization, ob.InitializationReceipt)
        return owner

    def accounting_packet(self, ob, *, trace=EXEC + EXIT + TERMINAL, scope=STAGE, member="m0", generation=0):
        packet = self.packet(ob, trace)
        task = ob.TaskKey(scope, 100, generation)
        raw = dataclasses.replace(packet.trace_members[0].member, member_id=ob.MemberId(member))
        return dataclasses.replace(packet, stage=scope, launch=dataclasses.replace(packet.launch, task=task),
                                   trace_members=(ob.TraceAssociation(raw, task),), tracer_diagnostics=packet.stderr)

    def inspect_once(self, loaded, owner, packet):
        with owner._operation(packet.stage) as checkpoint:
            self.assertIs(checkpoint.basis, owner._snapshot.book)
            self.assertIs(checkpoint.allowance, owner._snapshot.pending.allowance)
            result = loaded.observation.inspect(dataclasses.replace(packet, accounting=checkpoint))
            owner._receive(result)
        return checkpoint, result

    def synthetic_history(self, ob, usage, *, occurrences=(), stages=()):
        basis = self.empty_book(ob)
        closure = ob.Usage(traversal_bytes=1048576,
                           retained=(("preparation-restoration-export", 65536),), export_files=1)
        scopes = tuple(scope for scope, _, _ in usage.scope_counts) or (STAGE,)
        measured = ob.Usage()
        for index, scope in enumerate(scopes):
            selected = tuple(item for item in occurrences
                             if (item.scope if isinstance(item, ob.MemberOccurrence) else item.key.stage) == scope)
            members, tasks = next(((members, tasks) for name, members, tasks in usage.scope_counts if name == scope), (0, 0))
            records = (usage.physical_records if len(scopes) == 1 else
                       sum(item.prefix[0] for item in selected
                           if isinstance(item, ob.MemberOccurrence) and isinstance(item.prefix, tuple)))
            delta = ob.Usage(traversal_bytes=usage.traversal_bytes if index == 0 else 0,
                             retained=usage.retained if index == 0 else (), export_files=usage.export_files if index == 0 else 0,
                             physical_records=records, scope_counts=((scope, members, tasks),) if members or tasks else (),
                             four_row_members=members if scope.startswith("original-row-") else 0,
                             four_row_tasks=tasks if scope.startswith("original-row-") else 0)
            checkpoint = ob.Checkpoint("synthetic-history", index, measured, measured, ob.Usage(),
                                       closure, basis, scope, ob.Usage())
            checkpoint = dataclasses.replace(checkpoint, allowance=ob._allowance(scope, checkpoint))
            counts = dataclasses.replace(delta, traversal_bytes=0, retained=(), export_files=0)
            receipt = ob.OperationReceipt(checkpoint, delta, ob.Usage(),
                                           self.usage_difference(ob, checkpoint.allowance, delta), (), counts, counts, selected)
            basis = dataclasses.replace(basis, operations=basis.operations + (receipt,),
                                        occurrences=basis.occurrences + selected)
            measured = self.usage_sum(ob, measured, delta)
        self.assert_usage(measured, usage)
        return dataclasses.replace(basis, stages=stages)

    def count_history(self, ob, rows):
        occurrences = []
        scope_counts = []
        physical_records = 0
        total_bytes = 0
        for scope, count in rows:
            packet = self.accounting_packet(ob, scope=scope)
            clones = tuple(f'1700000000.000002 clone(child_stack=NULL, flags=SIGCHLD) = {101 + index}\n'.encode()
                           for index in range(count - 1))
            data = EXEC + b"".join(clones) + EXIT + TERMINAL
            raw = ob.Complete(ob.MemberId(scope + "-parent"), "trace.100", data, len(data), digest(data))
            occurrences.append(ob.MemberOccurrence(scope, "trace", raw, packet.launch.task, (count + 2, len(data))))
            occurrences.append(ob.TaskOccurrence(packet.launch.task, packet.launch))
            offset = len(EXEC)
            for index, line in enumerate(clones):
                task = ob.TaskKey(scope, 101 + index, 0)
                empty = ob.Complete(ob.MemberId(scope + "-child-" + str(index)), f"trace.{task.tid}", b"", 0, digest(b""))
                occurrences.append(ob.MemberOccurrence(scope, "trace", empty, task, (0, 0)))
                occurrences.append(ob.TaskOccurrence(task, (ob.RawRef(raw.member_id, offset, offset + len(line), index + 2),)))
                offset += len(line)
            scope_counts.append((scope, count, count))
            physical_records += count + 2
            total_bytes += len(data)
        usage = ob.Usage(traversal_bytes=2 * total_bytes, physical_records=physical_records,
                         retained=(("replay-traces", total_bytes),), scope_counts=tuple(scope_counts),
                         four_row_members=sum(count for scope, count in rows if scope.startswith("original-row-")),
                         four_row_tasks=sum(count for scope, count in rows if scope.startswith("original-row-")))
        return self.synthetic_history(ob, usage, occurrences=tuple(occurrences)), usage

    def owner_with_room(self, loaded, room):
        ob = loaded.observation
        sample_usage = ob.Usage(traversal_bytes=128 * 1048576)
        sample = self.new_owner(loaded, book=self.synthetic_history(ob, sample_usage), measured=sample_usage)
        validation_and_initialization = sample._snapshot.checkpoint.committed.traversal_bytes - sample_usage.traversal_bytes
        prior = ob.Usage(traversal_bytes=256 * 1048576 - 1048576 - validation_and_initialization - room)
        owner = self.new_owner(loaded, book=self.synthetic_history(ob, prior), measured=prior)
        grant = ob._allowance(STAGE, owner._snapshot.checkpoint)
        self.assertEqual(grant.traversal_bytes, room,
                         "Boundary must subtract actual constructor/adoption work and the held closure")
        return owner

    def assert_optional_denied(self, owner):
        entered = False
        before = owner._snapshot
        try:
            with owner._operation(STAGE):
                entered = True
        except ValueError:
            pass
        self.assertFalse(entered, "A stopped session cannot enter another optional body")
        self.assertIs(owner._snapshot.book, before.book)
        self.assert_usage(owner._snapshot.checkpoint.committed, before.checkpoint.committed)
        self.assertEqual(owner._snapshot.checkpoint.operation_sequence, before.checkpoint.operation_sequence)

    def assert_lost(self, ob, owner, trusted, checkpoint):
        state = owner._snapshot
        self.assertIsNone(state.pending)
        self.assertIsNotNone(state.stopped)
        self.assertEqual(state.closure, "held")
        self.assertEqual(state.checkpoint.operation_sequence, trusted.checkpoint.operation_sequence + 1)
        self.assert_usage(state.checkpoint.measured, trusted.checkpoint.measured)
        self.assert_usage(state.checkpoint.conservative,
                          self.usage_sum(ob, trusted.checkpoint.conservative, checkpoint.allowance))
        self.assert_usage(state.checkpoint.committed,
                          self.usage_sum(ob, state.checkpoint.measured, state.checkpoint.conservative))
        self.assert_usage(state.checkpoint.closure_reserved, trusted.checkpoint.closure_reserved)
        for name in ("stages", "identities", "products", "operations", "occurrences"):
            self.assertIs(getattr(state.book, name), getattr(trusted.book, name), "Loss cannot copy or invent trusted history")
        terminal, closure = state.book.terminal_operations
        self.assertIsNone(closure)
        self.assertIs(terminal.before, checkpoint)
        self.assert_usage(terminal.measured_delta, ob.Usage())
        self.assert_usage(terminal.conservative_delta, checkpoint.allowance)
        self.assert_usage(terminal.unused_allowance, ob.Usage())
        self.assertEqual(terminal.coverage, ())
        self.assert_optional_denied(owner)

    def assert_committed(self, ob, owner, trusted, checkpoint, returned):
        state = owner._snapshot
        receipt = state.book.operations[-1]
        self.assertIs(receipt.before, checkpoint)
        self.assertIs(checkpoint.basis, trusted.book)
        self.assertIs(state.book.stages[-1].operation, receipt)
        self.assertIsNone(state.pending)
        self.assertEqual(state.closure, "held")
        self.assertEqual(state.checkpoint.operation_sequence, trusted.checkpoint.operation_sequence + 1)
        self.assert_usage(state.checkpoint.measured, self.usage_sum(ob, trusted.checkpoint.measured, receipt.measured_delta))
        self.assert_usage(state.checkpoint.conservative,
                          self.usage_sum(ob, trusted.checkpoint.conservative, receipt.conservative_delta))
        self.assert_usage(state.checkpoint.committed,
                          self.usage_sum(ob, state.checkpoint.measured, state.checkpoint.conservative))
        self.assert_usage(self.usage_sum(ob, receipt.measured_delta, receipt.conservative_delta, receipt.unused_allowance),
                          checkpoint.allowance)
        self.assertGreaterEqual(receipt.measured_delta.traversal_bytes, returned.operation.measured_delta.traversal_bytes)
        self.assert_usage(state.checkpoint.closure_reserved, trusted.checkpoint.closure_reserved)
        return receipt

    def test_real_generated_loader_returns_two_modules_and_initialization(self):
        root = self.extracted()
        self.assert_loaded(self.loader_result(root, poison=True), root)
        self.require_two_helpers()
        for name, identity in self.adapter.FIXTURES.items():
            raw = (root / "fixtures" / name).read_bytes()
            self.assertEqual((len(raw), digest(raw)), identity)

    def test_both_preloads_refuse_without_executing_or_removing_foreign_modules(self):
        root = self.extracted()
        self.assert_loaded(self.loader_result(root), root)
        for action in ("preloaded-observation", "preloaded-replay"):
            with self.subTest(action=action):
                value = self.loader_result(root, action)
                self.assertEqual(value["state"], "REFUSED")
                self.assertEqual(value["executed"], [])
                for field in ("path_unchanged", "unrelated_preserved", "preload_preserved",
                              "owned_registrations_absent"):
                    self.assertTrue(value[field])

    def test_interruption_at_either_helper_rolls_back_owned_registrations(self):
        root = self.extracted()
        self.assert_loaded(self.loader_result(root), root)
        for action, first in (("interrupt-observation", ["observation.py"]),
                              ("interrupt-replay", list(HELPERS))):
            with self.subTest(action=action):
                value = self.loader_result(root, action)
                self.assertEqual(value["state"], "INTERRUPTED_THEN_LOADED")
                self.assertEqual(value["first"], first)
                self.assertEqual(value["retry"], list(HELPERS))
                for field in ("registered_before_exec", "rolled_back", "path_unchanged",
                              "unrelated_preserved", "registered"):
                    self.assertTrue(value[field])

    def test_second_source_identity_is_verified_before_first_source_executes(self):
        root = self.extracted()
        self.assert_loaded(self.loader_result(root), root)
        self.require_two_helpers()
        for helper_name in HELPERS:
            with self.subTest(helper=helper_name):
                changed = self.extracted()
                path = changed / helper_name
                raw = path.read_bytes()
                path.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
                value = self.loader_result(changed, poison=True)
                self.assertEqual(value["state"], "REFUSED")
                self.assertEqual(value["executed"], [], "Both exact sources must verify before either executes")

    def test_real_decoder_rejects_self_rehashed_replay_and_preserves_source_cap(self):
        root = self.extracted()
        self.assert_loaded(self.loader_result(root), root)
        self.require_two_helpers()
        for mutation in ("self-rehashed-replay", "source-cap"):
            with self.subTest(mutation=mutation):
                contents, manifest = list(self.bundle.contents), list(self.bundle.manifest)
                name = "replay.py" if mutation == "self-rehashed-replay" else "preflight.py"
                index = next(i for i, entry in enumerate(manifest) if entry[0] == name)
                old = contents[index][1]
                changed = bytes([old[0] ^ 1]) + old[1:] if mutation == "self-rehashed-replay" else old + b" " * 262145
                contents[index] = (name, changed)
                manifest[index] = (name, len(changed), digest(changed))
                decoder, transport = self.adapter.perturbed_decoder(self.bundle.decoder, manifest, contents)
                self.assertEqual(self.adapter.literal(ast.parse(decoder), "HELPER_MANIFEST"),
                                 self.adapter.literal(ast.parse(self.bundle.decoder), "HELPER_MANIFEST"))
                _, result = self.bundle.extract(decoder, transport)
                self.assertNotEqual(result[0], 0, "Untrusted self-rehashing cannot authorize new source")
                self.assertEqual(result[1], b"")

    def test_partial_extents_cannot_establish_full_identity_or_task_success(self):
        ob = self.modules().observation
        original = b"x" * 8192
        prefix = original[:4096]
        for extent in (ob.StableFinalSize(8192), ob.ObservedLowerBound(4097), ob.Unknown("extent-unknown", ())):
            with self.subTest(extent=type(extent).__name__):
                packet = self.packet(ob)
                partial = ob.Partial(ob.MemberId("m0"), "trace.100", prefix, 4096, digest(prefix), extent, "local-cap")
                packet = dataclasses.replace(packet, trace_members=(ob.TraceAssociation(partial, packet.launch.task),))
                result = ob.inspect(packet)
                self.assert_incomplete(result, "partial-raw-member")
                for field in ("tasks", "images", "exec_attempts", "path_uses"):
                    self.assertEqual(getattr(result, field), ())
                retained = next(item for item in result.members if item.member_id == partial.member_id)
                self.assertIsInstance(retained, ob.Partial)
                self.assertEqual(retained.data, prefix)
                self.assertEqual(retained.prefix_length, 4096)
                self.assertEqual(retained.prefix_sha256, digest(prefix))
                self.assertFalse(hasattr(retained, "sha256"), "A prefix never has a full-member digest")
                self.assertNotIn(digest(original), json.dumps(wire(result)))

    def test_withheld_required_member_has_only_safe_metadata_and_no_derived_facts(self):
        ob = self.modules().observation
        packet = self.packet(ob)
        withheld = ob.Withheld(ob.MemberId("m0"), "control", 4096, "sensitive-content")
        result = ob.inspect(dataclasses.replace(
            packet, trace_members=(ob.TraceAssociation(withheld, packet.launch.task),)))
        self.assert_incomplete(result, "withheld-raw-member")
        retained = next(item for item in result.members if item.member_id == withheld.member_id)
        for field in ("name", "data", "sha256", "prefix_sha256"):
            self.assertFalse(hasattr(retained, field))
        for field in ("tasks", "images", "exec_attempts", "path_uses"):
            self.assertEqual(getattr(result, field), ())
        occurrences = [item for item in result.operation.coverage
                       if isinstance(item, ob.MemberOccurrence) and item.member.member_id == withheld.member_id]
        self.assertEqual(len(occurrences), 1)
        self.assertIsInstance(occurrences[0].prefix, ob.Unknown)
        self.assertEqual(result.operation.newly_charged.physical_records, 0)

    def test_unknown_launch_and_association_are_truthful_inputs(self):
        ob = self.modules().observation
        packet = self.packet(ob)
        cases = (
            (dataclasses.replace(packet, launch=ob.Unknown("launch-failed", ()),
                                 end=ob.CaptureEnd("launch-error", ob.WaitMissing("not-launched"), ob.Cleanup(True, True))),
             "launch-unknown"),
            (dataclasses.replace(packet, trace_members=(ob.TraceAssociation(
                packet.trace_members[0].member, ob.Unknown("task-association-unknown", ())),)),
             "trace-association-unknown"),
        )
        for changed, code in cases:
            with self.subTest(code=code):
                result = ob.inspect(changed)
                self.assert_incomplete(result, code)
                self.assertEqual(result.tasks, ())
                self.assertEqual(result.exec_attempts, ())
                self.assertEqual(result.end, changed.end)

    def test_stream_roles_shared_stderr_and_timeout_wait_remain_independent(self):
        ob = self.modules().observation
        packet = self.packet(ob)
        stream = UNSUPPORTED + KILLED
        stdout = ob.Complete(ob.MemberId("m1"), "stdout", stream, len(stream), digest(stream))
        stderr = ob.Complete(ob.MemberId("m2"), "stderr", stream, len(stream), digest(stream))
        supplied = dataclasses.replace(packet, stdout=stdout, stderr=stderr,
                                       end=ob.CaptureEnd("timeout", ob.WaitSignaled("SIGTERM"), ob.Cleanup(True, True)))
        result = ob.inspect(supplied)
        self.assertEqual(result.status, "incomplete")
        self.assertEqual(result.end.trigger, "timeout")
        self.assertEqual(result.end.wait.signal, "SIGTERM")
        self.assertEqual(result.tasks[0].terminal.value.code, 7)
        self.assertEqual(result.tracer_diagnostics.reason, "shared-stderr-attribution-unknown")
        self.assertNotIn("unsupported-syscall", {reason.code for reason in result.reasons},
                         "Stdout/stderr bytes cannot enter the trace decoder")
        self.assertEqual(sum(item.member_id == stderr.member_id for item in result.members), 1,
                         "Shared stderr is retained once, including any logical diagnostic view")
        ref = result.tasks[0].terminal.raw_refs[0]
        self.assertEqual(ref.member, packet.trace_members[0].member.member_id)
        self.assertEqual((ref.byte_start, ref.byte_stop, ref.physical_line),
                         (len(EXEC) + len(EXIT), len(EXEC) + len(EXIT) + len(TERMINAL), 3))
        self.assertEqual(packet.trace_members[0].member.data[ref.byte_start:ref.byte_stop], TERMINAL)

    def test_inspection_returns_a_matching_measured_operation_delta(self):
        ob = self.modules().observation
        packet = self.packet(ob)
        result = ob.inspect(packet)
        self.assertTrue(hasattr(result, "operation"), "NEW real inspection must return its matching traversal delta")
        receipt = result.operation
        self.assertEqual(receipt.before, packet.accounting)
        self.assertIs(receipt.before, packet.accounting)
        self.assertIs(receipt.before.basis, packet.accounting.basis)
        self.assertIs(receipt.before.allowance, packet.accounting.allowance)
        self.assertGreater(receipt.measured_delta.traversal_bytes, len(EXEC + EXIT + TERMINAL),
                           "Hashing and decoding are distinct charged traversals")
        self.assertEqual(receipt.measured_delta.physical_records, 3)
        self.assertEqual(receipt.newly_charged.physical_records, 3)
        self.assertEqual(receipt.encountered.physical_records, 3)
        for projection in (receipt.encountered, receipt.newly_charged):
            self.assertEqual((projection.traversal_bytes, projection.retained, projection.export_files), (0, (), 0))
        self.assertEqual(receipt.conservative_delta.traversal_bytes, 0)
        self.assertEqual(packet.accounting.committed.traversal_bytes, 0, "Pure inspection cannot mutate the owner")

    def test_accounting_initialization_itinerary_adoption_and_bounded_enumeration(self):
        loaded = self.modules()
        ob = loaded.observation
        root = self.extracted()
        admitted = self.loader_result(root)
        self.assert_loaded(admitted, root)
        for index in range(8):
            (root / f"unexpected-{index}.py").write_bytes(b"raise RuntimeError('unverified')\n")
        refused = self.loader_result(root)
        self.assertEqual(refused["state"], "REFUSED")
        self.assertEqual(refused["executed"], [])
        self.assertEqual(refused["source_work"], [], "Closed-directory admission must precede source read/hash/submission")
        self.assertLessEqual(len(refused["directory_entries"]), 5, "Closed membership plus one refusal entry is the bound")

        owner = self.new_owner(loaded)
        adopted = owner._snapshot
        self.assertEqual(adopted.initialization.helper_identities, loaded.initialization.helper_identities)
        self.assert_usage(adopted.initialization.adoption_reserved, ob.Usage())
        self.assert_usage(adopted.initialization.prepaid_envelope, loaded.initialization.prepaid_envelope)
        self.assertGreater(adopted.initialization.measured_usage.traversal_bytes,
                           loaded.initialization.measured_usage.traversal_bytes)
        self.assert_usage(adopted.checkpoint.measured, adopted.initialization.measured_usage)
        self.assert_usage(adopted.checkpoint.conservative, adopted.initialization.conservative_debit)
        try:
            owner._adopt_initialization(loaded.initialization)
        except ValueError:
            pass
        self.assertIsNotNone(owner._snapshot.stopped)
        self.assertIs(owner._snapshot.book, adopted.book)
        self.assert_usage(owner._snapshot.checkpoint.committed, adopted.checkpoint.committed)
        self.assertEqual(owner._snapshot.checkpoint.operation_sequence, adopted.checkpoint.operation_sequence)
        self.assertEqual(owner._snapshot.closure, "held")
        self.assert_optional_denied(owner)

        real = loaded.initialization
        for label, changed in (
                ("helper-order", dataclasses.replace(real, helper_identities=tuple(reversed(real.helper_identities)))),
                ("missing-itinerary", dataclasses.replace(real, bounded_reads=())),
                ("unpaid-adoption", dataclasses.replace(real, adoption_reserved=ob.Usage())),
                ("impossible-envelope", dataclasses.replace(real, prepaid_envelope=ob.Usage()))):
            with self.subTest(synthetic_initialization=label):
                initial = loaded.replay._Initial("synthetic-invalid-initialization", self.empty_book(ob),
                                                  ob.Usage(), ob.Usage(), changed)
                with self.assertRaises(ValueError):
                    loaded.replay._Budget(initial)

    def test_accounting_constructor_prepays_history_and_rejects_inconsistent_witnesses(self):
        loaded = self.modules()
        ob = loaded.observation
        packet = self.accounting_packet(ob, trace=b"\n" * 16)
        raw = packet.trace_members[0].member
        occurrence = ob.MemberOccurrence(STAGE, "trace", raw, packet.launch.task, (16, 16))
        task = ob.TaskOccurrence(packet.launch.task, packet.launch)
        usage = ob.Usage(traversal_bytes=32, retained=(("controls", 16),), physical_records=16,
                         scope_counts=((STAGE, 1, 1),))
        book = self.synthetic_history(ob, usage, occurrences=(occurrence, task))
        with SourceVisits(ob, loaded.replay) as admitted:
            owner = self.new_owner(loaded, book=book, measured=usage)
        self.assertTrue(admitted.entries("hash"), "Real constructor history hashing must be observable")
        self.assertTrue(admitted.entries("framing"), "Real constructor prefix framing must be observable")
        self.assertGreaterEqual(owner._snapshot.checkpoint.measured.traversal_bytes,
                                usage.traversal_bytes + loaded.initialization.measured_usage.traversal_bytes + 32)
        self.assertEqual(owner._snapshot.checkpoint.measured.physical_records, 16)
        self.assertEqual(len(owner._snapshot.book.occurrences), 2)

        prior = dataclasses.replace(usage, traversal_bytes=256 * 1048576 - 1048576
                                     - loaded.initialization.prepaid_envelope.traversal_bytes - 31)
        denied_book = self.synthetic_history(ob, prior, occurrences=(occurrence, task))
        initial = loaded.replay._Initial("synthetic-history", denied_book, prior, ob.Usage(), loaded.initialization)
        with SourceVisits(ob, loaded.replay) as denied:
            with self.assertRaises(ValueError):
                loaded.replay._Budget(initial)
        self.assertFalse(denied.entries("hash"), "The whole history validation itinerary must fit before its first hash")
        self.assertFalse(denied.entries("framing"))

        altered = (
            ("span", dataclasses.replace(occurrence, prefix=(17, 16))),
            ("digest", dataclasses.replace(occurrence, member=dataclasses.replace(raw, sha256="0" * 64))),
            ("extent", dataclasses.replace(occurrence, prefix=(16, 15))),
            ("association", dataclasses.replace(occurrence, association=ob.TaskKey(STAGE, 100, 1))),
        )
        for label, changed in altered:
            with self.subTest(synthetic_history=label):
                invalid = dataclasses.replace(book, occurrences=(changed, task))
                initial = loaded.replay._Initial("synthetic-history", invalid, usage, ob.Usage(), loaded.initialization)
                with self.assertRaises(ValueError):
                    loaded.replay._Budget(initial)
        for label, invalid in (
                ("duplicate-id", dataclasses.replace(book, occurrences=(occurrence, occurrence, task))),
                ("sum", dataclasses.replace(usage, physical_records=17))):
            with self.subTest(synthetic_history=label):
                initial = loaded.replay._Initial("synthetic-history", invalid if label == "duplicate-id" else book,
                                                  usage if label == "duplicate-id" else invalid, ob.Usage(), loaded.initialization)
                with self.assertRaises(ValueError):
                    loaded.replay._Budget(initial)

    def test_accounting_record_cap_preserves_paid_rereads_and_session_bindings(self):
        loaded = self.modules()
        ob = loaded.observation
        packet = self.accounting_packet(ob, trace=b"\n" * 500000, member="counted-prefix")
        raw = packet.trace_members[0].member
        coverage = (ob.MemberOccurrence(STAGE, "trace", raw, packet.launch.task, (500000, 500000)),
                    ob.TaskOccurrence(packet.launch.task, packet.launch))
        prior = ob.Usage(traversal_bytes=1000000, retained=(("controls", 500000),), physical_records=500000,
                         scope_counts=((STAGE, 1, 1),))
        history = self.synthetic_history(ob, prior, occurrences=coverage)
        for new_id in (False, True):
            with self.subTest(new_id=new_id):
                owner = self.new_owner(loaded, book=history, measured=prior)
                supplied = packet
                if new_id:
                    supplied = dataclasses.replace(packet, trace_members=(ob.TraceAssociation(
                        dataclasses.replace(raw, member_id=ob.MemberId("fresh-identical-prefix")), packet.launch.task),))
                with SourceVisits(ob, loaded.replay) as visits:
                    checkpoint, result = self.inspect_once(loaded, owner, supplied)
                self.assertEqual(checkpoint.allowance.physical_records, 0)
                self.assertEqual(result.operation.newly_charged.physical_records, 0)
                if new_id:
                    self.assertFalse(visits.entries("framing"), "No new physical record may be extracted at the cap")
                    self.assertTrue(result.operation.refusals)
                    self.assertIsNotNone(owner._snapshot.stopped)
                    self.assert_optional_denied(owner)
                else:
                    self.assertTrue(visits.entries("hash"), "Known record credit cannot make its hash free")
                    self.assertTrue(visits.entries("framing"), "Known prefix credit must allow a paid real reread")
                    self.assertGreater(result.operation.measured_delta.traversal_bytes, len(raw.data))
                    self.assertGreater(result.operation.encountered.physical_records, 0)
                    self.assertEqual(owner._snapshot.checkpoint.measured.physical_records, 500000)

        ordinary = self.accounting_packet(ob)
        for binding in ("scope", "role", "association", "generation", "variant", "name", "bytes"):
            with self.subTest(changed_binding=binding):
                owner = self.new_owner(loaded)
                self.inspect_once(loaded, owner, ordinary)
                trusted = owner._snapshot
                changed = ordinary
                member = ordinary.trace_members[0].member
                task = ordinary.launch.task
                if binding == "scope":
                    task = ob.TaskKey("synthetic-other-scope", 100, 0)
                    changed = dataclasses.replace(changed, stage=task.stage, launch=dataclasses.replace(changed.launch, task=task))
                elif binding == "role":
                    changed = dataclasses.replace(changed, trace_members=(), stdout=member)
                elif binding in ("association", "generation"):
                    task = ob.TaskKey(STAGE, 101 if binding == "association" else 100, 1 if binding == "generation" else 0)
                elif binding == "variant":
                    member = ob.Partial(member.member_id, member.name, member.data[:-1], len(member.data) - 1,
                                        digest(member.data[:-1]), ob.StableFinalSize(len(member.data)), "Synthetic changed binding")
                elif binding == "name":
                    member = dataclasses.replace(member, name="other-trace.100")
                else:
                    altered = member.data.replace(b"literal,...", b"changed,...")
                    member = dataclasses.replace(member, data=altered, byte_length=len(altered), sha256=digest(altered))
                if binding != "role":
                    changed = dataclasses.replace(changed, trace_members=(ob.TraceAssociation(member, task),))
                with owner._operation(changed.stage) as checkpoint:
                    result = ob.inspect(dataclasses.replace(changed, accounting=checkpoint))
                    self.assertTrue(result.operation.refusals, "Reused MemberId must refuse a changed session binding")
                    self.assertEqual(result.operation.newly_charged.physical_records, 0)
                    try:
                        owner._receive(result)
                    except ValueError:
                        pass
                self.assertIsNotNone(owner._snapshot.stopped)
                self.assertIs(owner._snapshot.book.occurrences, trusted.book.occurrences)
                self.assert_optional_denied(owner)

        generations = []
        for generation in (0, 1):
            described = self.accounting_packet(ob, member="generation-" + str(generation), generation=generation)
            member = described.trace_members[0].member
            generations.extend((ob.MemberOccurrence(STAGE, "trace", member, described.launch.task, (3, len(member.data))),
                                ob.TaskOccurrence(described.launch.task, described.launch)))
        assumed = ob.Usage(traversal_bytes=4 * len(EXEC + EXIT + TERMINAL), physical_records=6,
                           retained=(("controls", 2 * len(EXEC + EXIT + TERMINAL)),), scope_counts=((STAGE, 2, 2),))
        validated = self.new_owner(loaded, book=self.synthetic_history(ob, assumed, occurrences=tuple(generations)), measured=assumed)
        self.assertEqual(validated._snapshot.checkpoint.measured.scope_counts, ((STAGE, 2, 2),))
        self.assertEqual({item.key.birth_generation for item in validated._snapshot.book.occurrences
                          if isinstance(item, ob.TaskOccurrence)}, {0, 1})

        shared = self.new_owner(loaded)
        checkpoint, result = self.inspect_once(loaded, shared, ordinary)
        stderr_occurrences = [item for item in result.operation.coverage
                              if isinstance(item, ob.MemberOccurrence) and item.member.member_id == ordinary.stderr.member_id]
        self.assertEqual(len(stderr_occurrences), 1)
        self.assertEqual(stderr_occurrences[0].role, "stderr")
        self.assertEqual(result.operation.newly_charged.scope_counts, ((STAGE, 1, 1),))
        self.assertEqual(result.operation.newly_charged.physical_records, 3)
        self.assertIs(result.tracer_diagnostics, ordinary.stderr)

        independent = self.new_owner(loaded)
        self.inspect_once(loaded, independent, ordinary)
        fresh = dataclasses.replace(ordinary, trace_members=(ob.TraceAssociation(
            dataclasses.replace(ordinary.trace_members[0].member, member_id=ob.MemberId("same-bytes-new-id")), ordinary.launch.task),))
        _, result = self.inspect_once(loaded, independent, fresh)
        self.assertEqual(result.operation.newly_charged.scope_counts, ((STAGE, 1, 0),))
        self.assertEqual(result.operation.newly_charged.physical_records, 3)
        self.assertEqual(independent._snapshot.checkpoint.measured.scope_counts, ((STAGE, 2, 1),))
        self.assertEqual(independent._snapshot.checkpoint.measured.physical_records, 6)

    def test_accounting_common_residuals_obey_component_and_projection_bounds(self):
        loaded = self.modules()
        ob = loaded.observation
        rows = ("original-row-1", "original-row-2", "original-row-3", "original-row-4")

        def fresh_packet(scope, label):
            supplied = self.accounting_packet(ob, scope=scope, member=label + scope)
            task = ob.TaskKey(scope, 10000, 0)
            return dataclasses.replace(supplied, launch=dataclasses.replace(supplied.launch, task=task),
                trace_members=(ob.TraceAssociation(supplied.trace_members[0].member, task),))

        for row_counts in (((rows[0], 511),), ((rows[0], 512), (rows[1], 511))):
            history, prior = self.count_history(ob, row_counts)
            selected = row_counts[-1][0]
            with self.subTest(final_admission=row_counts):
                owner = self.new_owner(loaded, book=history, measured=prior)
                trusted = owner._snapshot
                supplied = fresh_packet(selected, "admitted-")
                raw = supplied.trace_members[0].member
                with SourceVisits(ob, loaded.replay, watch=(raw.data,)) as admitted:
                    checkpoint, actual = self.inspect_once(loaded, owner, supplied)
                self.assertEqual(checkpoint.allowance.scope_counts, ((selected, 1, 1),))
                self.assertEqual((checkpoint.allowance.four_row_members, checkpoint.allowance.four_row_tasks), (1, 1))
                self.assertEqual(actual.status, "observed")
                self.assertEqual(actual.operation.refusals, ())
                receipt = self.assert_committed(ob, owner, trusted, checkpoint, actual)
                delta = ob.Usage(physical_records=3, scope_counts=((selected, 1, 1),),
                                 four_row_members=1, four_row_tasks=1)
                for counts in (actual.operation.newly_charged, receipt.newly_charged, receipt.encountered):
                    self.assert_usage(counts, delta)
                member_coverage = [item for item in receipt.coverage if isinstance(item, ob.MemberOccurrence)]
                self.assertEqual({item.member.member_id for item in member_coverage},
                                 {raw.member_id, supplied.stdout.member_id, supplied.stderr.member_id})
                trace = next(item for item in member_coverage if item.member.member_id == raw.member_id)
                self.assertIs(trace.member, raw)
                self.assertEqual((trace.scope, trace.role, trace.association, trace.prefix),
                                 (selected, "trace", supplied.launch.task, (3, len(raw.data))))
                tasks = [item for item in receipt.coverage if isinstance(item, ob.TaskOccurrence)]
                self.assertEqual(len(tasks), 1)
                self.assertEqual(tasks[0].key, supplied.launch.task)
                self.assertIs(tasks[0].witness, supplied.launch)
                for item in receipt.coverage:
                    self.assertTrue(any(canonical is item for canonical in owner._snapshot.book.occurrences))
                self.assertEqual(len(owner._snapshot.book.occurrences), len(trusted.book.occurrences) + 4)
                expected = tuple((scope, count + int(scope == selected), count + int(scope == selected))
                                 for scope, count in row_counts)
                self.assertEqual(owner._snapshot.checkpoint.measured.scope_counts, expected)
                self.assertEqual(dict((scope, (members, tasks)) for scope, members, tasks in expected)[selected], (512, 512))
                self.assertEqual((owner._snapshot.checkpoint.measured.four_row_members,
                                  owner._snapshot.checkpoint.measured.four_row_tasks),
                                 (sum(count for _, count in row_counts) + 1,) * 2)
                self.assertEqual(owner._snapshot.checkpoint.measured.physical_records, prior.physical_records + 3)
                self.assertTrue(admitted.entries("hash", raw.data))
                self.assertTrue(admitted.entries("framing", raw.data))
                self.assertGreaterEqual(receipt.measured_delta.traversal_bytes, admitted.observed_bytes)

            exhausted_rows = tuple((scope, count + int(scope == selected)) for scope, count in row_counts)
            exhausted_history, exhausted_usage = self.count_history(ob, exhausted_rows)
            with self.subTest(next_occurrence_refused=exhausted_rows):
                owner = self.new_owner(loaded, book=exhausted_history, measured=exhausted_usage)
                supplied = fresh_packet(selected, "refused-")
                raw = supplied.trace_members[0].member
                returned = None
                with SourceVisits(ob, loaded.replay, watch=(raw.data,)) as denied:
                    try:
                        with owner._operation(selected) as checkpoint:
                            self.assertEqual(checkpoint.allowance.scope_counts, ())
                            self.assertEqual((checkpoint.allowance.four_row_members, checkpoint.allowance.four_row_tasks), (0, 0))
                            returned = ob.inspect(dataclasses.replace(supplied, accounting=checkpoint))
                            owner._receive(returned)
                    except ValueError:
                        pass
                self.assertIsNotNone(returned, "The real inspector must report count refusal")
                self.assertTrue(returned.operation.refusals)
                self.assertEqual(returned.operation.newly_charged.scope_counts, ())
                for label in ("hash", "framing", "copy"):
                    self.assertFalse(denied.entries(label, raw.data), "New occurrence content must not be traversed at the count cap")
                self.assertFalse(any(isinstance(item, ob.MemberOccurrence) and item.member.member_id == raw.member_id
                                     for item in owner._snapshot.book.occurrences))
                self.assertEqual(owner._snapshot.checkpoint.measured.scope_counts, exhausted_usage.scope_counts)
                self.assertIsNotNone(owner._snapshot.stopped)
                self.assert_optional_denied(owner)

            for selected in (row_counts[-1][0], rows[2]):
                with self.subTest(rows=row_counts, selected=selected):
                    owner = self.new_owner(loaded, book=history, measured=prior)
                    trusted = owner._snapshot
                    with owner._operation(selected) as checkpoint:
                        grant = checkpoint.allowance
                        used = dict((scope, (members, tasks)) for scope, members, tasks in trusted.checkpoint.committed.scope_counts)
                        remaining = min(512 - used.get(selected, (0, 0))[0], 1024 - prior.four_row_members)
                        self.assertEqual(grant.scope_counts, ((selected, remaining, remaining),) if remaining else ())
                        self.assertEqual((grant.four_row_members, grant.four_row_tasks), (remaining, remaining))
                        self.assertEqual(512 * 1048576 + trusted.checkpoint.committed.traversal_bytes
                                         + trusted.checkpoint.closure_reserved.traversal_bytes + grant.traversal_bytes,
                                         768 * 1048576)
                        supplied = self.accounting_packet(ob, scope=selected, member="new-" + selected)
                        task = ob.TaskKey(selected, 10000, 0)
                        supplied = dataclasses.replace(supplied, launch=dataclasses.replace(supplied.launch, task=task),
                            trace_members=(ob.TraceAssociation(supplied.trace_members[0].member, task),))
                        actual = ob.inspect(dataclasses.replace(supplied, accounting=checkpoint))
                        self.assertIs(actual.operation.before, checkpoint)
                    self.assert_lost(ob, owner, trusted, checkpoint)
                    charged = owner._snapshot.checkpoint.committed
                    self.assertLessEqual(charged.four_row_members, 1024)
                    self.assertLessEqual(charged.four_row_tasks, 1024)
                    self.assertTrue(all(members <= 512 and tasks <= 512 for _, members, tasks in charged.scope_counts))

        for scope, applicable in ((STAGE, ("controls",)),
                                  (rows[0], ("replay-traces", "replay-streams", "replay-reports-metadata"))):
            with self.subTest(exact_scope_residual=scope):
                owner = self.new_owner(loaded)
                trusted = owner._snapshot
                self.assertGreater(trusted.checkpoint.measured.traversal_bytes,
                                   loaded.initialization.measured_usage.traversal_bytes)
                with owner._operation(scope) as checkpoint:
                    caps = {"replay-traces": 64, "replay-streams": 16, "replay-reports-metadata": 16,
                            "controls": 8, "preparation-restoration-export": 8}
                    committed = dict(trusted.checkpoint.committed.retained)
                    held = dict(trusted.checkpoint.closure_reserved.retained)
                    residuals = {category: mib * 1048576 - committed.get(category, 0) - held.get(category, 0)
                                 for category, mib in caps.items()}
                    expected = {category: min(1048576, residuals[category]) if category == "controls" else residuals[category]
                                for category in applicable}
                    self.assertEqual(dict(checkpoint.allowance.retained), expected)
                    unissued = sum(residuals.values()) - sum(expected.values())
                    self.assertEqual(48 * 1048576 + sum(committed.values()) + sum(held.values())
                                     + sum(expected.values()) + unissued, 160 * 1048576)
                    self.assertEqual(checkpoint.allowance.export_files,
                                     128 - 64 - trusted.checkpoint.committed.export_files - trusted.checkpoint.closure_reserved.export_files)
                    self.assertEqual(checkpoint.allowance.traversal_bytes,
                                     256 * 1048576 - trusted.checkpoint.committed.traversal_bytes
                                     - trusted.checkpoint.closure_reserved.traversal_bytes)
                    self.assertEqual(512 * 1048576 + trusted.checkpoint.committed.traversal_bytes
                                     + trusted.checkpoint.closure_reserved.traversal_bytes + checkpoint.allowance.traversal_bytes,
                                     768 * 1048576)
                    self.assertEqual(checkpoint.allowance.physical_records, 500000 - trusted.checkpoint.committed.physical_records)
                    actual = ob.inspect(dataclasses.replace(self.accounting_packet(ob, scope=scope), accounting=checkpoint))
                    self.assertIs(actual.operation.before, checkpoint)
                self.assert_lost(ob, owner, trusted, checkpoint)

        supplied = self.accounting_packet(ob)
        raw = supplied.trace_members[0].member
        small_output = b"bounded control output\n"
        supplied = dataclasses.replace(supplied, stdout=ob.Complete(
            ob.MemberId("control-small-output"), "stdout", small_output, len(small_output), digest(small_output)))
        owner = self.new_owner(loaded)
        trusted = owner._snapshot
        with SourceVisits(ob, loaded.replay, watch=(raw.data, small_output)) as admitted:
            checkpoint, actual = self.inspect_once(loaded, owner, supplied)
        self.assertEqual(dict(checkpoint.allowance.retained), {"controls": 1048576})
        self.assertEqual(actual.status, "observed")
        self.assertEqual(actual.operation.refusals, ())
        receipt = self.assert_committed(ob, owner, trusted, checkpoint, actual)
        retained = self.usage_sum(ob, receipt.measured_delta, receipt.conservative_delta)
        self.assertGreaterEqual(dict(retained.retained).get("controls", 0), len(raw.data) + len(small_output))
        self.assertLessEqual(dict(retained.retained).get("controls", 0), 1048576,
                             "Control metadata and raw payload share the same receipt allowance")
        self.assertTrue(admitted.entries("hash", raw.data))
        self.assertTrue(admitted.entries("hash", small_output), "The paired positive must inspect actual stdout bytes")
        self.assertGreaterEqual(receipt.measured_delta.traversal_bytes, admitted.observed_bytes)

        oversized = b"x" * (1048576 + 1)
        stream = ob.Complete(ob.MemberId("control-beyond-receipt"), "stdout", oversized, len(oversized), digest(oversized))
        supplied = dataclasses.replace(supplied, stdout=stream)
        owner = self.new_owner(loaded)
        returned = None
        with SourceVisits(ob, loaded.replay, watch=(oversized,)) as denied:
            try:
                with owner._operation(STAGE) as checkpoint:
                    self.assertEqual(dict(checkpoint.allowance.retained), {"controls": 1048576})
                    returned = ob.inspect(dataclasses.replace(supplied, accounting=checkpoint))
                    owner._receive(returned)
            except ValueError:
                pass
        self.assertIsNotNone(returned)
        self.assertTrue(returned.operation.refusals)
        for label in ("hash", "framing", "copy"):
            self.assertFalse(denied.entries(label, oversized), "Over-bound control content must refuse before traversal")
        self.assertLessEqual(dict(owner._snapshot.checkpoint.committed.retained).get("controls", 0), 1048576)
        self.assertIsNotNone(owner._snapshot.stopped)
        self.assert_optional_denied(owner)

        for room in (0, 1):
            with self.subTest(traversal_room=room):
                owner = self.owner_with_room(loaded, room)
                trusted = owner._snapshot
                with SourceVisits(ob, loaded.replay) as denied:
                    try:
                        with owner._operation(STAGE) as checkpoint:
                            actual = ob.inspect(dataclasses.replace(self.accounting_packet(ob), accounting=checkpoint))
                            owner._receive(actual)
                    except ValueError:
                        pass
                self.assertFalse(denied.entries("hash"))
                self.assertFalse(denied.entries("framing"))
                self.assertIsNotNone(owner._snapshot.stopped)
                self.assertLessEqual(owner._snapshot.checkpoint.committed.traversal_bytes
                                     + owner._snapshot.checkpoint.closure_reserved.traversal_bytes, 256 * 1048576)
                self.assert_optional_denied(owner)
    def test_accounting_duplicate_stale_and_foreign_real_returns_stop_once(self):
        loaded = self.modules()
        ob = loaded.observation
        packet = self.accounting_packet(ob)
        for fault in ("duplicate", "stale", "foreign"):
            with self.subTest(fault=fault):
                owner = self.new_owner(loaded)
                first_before = owner._snapshot
                first_checkpoint, first = self.inspect_once(loaded, owner, packet)
                self.assert_committed(ob, owner, first_before, first_checkpoint, first)
                trusted = owner._snapshot
                if fault == "duplicate":
                    try:
                        owner._receive(first)
                    except ValueError:
                        pass
                    state = owner._snapshot
                    self.assertIs(state.book, trusted.book)
                    self.assertEqual(state.stopped.code, "duplicate-receipt")
                    self.assertIsNone(state.pending)
                    self.assert_usage(state.checkpoint.measured, trusted.checkpoint.measured)
                    self.assert_usage(state.checkpoint.conservative, trusted.checkpoint.conservative)
                    self.assertEqual(state.checkpoint.operation_sequence, trusted.checkpoint.operation_sequence)
                    self.assertEqual(state.closure, "held")
                    self.assert_usage(state.checkpoint.closure_reserved, trusted.checkpoint.closure_reserved)
                    self.assert_optional_denied(owner)
                    continue
                other = self.new_owner(loaded)
                _, foreign = self.inspect_once(loaded, other, packet)
                returned = first if fault == "stale" else foreign
                try:
                    with owner._operation(STAGE) as checkpoint:
                        current = ob.inspect(dataclasses.replace(packet, accounting=checkpoint))
                        self.assertIs(current.operation.before, checkpoint)
                        owner._receive(returned)
                except ValueError:
                    pass
                self.assert_lost(ob, owner, trusted, checkpoint)

    def test_accounting_malformed_and_overbudget_real_returns_burn_one_grant(self):
        loaded = self.modules()
        ob = loaded.observation
        packet = self.accounting_packet(ob)
        faults = ("missing", "wrong-type", "negative", "partition", "coverage", "copied-before", "over-budget",
                  "validation-exhausted", "export_files", "physical_records", "four_row_members", "four_row_tasks",
                  "scope-members", "scope-tasks", "retained:original-materializer", "retained:replay-traces",
                  "retained:replay-streams", "retained:replay-reports-metadata", "retained:controls",
                  "retained:preparation-restoration-export")
        for fault in faults:
            with self.subTest(synthetic_return=fault):
                owner = self.new_owner(loaded)
                trusted = owner._snapshot
                genuine = []
                try:
                    with owner._operation(STAGE) as checkpoint:
                        real = ob.inspect(dataclasses.replace(packet, accounting=checkpoint))
                        genuine.append(real)
                        receipt = real.operation
                        if fault == "missing":
                            changed = None
                        elif fault == "wrong-type":
                            changed = object()
                        else:
                            if fault == "negative":
                                receipt = dataclasses.replace(receipt, measured_delta=dataclasses.replace(
                                    receipt.measured_delta, traversal_bytes=-1))
                            elif fault == "partition":
                                receipt = dataclasses.replace(receipt, unused_allowance=ob.Usage())
                            elif fault == "coverage":
                                receipt = dataclasses.replace(receipt, coverage=())
                            elif fault == "copied-before":
                                receipt = dataclasses.replace(receipt, before=dataclasses.replace(checkpoint))
                            elif fault == "over-budget":
                                receipt = dataclasses.replace(receipt,
                                    measured_delta=dataclasses.replace(receipt.measured_delta,
                                        traversal_bytes=checkpoint.allowance.traversal_bytes + 1), unused_allowance=ob.Usage())
                            elif fault == "validation-exhausted":
                                receipt = dataclasses.replace(receipt,
                                    measured_delta=self.usage_sum(ob, receipt.measured_delta, receipt.unused_allowance),
                                    unused_allowance=ob.Usage())
                            else:
                                claimed = self.coordinates(receipt.measured_delta)
                                grant = self.coordinates(checkpoint.allowance)
                                if fault.startswith("retained:"):
                                    coordinate = ("retained", fault.split(":", 1)[1])
                                elif fault.startswith("scope-"):
                                    coordinate = ("members" if fault == "scope-members" else "tasks", STAGE)
                                else:
                                    coordinate = fault
                                claimed[coordinate] = grant.get(coordinate, 0) + 1
                                receipt = dataclasses.replace(receipt, measured_delta=self.usage_from_coordinates(ob, claimed),
                                                               unused_allowance=ob.Usage())
                            changed = dataclasses.replace(real, origin_label="Synthetic corrupted real return", operation=receipt)
                        owner._receive(changed)
                except ValueError:
                    pass
                self.assertEqual(len(genuine), 1, "Fault injection must follow genuine inspection")
                self.assert_lost(ob, owner, trusted, checkpoint)

    def test_accounting_nested_entry_denies_work_and_burns_outer_grant_once(self):
        loaded = self.modules()
        ob = loaded.observation
        owner = self.new_owner(loaded)
        trusted = owner._snapshot
        nested_entered = False
        inspected = []
        try:
            with owner._operation(STAGE) as checkpoint:
                inspected.append(ob.inspect(dataclasses.replace(self.accounting_packet(ob), accounting=checkpoint)))
                with owner._operation(STAGE):
                    nested_entered = True
                    ob.inspect(self.accounting_packet(ob))
        except ValueError:
            pass
        self.assertEqual(len(inspected), 1)
        self.assertFalse(nested_entered, "Nested entry cannot run another inspector")
        self.assert_lost(ob, owner, trusted, checkpoint)

    def test_accounting_real_inspection_loss_and_baseexception_keep_trusted_history(self):
        loaded = self.modules()
        ob = loaded.observation
        packet = self.accounting_packet(ob)
        for fault in ("no-receive", "lost-result", "baseexception"):
            with self.subTest(fault=fault):
                owner = self.new_owner(loaded)
                before_first = owner._snapshot
                first_checkpoint, first = self.inspect_once(loaded, owner, packet)
                self.assert_committed(ob, owner, before_first, first_checkpoint, first)
                trusted = owner._snapshot
                inspected = []

                def real_then_lose(sealed):
                    result = ob.inspect(sealed)
                    inspected.append(result)
                    if fault == "baseexception":
                        raise StopObservedWork()
                    return None

                try:
                    with owner._operation(STAGE) as checkpoint:
                        returned = real_then_lose(dataclasses.replace(packet, accounting=checkpoint))
                        if fault != "no-receive":
                            owner._receive(returned)
                except (StopObservedWork, ValueError):
                    pass
                self.assertEqual(len(inspected), 1)
                self.assertIs(inspected[0].operation.before, checkpoint)
                self.assert_lost(ob, owner, trusted, checkpoint)

    def test_accounting_interruption_before_and_after_atomic_store(self):
        loaded = self.modules()
        ob = loaded.observation
        packet = self.accounting_packet(ob)
        for after in (False, True):
            with self.subTest(after_store=after):
                owner = self.new_owner(loaded)
                trusted = owner._snapshot
                inspected = []
                with interrupt_canonical_store(owner, loaded.replay, after=after) as observed:
                    with self.assertRaises(StopObservedWork):
                        with owner._operation(STAGE) as checkpoint:
                            returned = ob.inspect(dataclasses.replace(packet, accounting=checkpoint))
                            inspected.append(returned)
                            owner._receive(returned)
                self.assertTrue(observed["hit"], "Interruption must reach the actual canonical store")
                self.assertEqual(len(inspected), 1)
                if not after:
                    self.assert_lost(ob, owner, trusted, checkpoint)
                    continue
                candidate = observed["candidate"]
                self.assertIs(owner._snapshot.book, candidate.book)
                self.assertIs(owner._snapshot.book.operations[-1], candidate.book.stages[-1].operation)
                self.assert_committed(ob, owner, trusted, checkpoint, returned)
                self.assert_usage(owner._snapshot.checkpoint.measured, candidate.checkpoint.measured)
                self.assert_usage(owner._snapshot.checkpoint.conservative, candidate.checkpoint.conservative)
                self.assertIsNotNone(owner._snapshot.stopped)
                self.assert_optional_denied(owner)

    def test_accounting_closure_is_held_once_and_spent_even_when_it_fails(self):
        loaded = self.modules()
        ob = loaded.observation
        for fail in (False, True):
            with self.subTest(closure_fails=fail):
                owner = self.new_owner(loaded)
                trusted = owner._snapshot
                with self.assertRaises(StopObservedWork):
                    with owner._operation(STAGE) as checkpoint:
                        real = ob.inspect(dataclasses.replace(self.accounting_packet(ob), accounting=checkpoint))
                        self.assertIs(real.operation.before, checkpoint)
                        raise StopObservedWork()
                self.assert_lost(ob, owner, trusted, checkpoint)
                stopped = owner._snapshot
                try:
                    with owner._closure() as closure:
                        self.assertEqual(owner._snapshot.closure, "pending")
                        self.assert_usage(closure.allowance, stopped.checkpoint.closure_reserved)
                        if fail:
                            raise StopObservedWork()
                        owner._receive(ob.OperationReceipt(closure, ob.Usage(), ob.Usage(), closure.allowance,
                                                            (), ob.Usage(), ob.Usage(), ()))
                except StopObservedWork:
                    pass
                closed = owner._snapshot
                self.assertEqual(closed.closure, "spent")
                self.assertIsNone(closed.pending)
                self.assert_usage(closed.checkpoint.closure_reserved, ob.Usage())
                self.assertEqual(closed.checkpoint.operation_sequence, stopped.checkpoint.operation_sequence + 1)
                self.assertIs(closed.book.terminal_operations[0], stopped.book.terminal_operations[0])
                if fail:
                    receipt = closed.book.terminal_operations[1]
                    self.assertIs(receipt.before, closure)
                    self.assert_usage(receipt.measured_delta, ob.Usage())
                    self.assert_usage(receipt.conservative_delta, closure.allowance)
                    self.assertEqual(receipt.coverage, ())
                    self.assert_usage(closed.checkpoint.measured, stopped.checkpoint.measured)
                    self.assert_usage(closed.checkpoint.conservative,
                                      self.usage_sum(ob, stopped.checkpoint.conservative, closure.allowance))
                    for name in ("stages", "identities", "products", "operations", "occurrences"):
                        self.assertIs(getattr(closed.book, name), getattr(stopped.book, name))
                else:
                    receipt = closed.book.operations[-1]
                    self.assertIs(receipt.before, closure)
                    self.assertIsNone(closed.book.terminal_operations[1])
                    self.assert_usage(self.usage_sum(ob, receipt.measured_delta, receipt.conservative_delta, receipt.unused_allowance),
                                      closure.allowance)
                    self.assert_usage(closed.checkpoint.measured, self.usage_sum(ob, stopped.checkpoint.measured, receipt.measured_delta))
                    self.assert_usage(closed.checkpoint.conservative,
                                      self.usage_sum(ob, stopped.checkpoint.conservative, receipt.conservative_delta))
                    for name in ("stages", "identities", "products", "occurrences"):
                        self.assertIs(getattr(closed.book, name), getattr(stopped.book, name))
                self.assert_usage(closed.checkpoint.committed, self.usage_sum(ob, closed.checkpoint.measured, closed.checkpoint.conservative))
                entered_again = False
                try:
                    with owner._closure():
                        entered_again = True
                except ValueError:
                    pass
                self.assertFalse(entered_again)
                self.assert_usage(owner._snapshot.checkpoint.committed, closed.checkpoint.committed)
                self.assertEqual(owner._snapshot.checkpoint.operation_sequence, closed.checkpoint.operation_sequence)
                self.assert_optional_denied(owner)

    def test_accounting_each_observed_traversal_has_an_admission_boundary(self):
        loaded = self.modules()
        ob = loaded.observation
        trace = b'1700000000.000001 execve("/x", ["/x"], []) = 0\n' + EXIT + TERMINAL
        packet = self.accounting_packet(ob, trace=trace)
        binary = dataclasses.replace(packet.launch.binary, spelling=b"/x")
        launch = dataclasses.replace(packet.launch, argv=(b"/x",), environment=(), binary=binary,
                                     tracer_argv=TRACER + (b"/x",), tracer_environment=())
        packet = dataclasses.replace(packet, launch=launch, binary_identities=(binary,))
        attempts = {}

        def attempt(room):
            if room in attempts:
                return attempts[room]
            self.assertLess(len(attempts), 128, "Source-site proof exceeded its bounded number of disposable attempts")
            owner = self.owner_with_room(loaded, room)
            trusted = owner._snapshot
            returned, issued = None, None
            with SourceVisits(ob, loaded.replay, detail=True) as visits:
                try:
                    with owner._operation(STAGE) as checkpoint:
                        issued = checkpoint
                        returned = ob.inspect(dataclasses.replace(packet, accounting=checkpoint))
                        owner._receive(returned)
                except ValueError:
                    pass
            state = owner._snapshot
            self.assertIsNone(state.pending)
            if issued is not None and state.book.terminal_operations[0] is not None:
                self.assert_lost(ob, owner, trusted, issued)
            elif returned is not None:
                receipt = self.assert_committed(ob, owner, trusted, issued, returned)
                self.assertGreaterEqual(receipt.measured_delta.traversal_bytes, visits.observed_bytes,
                                        "Finalized measured debit must include independently observed input work")
            self.assertEqual(visits.observed_bytes, sum(visits.visited_bytes.values()),
                             "One operation with several labels must be charged only once by the observer")
            self.assertLessEqual(visits.observed_bytes, room,
                                 "A later visit cannot borrow admission credit already consumed by an earlier visit")
            if issued is not None:
                self.assertEqual(issued.allowance.traversal_bytes, room)
            self.assertLessEqual(state.checkpoint.committed.traversal_bytes
                                 + state.checkpoint.closure_reserved.traversal_bytes, 256 * 1048576)
            if room == 65536:
                self.assertIsNotNone(returned)
                self.assertEqual(returned.status, "observed")
                self.assertIsNone(state.stopped)
                self.assertEqual(returned.operation.refusals, ())
            attempts[room] = visits
            return visits

        full = attempt(65536)
        zero = attempt(0)
        for label in ("hash", "framing", "field", "string", "regex", "copy"):
            self.assertTrue(full.entries(label), f"NEW actual {label} traversal is unobservable; no admission proof")
            self.assertFalse(zero.entries(label), f"Zero capacity entered actual {label} traversal")
        for site, expected in full.occurrences.items():
            with self.subTest(actual_site=site, required_occurrences=len(expected)):
                def reached(visits):
                    return visits.occurrences.get(site, ())[:len(expected)] == expected

                low, high = 0, 65536
                for _ in range(16):
                    if high - low == 1:
                        break
                    middle = (low + high) // 2
                    if reached(attempt(middle)):
                        high = middle
                    else:
                        low = middle
                self.assertEqual(high - low, 1, "Bounded admission search must isolate consecutive byte grants")
                denied, admitted = attempt(low), attempt(high)
                before = denied.occurrences.get(site, ())
                self.assertLess(len(before), len(expected), "Earlier occurrences cannot supply the missing final occurrence")
                self.assertEqual(before, expected[:len(before)], "A different refusal-path input cannot stand in for this site")
                self.assertTrue(reached(admitted), "Adjacent admission must reach this exact site's actual input occurrences")
                sampled = [reached(visits) for _, visits in sorted(attempts.items())]
                self.assertEqual(sampled, sorted(sampled), "Nonmonotone observed paths need a resolved attribution before proof")

    def test_accounting_repeated_wire_references_do_not_expand_history_or_payload(self):
        loaded = self.modules()
        ob = loaded.observation
        packet = self.accounting_packet(ob)
        owner = self.new_owner(loaded)
        canonical_receipts = []
        for index in range(4):
            trusted = owner._snapshot
            checkpoint, returned = self.inspect_once(loaded, owner, packet)
            receipt = self.assert_committed(ob, owner, trusted, checkpoint, returned)
            canonical_receipts.append(receipt)
            self.assertIs(receipt.before.basis, trusted.book)
            reference = wire(receipt.before)["basis"]
            self.assertEqual(reference, {"session_id": checkpoint.session_id,
                                         "operation_sequence": checkpoint.operation_sequence})
            self.assertEqual(set(reference), {"session_id", "operation_sequence"})
            self.assertEqual(receipt.newly_charged.physical_records, 3 if index == 0 else 0)
            self.assertEqual(receipt.newly_charged.scope_counts, ((STAGE, 1, 1),) if index == 0 else ())
            self.assertGreater(receipt.measured_delta.traversal_bytes, len(EXEC + EXIT + TERMINAL))
            self.assertEqual(receipt.encountered.physical_records, 3)
            for occurrence, projected in zip(receipt.coverage, wire(receipt.coverage)):
                if isinstance(occurrence, ob.MemberOccurrence):
                    self.assertEqual(projected, {"scope": occurrence.scope, "role": occurrence.role,
                        "member_id": wire(occurrence.member.member_id), "association": wire(occurrence.association),
                        "prefix": wire(occurrence.prefix)})
                else:
                    self.assertEqual(projected["key"], wire(occurrence.key))
                    self.assertEqual(set(projected), {"key", "launch_task"})
                for field in ("data", "name", "sha256", "member", "stages", "operations"):
                    self.assertNotIn(field, projected)
        references = json.dumps([wire(receipt) for receipt in canonical_receipts], sort_keys=True)
        self.assertNotIn("bytes_hex", references)
        self.assertNotIn("stages", references)
        whole = json.dumps(wire(owner._snapshot.book), sort_keys=True)
        exact_raw_wire = json.dumps({"bytes_hex": (EXEC + EXIT + TERMINAL).hex()}, sort_keys=True)
        self.assertEqual(whole.count(exact_raw_wire), 4,
                         "Only the four existing stage raw stores carry payload; new basis/coverage fields add none")
        self.assertEqual(len(owner._snapshot.book.occurrences), len(canonical_receipts[0].coverage))

    def test_plain_capture_receipt_keeps_canonical_identity_and_paid_inspection_rereads(self):
        loaded = self.modules()
        ob = loaded.observation
        owner = self.new_owner(loaded)
        packet = self.accounting_packet(ob, scope="control-plain-capture")
        with owner._operation(packet.stage) as checkpoint:
            tally = ob._Tally(checkpoint)
            ob._admit_task(tally, packet.launch.task, packet.launch)
            for role, member, association in (
                    ("trace", packet.trace_members[0].member, packet.launch.task),
                    ("stdout", packet.stdout, ob.Unknown("stream")),
                    ("stderr", packet.stderr, ob.Unknown("stream"))):
                ob._admit_member(tally, member, role, association)
            tally.metadata(tuple(tally.coverage))
            returned = tally.receipt()
            self.assertIs(type(returned), ob.OperationReceipt)
            owner._receive(returned)
        captured = owner._snapshot
        self.assertIsNone(captured.stopped)
        self.assertIsNone(captured.pending)
        self.assertEqual(captured.closure, "held")
        self.assertEqual(captured.book.stages, ())
        self.assertEqual(len(captured.book.operations), 1)
        self.assertIs(captured.book.operations[0].before, checkpoint)
        self.assertGreater(captured.book.operations[0].measured_delta.traversal_bytes,
                           returned.measured_delta.traversal_bytes)
        self.assertEqual(captured.checkpoint.measured.scope_counts, ((packet.stage, 1, 1),))
        self.assertEqual(captured.checkpoint.measured.physical_records, 0)
        self.assertEqual(len(captured.book.occurrences), 4)
        self.assertEqual([item.key for item in captured.book.occurrences if type(item) is ob.TaskOccurrence],
                         [packet.launch.task])
        expected_members = (packet.trace_members[0].member, packet.stdout, packet.stderr)
        self.assertEqual([item.member for item in captured.book.occurrences if type(item) is ob.MemberOccurrence],
                         list(expected_members))
        for index in range(2):
            trusted = owner._snapshot
            issued, inspected = self.inspect_once(loaded, owner, packet)
            self.assertEqual(inspected.status, "observed")
            receipt = self.assert_committed(ob, owner, trusted, issued, inspected)
            self.assertGreater(receipt.measured_delta.traversal_bytes, len(EXEC + EXIT + TERMINAL))
            self.assertEqual(receipt.newly_charged.scope_counts, ())
            self.assertEqual(receipt.newly_charged.physical_records, 3 if index == 0 else 0)
            self.assertEqual(owner._snapshot.checkpoint.measured.scope_counts, ((packet.stage, 1, 1),))
            self.assertEqual(owner._snapshot.checkpoint.measured.physical_records, 3)
            self.assertEqual(len(owner._snapshot.book.occurrences), 4)
            self.assertEqual([item.key for item in owner._snapshot.book.occurrences
                              if type(item) is ob.TaskOccurrence], [packet.launch.task])
            self.assertEqual([item.member for item in owner._snapshot.book.occurrences
                              if type(item) is ob.MemberOccurrence], list(expected_members))
            self.assertIsNone(owner._snapshot.stopped)

    def test_plain_capture_malformed_bindings_lose_one_grant_and_preserve_trusted_history(self):
        loaded = self.modules()
        ob = loaded.observation
        packet = self.accounting_packet(ob, scope="control-plain-capture", member="capture-trace")
        packet = dataclasses.replace(packet,
            stdout=dataclasses.replace(packet.stdout, member_id=ob.MemberId("capture-stdout")),
            stderr=dataclasses.replace(packet.stderr, member_id=ob.MemberId("capture-stderr")))
        packet = dataclasses.replace(packet, tracer_diagnostics=packet.stderr)
        domain_cases = {
            f"{target}-{name}": (target, changes)
            for target in ("task-and-association", "association-only")
            for name, changes in (
                ("zero-tid", {"tid": 0}),
                ("negative-tid", {"tid": -1}),
                ("boolean-tid", {"tid": True}),
                ("negative-generation", {"birth_generation": -1}),
                ("boolean-generation", {"birth_generation": False}),
            )
        }
        for label in ("duplicate-task", "launch-rebinding", "invalid-role", "foreign-association",
                      "complete-unknown-prefix", "copied-before", "foreign-task-scope", *domain_cases):
            with self.subTest(variant=label):
                owner = self.new_owner(loaded)
                prior = packet if label == "launch-rebinding" else self.accounting_packet(
                    ob, scope="control-trusted-history", member="trusted-trace")
                _, seeded = self.inspect_once(loaded, owner, prior)
                self.assertEqual(seeded.status, "observed")
                trusted = owner._snapshot
                self.assertTrue(trusted.book.occurrences)
                with owner._operation(packet.stage) as checkpoint:
                    genuine = ob.inspect(dataclasses.replace(packet, accounting=checkpoint))
                    self.assertEqual(genuine.status, "observed")
                    self.assertEqual(genuine.operation.refusals, ())
                    tally = ob._Tally(checkpoint)
                    ob._admit_task(tally, packet.launch.task, packet.launch)
                    if label == "launch-rebinding":
                        self.assertEqual(tally.receipt().newly_charged.scope_counts, ())
                        tally.coverage[0] = dataclasses.replace(tally.coverage[0],
                            witness=dataclasses.replace(packet.launch, cwd=b"/owned/other-work"))
                        tally.count("tasks")
                    else:
                        for role, member, association in (
                                ("trace", packet.trace_members[0].member, packet.launch.task),
                                ("stdout", packet.stdout, ob.Unknown("stream")),
                                ("stderr", packet.stderr, ob.Unknown("stream"))):
                            ob._admit_member(tally, member, role, association)
                        if label == "duplicate-task":
                            tally.coverage.append(tally.coverage[0])
                            tally.count("tasks")
                            tally.encounter("tasks")
                        elif label == "invalid-role":
                            tally.coverage[2] = dataclasses.replace(tally.coverage[2], role="invalid-role")
                        elif label == "foreign-association":
                            tally.coverage[1] = dataclasses.replace(tally.coverage[1],
                                association=ob.TaskKey("control-foreign", 100, 0))
                        elif label == "complete-unknown-prefix":
                            tally.coverage[1] = dataclasses.replace(tally.coverage[1],
                                prefix=ob.Unknown("Synthetic malformed prefix"))
                        elif label == "foreign-task-scope":
                            foreign = ob.TaskKey("control-foreign", 100, 0)
                            tally.coverage[0] = ob.TaskOccurrence(foreign,
                                dataclasses.replace(packet.launch, task=foreign))
                        elif label in domain_cases:
                            target, changes = domain_cases[label]
                            task = dataclasses.replace(packet.launch.task, **changes)
                            if target == "task-and-association":
                                tally.coverage[0] = dataclasses.replace(tally.coverage[0], key=task,
                                    witness=dataclasses.replace(packet.launch, task=task))
                            tally.coverage[1] = dataclasses.replace(tally.coverage[1], association=task)
                    tally.metadata(tuple(tally.coverage))
                    returned = tally.receipt()
                    if label in domain_cases:
                        self.assertIs(returned.before, checkpoint)
                        self.assertIs(returned.before.allowance, checkpoint.allowance)
                        self.assertEqual(returned.refusals, ())
                        self.assertEqual(returned.newly_charged.scope_counts, ((packet.stage, 1, 1),))
                        self.assert_usage(self.usage_sum(ob, returned.measured_delta, returned.conservative_delta,
                                                         returned.unused_allowance), checkpoint.allowance)
                    if label == "copied-before":
                        returned = dataclasses.replace(returned, before=dataclasses.replace(checkpoint))
                    self.assertIs(type(returned), ob.OperationReceipt)
                    with self.assertRaisesRegex(ValueError, "untrusted-receipt"):
                        owner._receive(returned)
                self.assert_lost(ob, owner, trusted, checkpoint)
                lost = owner._snapshot
                self.assertEqual(lost.stopped.code, "untrusted-receipt")
                with self.assertRaises(ValueError):
                    owner._receive(returned)
                self.assertIs(owner._snapshot.book, lost.book)
                self.assertIs(owner._snapshot.checkpoint, lost.checkpoint)
                self.assertEqual(owner._snapshot.closure, "held")

    def test_loader_directory_admission_bounds_real_os_work_before_refusal(self):
        loaded = self.modules()
        driver = loaded.replay._driver
        root = Path(driver.__file__).parent
        for name, module in zip(MODULES, (loaded.observation, loaded.replay)):
            self.remove_owned_module(name, module)
        real_listdir, real_scandir = os.listdir, os.scandir
        directory_identity = root.stat()
        entries, work, executed = [], [], []
        active = True
        def at_root(path):
            if isinstance(path, int):
                current = os.fstat(path)
                return (current.st_dev, current.st_ino) == (directory_identity.st_dev, directory_identity.st_ino)
            return Path(os.fsdecode(path)) == root
        def observed_listdir(path="."):
            values = real_listdir(path)
            if at_root(path):
                work.append(("listdir", len(values)))
                entries.extend(os.fsdecode(value) for value in values)
            return values
        class ObservedDirectory:
            def __init__(self, iterator, watched):
                self.iterator, self.watched = iterator, watched
            def __enter__(self):
                self.iterator.__enter__()
                return self
            def __exit__(self, *args):
                return self.iterator.__exit__(*args)
            def __iter__(self):
                return self
            def __next__(self):
                entry = next(self.iterator)
                if self.watched:
                    work.append(("scandir", 1))
                    entries.append(os.fsdecode(entry.name))
                return entry
            def close(self):
                return self.iterator.close()
        def observed_scandir(path="."):
            return ObservedDirectory(real_scandir(path), at_root(path))
        def observe(event, args):
            if active and event == "exec":
                path = Path(args[0].co_filename)
                if path.parent == root and path.name in HELPERS:
                    executed.append(path.name)
        sys.addaudithook(observe)
        before_path = tuple(sys.path)
        os.listdir, os.scandir = observed_listdir, observed_scandir
        try:
            admitted = driver._load_helpers()
            self.assertEqual(executed, list(HELPERS))
            self.assertEqual(set(entries), {"preflight.py", "fixtures", *HELPERS})
            self.assertEqual(sum(amount for _, amount in work), 4)
            for name, module in zip(MODULES, (admitted.observation, admitted.replay)):
                self.assertIs(sys.modules.get(name), module)
                self.remove_owned_module(name, module)
            for index in range(8):
                (root / f"unexpected-{index}.py").write_bytes(b"raise RuntimeError('never execute')\n")
            entries.clear()
            work.clear()
            executed.clear()
            with self.assertRaises(ValueError):
                driver._load_helpers()
            self.assertEqual(executed, [])
            self.assertTrue(all(name not in sys.modules for name in MODULES))
            self.assertIs(sys.modules.get(driver.__name__), driver)
            self.assertEqual(tuple(sys.path), before_path)
            self.assertGreater(sum(amount for _, amount in work), 0)
            self.assertLessEqual(sum(amount for _, amount in work), 5,
                                 "The OS must not materialize entries hidden by a later Path-yield bound")
        finally:
            active = False
            os.listdir, os.scandir = real_listdir, real_scandir
            for name, filename in zip(MODULES, HELPERS):
                module = sys.modules.get(name)
                if module is not None and getattr(module, "__file__", None) == str(root / filename):
                    self.remove_owned_module(name, module)

    def test_cleanup_never_signals_reused_group_after_owned_child_reap(self):
        loaded = self.modules()
        rp = loaded.replay
        location = self.bundle.location("cleanup-ownership")
        for case in ("owned", "empty", "reused"):
            with self.subTest(case=case):
                body = "import time; time.sleep(5)" if case == "owned" else "pass"
                process = subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", body],
                    cwd=location, env=self.adapter.clean_environment(location), stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    close_fds=True, pass_fds=(), start_new_session=True)
                real_killpg = os.killpg
                actions = []
                def group_boundary(group, action):
                    self.assertEqual(group, process.pid)
                    actions.append((action, process.returncode))
                    if case == "reused":
                        return None
                    if case == "empty":
                        raise ProcessLookupError(group)
                    if action != 0:
                        self.assertIsNone(process.returncode, "The owned wait anchor must still exist before signaling")
                        self.assertEqual(os.getpgid(process.pid), process.pid)
                    return real_killpg(group, action)
                try:
                    if case != "owned":
                        self.assertEqual(process.wait(timeout=5), 0)
                        self.assertIsNotNone(process.returncode)
                        with self.assertRaises(ProcessLookupError):
                            real_killpg(process.pid, 0)
                    os.killpg = group_boundary
                    result = rp._cleanup(process, case == "owned")
                    self.assertTrue(result.tracer_reaped)
                    self.assertEqual(result.owned_group_empty, case != "reused")
                    signals = [(action, status) for action, status in actions if action != 0]
                    if case == "owned":
                        self.assertTrue(signals, "The safe adapter must observe a real still-owned group signal")
                        self.assertTrue(all(status is None for _, status in signals))
                    else:
                        self.assertEqual(signals, [], "Reaping consumes authority to signal a numeric group")
                finally:
                    os.killpg = real_killpg
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=5)

    def fixed_controls(self):
        if type(self).control_cache is not None:
            return self.assert_control_value(type(self).control_cache)
        self.assertFalse(type(self).control_attempted,
                         "The one real control attempt did not return trustworthy data; no unchanged retry")
        root = self.extracted()
        self.assert_loaded(self.loader_result(root), root)
        owner = self.bundle.location("actual-controls")
        stdout_path, stderr_path = owner / "stdout", owner / "stderr"
        type(self).control_attempted = True
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            process = subprocess.Popen(
                [sys.executable, "-I", "-S", "-B", str(self.control_child), str(root),
                 str(owner / "owned"), str(HERE.parents[2])],
                cwd=owner, env=self.adapter.clean_environment(owner), stdin=subprocess.DEVNULL,
                stdout=stdout, stderr=stderr, close_fds=True, pass_fds=(), start_new_session=True,
            )
            deadline = time.monotonic() + 330
            try:
                while process.poll() is None:
                    self.assertLess(time.monotonic(), deadline, "Fixed controls exceeded outer 330 seconds")
                    self.assertLessEqual(max(stdout_path.stat().st_size, stderr_path.stat().st_size), 1048576)
                    time.sleep(0.01)
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        self.assertEqual(process.returncode, 0, "A child crash is never a qualified negative control")
        self.assertLessEqual(max(stdout_path.stat().st_size, stderr_path.stat().st_size), 1048576)
        self.assertEqual(stderr_path.read_bytes(), b"")
        value = json.loads(stdout_path.read_bytes())
        type(self).control_cache = value
        return self.assert_control_value(value)

    def assert_control_value(self, value):
        self.assertEqual(value["state"], "CAPTURED", "NEW real fixed capture is unavailable")
        self.assertEqual(value["platform"], "linux", "Actual controls require later Linux execution; no default skip")
        self.assertTrue(value["shared_packet_identity"])
        return value

    def control_stage(self, value, name):
        qualification = value["qualification"]
        cases = [case for case in qualification["cases"] if case["name"] == name]
        self.assertEqual(len(cases), 1, "The finite fixed control must run exactly once")
        self.assertTrue(cases[0]["qualified"], "Qualification is separate from packet completeness")
        stages = [stage for stage in qualification["book"]["stages"] if stage["stage"] in cases[0]["scope_ids"]]
        self.assertTrue(stages, "A control summary cannot replace its sealed stage")
        return stages

    def test_actual_nonzero_signal_limits_withholding_and_synthetic_edits(self):
        value = self.fixed_controls()
        nonzero = self.control_stage(value, "exit-seven")[0]
        killed = self.control_stage(value, "sigterm")[0]
        self.assertEqual(nonzero["origin"], "ActualControl")
        self.assertEqual(nonzero["end"]["wait"], {"code": 7})
        self.assertEqual(killed["origin"], "ActualControl")
        self.assertIn(set(killed["end"]["wait"]), ({"code"}, {"signal"}),
                      "The actual tracer wait stays separate from the tracee signal")
        self.assertNotEqual(killed["end"]["wait"], {"code": 7})
        signal_refs = [marker["raw_refs"] for marker in killed["terminal_markers"]
                       if marker["terminal"] == {"signal": "SIGTERM"}]
        self.assertTrue(signal_refs and all(signal_refs), "Actual SIGTERM needs its own byte-bound terminal marker")
        for stage in (nonzero, killed):
            launch = stage["launch"]
            keys = {bytes.fromhex(key["bytes_hex"]) for key, _ in launch["environment"]}
            self.assertEqual(keys, {key for key, _ in ENVIRONMENT})
            self.assertEqual(launch["stdin"], "DEVNULL")
            self.assertTrue(launch["close_fds"])
            self.assertEqual(launch["pass_fds"], [])
            self.assertGreater(launch["tracer_pid"], 0)
            self.assertEqual(launch["session_id"], launch["tracer_pid"])
        prefix = self.control_stage(value, "prefix-4096")[0]
        self.assertEqual(prefix["origin"], "ActualControl")
        self.assertEqual(prefix["status"], "incomplete")
        partials = [item for item in prefix["members"] if "prefix_length" in item]
        self.assertTrue(partials)
        self.assertTrue(any(item["prefix_length"] == 4096 for item in partials))
        for item in partials:
            self.assertNotIn("sha256", item)
            self.assertEqual(digest(bytes.fromhex(item["data"]["bytes_hex"])), item["prefix_sha256"])
        self.assertTrue(any(item["extent"].get("byte_length", 0) > 4096 for item in partials),
                        "The real prefix control must observe a larger output")
        count = self.control_stage(value, "trace-members-two")[0]
        self.assertEqual(count["status"], "incomplete")
        self.assertEqual(count["end"]["trigger"], "cap")
        self.assertIn("local-member-cap", {reason["code"] for reason in count["reasons"]})
        for name, marker in (("withhold-content", CONTENT_MARKER), ("withhold-name", NAME_MARKER)):
            stage = self.control_stage(value, name)[0]
            self.assertEqual(stage["status"], "incomplete")
            withheld = [item for item in stage["members"] if item.get("reason") in ("sensitive-content", "sensitive-name")]
            self.assertTrue(withheld)
            for item in withheld:
                for field in ("name", "data", "sha256", "prefix_sha256"):
                    self.assertNotIn(field, item)
            encoded = json.dumps(value, sort_keys=True)
            for forbidden in (marker.decode(), marker.hex(), digest(marker)):
                self.assertNotIn(forbidden, encoded, "Ordinary returned evidence must not disclose withheld data")
        for name, reason in (("missing-terminal-synthetic", "missing-task-terminal"),
                             ("missing-reap-synthetic", "cleanup-incomplete")):
            stage = self.control_stage(value, name)[0]
            self.assertEqual((stage["origin"], stage["status"]), ("Synthetic", "incomplete"))
            self.assertIn(reason, {item["code"] for item in stage["reasons"]})

    def test_actual_unsupported_syntax_collector_error_and_owned_timeout(self):
        value = self.fixed_controls()
        unsupported = self.control_stage(value, "unsupported-syntax")[0]
        self.assertEqual(unsupported["status"], "incomplete")
        self.assertTrue(any(reason["raw_refs"] for reason in unsupported["reasons"]))
        for name, trigger in (("collector-exception", "collector-error"), ("owned-timeout", "timeout")):
            stage = self.control_stage(value, name)[0]
            self.assertEqual((stage["origin"], stage["status"]), ("ActualControl", "incomplete"))
            self.assertEqual(stage["end"]["trigger"], trigger)
            self.assertNotIn("reason", stage["end"]["wait"], "Actual final direct-child wait is required")
            self.assertEqual(stage["end"]["cleanup"], {"tracer_reaped": True, "owned_group_empty": True})
        timeout = self.control_stage(value, "owned-timeout")[0]
        self.assertIn("signal", timeout["end"]["wait"], "Timeout cannot erase the actual final signal wait")

    def test_fixed_capture_receipts_keep_cumulative_reread_and_refusal_charges(self):
        value = self.fixed_controls()
        successive = self.control_stage(value, "successive-captures")
        self.assertGreaterEqual(len(successive), 2)
        refusal = self.control_stage(value, "reread-refusal")[-1]
        self.assertEqual(refusal["status"], "incomplete")
        receipts = value["qualification"]["book"]["operations"]
        self.assertTrue(receipts)
        checkpoints = [receipt["before"] for receipt in receipts]
        self.assertEqual(len({item["session_id"] for item in checkpoints}), 1)
        sequences = [item["operation_sequence"] for item in checkpoints]
        self.assertEqual(sequences, sorted(set(sequences)), "Each matching receipt is committed at most once")
        measured = [item["committed"]["traversal_bytes"] for item in checkpoints]
        self.assertEqual(measured, sorted(measured))
        self.assertGreaterEqual(measured[0], value["initialization"]["measured_usage"]["traversal_bytes"])
        for field in ("retained", "export_files", "physical_records", "scope_counts", "four_row_members", "four_row_tasks"):
            self.assertIn(field, checkpoints[0]["committed"], "Every accepted count/category dimension must survive")
        selected = [receipt for receipt in receipts if receipt["before"] in [stage["operation"]["before"] for stage in successive]]
        self.assertGreaterEqual(len(selected), 2)
        self.assertTrue(all(item["measured_delta"]["traversal_bytes"] > 0 for item in selected))
        charged_refusals = [receipt for receipt in receipts if receipt["before"] == refusal["operation"]["before"]]
        self.assertEqual(len(charged_refusals), 1)
        self.assertGreater(charged_refusals[0]["measured_delta"]["traversal_bytes"], 0)
        self.assertTrue(charged_refusals[0]["refusals"], "A refused traversal retains its charged refusal receipt")

    def test_real_untraced_gap_pair_preserves_original_clock_and_cleanup(self):
        value = self.fixed_controls()
        clock_cases = value["qualification"]["clock_cases"]
        self.assertEqual({case["name"] for case in clock_cases}, {"read-gap-before", "read-gap-after"})
        identities = value["qualification"]["book"]["identities"]
        self.assertTrue(identities, "The new owner must retain charged pre-use fixture identity evidence")
        for case in clock_cases:
            with self.subTest(case=case["name"]):
                self.assertGreaterEqual(case["gap_end"] - case["gap_start"], 61)
                self.assertEqual(case["owner_end_before"], case["owner_end_after"])
                manifest = case["original_manifest"]
                self.assertEqual(manifest["evidence_complete"], case["name"] == "read-gap-before")
                if case["name"] == "read-gap-before":
                    self.assertIsNone(case["collection_started_before_gap"])
                else:
                    self.assertIsInstance(case["collection_started_before_gap"], (int, float))
                    self.assertLessEqual(case["collection_started_before_gap"], case["gap_start"])
                    self.assertTrue(any("60 seconds" in issue or "collector" in issue for issue in manifest["issues"]))
                self.assertTrue(manifest["cleanup"]["deleted"])
                self.assertTrue(manifest["cleanup"]["shutil_restored"])
                self.assertTrue(manifest["restored"])
                self.assertTrue(manifest["source_counts"])
                self.assertEqual(manifest["source_counts"], manifest["source_blob_counts"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
