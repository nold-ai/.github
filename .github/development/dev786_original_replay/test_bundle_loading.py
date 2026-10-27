from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
import zlib


_configured_inputs = os.environ.get("DEV786_PREFLIGHT_INPUTS")
if not _configured_inputs or not Path(_configured_inputs).is_absolute():
    raise RuntimeError("Set absolute DEV786_PREFLIGHT_INPUTS before collecting bundle tests")
INPUTS = Path(_configured_inputs).resolve(strict=True)
HERE = Path(__file__).resolve().parent
HELPERS = ("observation.py", "replay.py")
MODULES = ("_dev786_original_replay_observation", "_dev786_original_replay_replay")
ORIGINAL_OWNERS = (
    "sha", "encoded", "require", "frozen_inputs", "load_policy", "fixtures", "Deadline",
    "command_cleanup", "Timer", "schedule", "Transcript", "expected", "exception_facts",
    "Evidence", "cleanup_observer", "adapter_controls", "cleanup_signal_control",
    "cleanup_controls", "acquisition_negatives", "restored_acquisition", "tool_facts",
    "actual", "creation_control", "export_bytes", "publish_safe", "main",
)
OWNER_SOURCE_SHA = "9af0bb2d29a86660bc543c1db206519d2c957db0e78939fce798b6d39065c393"
CONSTANT_SOURCE_SHA = "a3fa7c3c5c9a936600ec8970680611e1e28c9b41428718bf1457e1c37e2bf847"
PREFIX_SHA = "a164650c45b033b2da357918bcc961c4f8b32f38e09ce00ca3de517a0b8e51a3"
SUFFIX_SHA = "3af40a1ba25a8d19cf632c2ad9e6dc991c705ddecb39f11ecfb1777800267826"
SOURCE_CAP = 256 * 1024
OUTPUT_CAP = 1024 * 1024
FIXTURES = {
    "compare.json": (326, "e49c731f723a5bfe5daae171806b3e37caad1f46902e37a27d7bb6800a0f8599"),
    "corrupt-input-envelope.json": (738, "873544e96ec37ac6b2557691048493a492557aaade29a6eab0eb2606a451eeb5"),
    "corrupt-requirements.in": (413, "b909849caf501cb1343aecf0e80fc26bf997126a78d574c46881d5e54741b18b"),
    "index-envelope.json": (638, "50e7030d2509d0adeae22777643fcae3af4ce8656c65fc623fe46fc7ea9ef520"),
    "index.json": (347, "8bb0276e13664a5208a26451fd66a7e83620c445209b0d24a569daf78d78bc27"),
    "main.json": (101, "2e6ee0a8cf7619f4dbe5624eb4814d59df4a701158d64c8af177c426e30b71db"),
    "moved-main.json": (101, "9187f2fd6a58682fcd4965fefc100865e6d7b8f5155034d382a24b478e8d664e"),
    "wrong-index-envelope.json": (638, "29ef78589ab54e3eba309f464d21d5051d0041eb93a1a05fda292d43034805b5"),
    "wrong-index.json": (347, "cd491ae49ee174fc79d4eed775b22c03156d2d39ad147769da3a5afbed171359"),
}
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
EXEC_RECORD = (
    b'1700000000.000001 execve("/owned/bin/first", '
    b'["/owned/bin/first", "literal,..."], ' + RAW_ENVIRONMENT + b') = 0\n'
)
OPEN_RECORD = (
    b'1700000000.000003 openat(AT_FDCWD</owned/work>, "direct", '
    b'O_RDONLY) = 3</owned/work/direct>\n'
)
EXIT_RECORD = b'1700000000.000020 exit_group(0) = ?\n'
TERMINAL_RECORD = b'1700000000.000021 +++ exited with 0 +++\n'
BINARY_BYTES = b"Synthetic first executable identity, never executed"


CHILD = r'''
import dataclasses
import enum
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import types

root, action = Path(sys.argv[1]), sys.argv[2]
before_path = tuple(sys.path)
name = "_dev786_bundle_preflight"
spec = importlib.util.spec_from_file_location(name, root / "preflight.py")
driver = importlib.util.module_from_spec(spec)
sys.modules[name] = driver
spec.loader.exec_module(driver)
loader = getattr(driver, "_load_helpers", None)
if not callable(loader):
    print(json.dumps({"state": "NEW_LOADER_UNAVAILABLE"}))
    raise SystemExit(0)
names = ("_dev786_original_replay_observation", "_dev786_original_replay_replay")
files = ("observation.py", "replay.py")
if action.startswith("preloaded-"):
    index = files.index(action.removeprefix("preloaded-"))
    substitute = types.ModuleType(names[index])
    substitute.__file__ = str(root / files[index])
    sys.modules[substitute.__name__] = substitute
helper_executions = []
def observe_execution(event, args):
    if event == "exec" and Path(args[0].co_filename).parent == root:
        helper_executions.append(args[0].co_filename)
sys.addaudithook(observe_execution)
try:
    loaded = loader()
except ValueError:
    print(json.dumps({"state": "REFUSED", "path_unchanged": tuple(sys.path) == before_path,
                      "helper_execution_count": len(helper_executions)}))
    raise SystemExit(0)

observer = loaded.observation
missing = [name for name in ("MemberId", "Complete", "TraceAssociation", "CaptureEnd", "WaitExited",
                             "Usage", "Checkpoint", "Book", "Incomplete", "MemberOccurrence",
                             "TaskOccurrence", "OperationReceipt") if not hasattr(observer, name)]
if not callable(getattr(observer, "_allowance", None)):
    missing.append("_allowance")
if not missing and tuple(field.name for field in dataclasses.fields(observer.Checkpoint)) != (
        "session_id", "operation_sequence", "committed", "measured", "conservative", "closure_reserved",
        "basis", "scope", "allowance"):
    missing.append("expanded Checkpoint constructor")
if missing:
    print(json.dumps({"state": "NEW_CAPTURE_DATA_UNAVAILABLE", "missing": missing}))
    raise SystemExit(0)

def wire(value):
    if dataclasses.is_dataclass(value):
        kind = type(value).__name__
        if kind == "MemberOccurrence":
            return {"scope": value.scope, "role": value.role, "member_id": wire(value.member.member_id),
                    "association": wire(value.association), "prefix": wire(value.prefix)}
        if kind == "TaskOccurrence":
            witness = ({"launch_task": wire(value.witness.task)} if isinstance(value.witness, observer.Launch)
                       else {"birth_refs": wire(value.witness)})
            return {"key": wire(value.key), **witness}
        return {field.name: ({"session_id": value.session_id, "operation_sequence": value.operation_sequence}
                            if kind == "Checkpoint" and field.name == "basis"
                            else wire(getattr(value, field.name))) for field in dataclasses.fields(value)}
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if isinstance(value, tuple):
        return [wire(item) for item in value]
    return value

stage = "synthetic-observer-unit"
task = observer.TaskKey(stage, 100, 0)
env = ((b"HOME", b"/owned/home"), (b"TMPDIR", b"/owned/tmp"),
       (b"PATH", b"/owned/bin:/usr/bin:/bin"), (b"LC_ALL", b"C.UTF-8"),
       (b"VIRTUAL_ENV", b"/owned/venv"), (b"SPECFACT_MODULES_REPO", b"/owned/modules"),
       (b"SPECFACT_MODULES_ROOTS", b"/owned/modules/packages"))
raw_env = (b'["HOME=/owned/home", "TMPDIR=/owned/tmp", "PATH=/owned/bin:/usr/bin:/bin", '
           b'"LC_ALL=C.UTF-8", "VIRTUAL_ENV=/owned/venv", "SPECFACT_MODULES_REPO=/owned/modules", '
           b'"SPECFACT_MODULES_ROOTS=/owned/modules/packages"]')
lines = (
    b'1700000000.000001 execve("/owned/bin/first", '
    b'["/owned/bin/first", "literal,..."], ' + raw_env + b') = 0\n',
    b'1700000000.000003 openat(AT_FDCWD</owned/work>, "direct", '
    b'O_RDONLY) = 3</owned/work/direct>\n',
    b'1700000000.000020 exit_group(0) = ?\n',
    b'1700000000.000021 +++ exited with 0 +++\n',
)
raw = b"".join(lines)
binary_bytes = b"Synthetic first executable identity, never executed"
binary = observer.BinaryIdentity(b"/owned/bin/first", b"/owned/libexec/first",
                                 len(binary_bytes), hashlib.sha256(binary_bytes).hexdigest())
argv = (b"/owned/bin/first", b"literal,...")
trace = (b"/usr/bin/strace", b"-ff", b"-v", b"-s", b"131072", b"-yy", b"-ttt", b"-e",
         b"trace=%process,%file,fchdir,getcwd,close,close_range,dup,dup2,dup3,fcntl,unshare,setsid,setpgid",
         b"-o", b"/owned/traces/trace") + argv
member = observer.Complete(observer.MemberId("m-parent"), "trace.100", raw, len(raw),
                           hashlib.sha256(raw).hexdigest())
stdout = observer.Complete(observer.MemberId("m-stdout"), "stdout", b"", 0, hashlib.sha256(b"").hexdigest())
stderr = observer.Complete(observer.MemberId("m-stderr"), "stderr", b"", 0, hashlib.sha256(b"").hexdigest())
closure = observer.Usage(traversal_bytes=1048576,
                         retained=(("preparation-restoration-export", 65536),), export_files=1)
checkpoint = observer.Checkpoint("synthetic-bundle-session", 0, observer.Usage(), observer.Usage(),
                                 observer.Usage(), closure,
                                 observer.Book((), (), (), (), (), (None, None),
                                     observer.Unknown("original-not-run", ()), observer.Unknown("replay-not-finished", ()),
                                     observer.Unknown("retrieval-not-run", ()), observer.Incomplete(())),
                                 stage, observer.Usage())
checkpoint = dataclasses.replace(checkpoint, allowance=observer._allowance(stage, checkpoint))
packet = observer.StagePacket(
    origin=observer.Origin.SYNTHETIC, origin_label="bundle-complete", stage=stage,
    launch=observer.Launch(task, argv, env, b"/owned/work", binary, trace, env, 900, 900,
                    "DEVNULL", True, ()),
    trace_members=(observer.TraceAssociation(member, task),), stdout=stdout, stderr=stderr,
    tracer_diagnostics=stderr, binary_identities=(binary,),
    end=observer.CaptureEnd("returned", observer.WaitExited(0), observer.Cleanup(True, True)),
    accounting=checkpoint,
)
complete = observer.inspect(packet)
malformed = observer.inspect(dataclasses.replace(
    packet, origin_label="bundle-malformed",
    trace_members=(observer.TraceAssociation(dataclasses.replace(member, sha256="0" * 64), task),)))
print(json.dumps({"state": "LOADED", "path_unchanged": tuple(sys.path) == before_path,
                  "helper_execution_count": len(helper_executions),
                  "module_name": observer.__name__, "file": observer.__file__,
                  "spec_origin": observer.__spec__.origin,
                  "registered": sys.modules.get(observer.__name__) is observer,
                  "helper_executions": helper_executions,
                  "modules": [{"name": module.__name__, "file": module.__file__,
                               "spec_origin": module.__spec__.origin,
                               "registered": sys.modules.get(module.__name__) is module}
                              for module in (loaded.observation, loaded.replay)],
                  "initialization_immutable": dataclasses.is_dataclass(loaded.initialization)
                      and loaded.initialization.__dataclass_params__.frozen,
                  "initialization_helpers": [item.name for item in loaded.initialization.helper_identities],
                  "initialization_reads": loaded.initialization.measured_usage.traversal_bytes,
                  "initialization": wire(loaded.initialization),
                  "complete": wire(complete), "malformed": wire(malformed)}, sort_keys=True))
'''


DECODER_CHILD = r'''
import json
from pathlib import Path
import runpy
import sys

script, root, receipt = map(Path, sys.argv[1:])
helper_executions = []
def observe_execution(event, args):
    if event == "exec" and Path(args[0].co_filename).parent == root:
        helper_executions.append(args[0].co_filename)
sys.addaudithook(observe_execution)
try:
    runpy.run_path(str(script), run_name="__main__")
finally:
    receipt.write_text(json.dumps(helper_executions))
'''


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def literal(tree: ast.Module, name: str):
    nodes = [node.value for node in tree.body if isinstance(node, ast.Assign)
             and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    if not nodes:
        return None
    if len(nodes) != 1:
        raise AssertionError(f"Expected one literal {name}")
    return ast.literal_eval(nodes[0])


def clean_environment(owner: Path, runner_temp: Path | None = None) -> dict[str, str]:
    home, tmp = owner / "home", owner / "tmp"
    home.mkdir(mode=0o700, exist_ok=True)
    tmp.mkdir(mode=0o700, exist_ok=True)
    result = {"HOME": str(home), "TMPDIR": str(tmp), "PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"}
    if runner_temp is not None:
        result["RUNNER_TEMP"] = str(runner_temp)
    return result


def launch(script: Path, owner: Path, *args: str, runner_temp: Path | None = None):
    owner.mkdir(mode=0o700, exist_ok=True)
    stdout_path, stderr_path = owner / "stdout", owner / "stderr"
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        process = subprocess.Popen(
            [sys.executable, "-I", "-S", "-B", str(script), *args], cwd=owner,
            env=clean_environment(owner, runner_temp), stdin=subprocess.DEVNULL,
            stdout=stdout, stderr=stderr, close_fds=True, pass_fds=(), start_new_session=True,
        )
        deadline = time.monotonic() + 15
        try:
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    raise AssertionError("Isolated bundle child exceeded 15 seconds")
                if max(stdout_path.stat().st_size, stderr_path.stat().st_size) > OUTPUT_CAP:
                    raise AssertionError("Isolated bundle child exceeded stream bound")
                time.sleep(0.01)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
    if max(stdout_path.stat().st_size, stderr_path.stat().st_size) > OUTPUT_CAP:
        raise AssertionError("Isolated bundle child stream was oversized")
    return process.returncode, stdout_path.read_bytes(), stderr_path.read_bytes()


def generated(workflow: str) -> tuple[str, bytes]:
    chunks = re.findall(r"(?m)^\s*printf '%s' '([A-Za-z0-9+/=]+)' >>", workflow)
    decoders = re.findall(
        r"(?ms)^          /usr/bin/python3 -I -S - <<'PY_DECODE'\n(.*?)^          PY_DECODE\n",
        workflow,
    )
    if not chunks or len(decoders) != 1:
        raise AssertionError("Actual generated transport/PY_DECODE format changed; review adapter")
    return textwrap.dedent(decoders[0]), "".join(chunks).encode("ascii")


def payloads(decoder: str, transport: bytes):
    manifest = literal(ast.parse(decoder), "manifest")
    decompressor = zlib.decompressobj()
    raw = decompressor.decompress(base64.b64decode(transport, validate=True), SOURCE_CAP + 1)
    if len(raw) > SOURCE_CAP or not decompressor.eof or decompressor.unused_data or decompressor.unconsumed_tail:
        raise AssertionError("Actual baseline builder emitted invalid/oversized compressed source")
    result, offset = [], 0
    for name, size, sha256 in manifest:
        data = raw[offset:offset + size]
        if len(data) != size or digest(data) != sha256:
            raise AssertionError("Actual baseline builder emitted inconsistent payload identity")
        result.append((name, data))
        offset += size
    if offset != len(raw):
        raise AssertionError("Actual baseline payload was not fully accounted")
    return manifest, result


def perturbed_decoder(original: str, manifest, contents):
    joined = b"".join(data for _, data in contents)
    compressed = zlib.compress(joined, level=9)
    transport = base64.b64encode(compressed)
    replacements = {
        "transport.stat().st_size": len(transport),
        "len(transport_bytes)": len(transport),
        "len(compressed)": len(compressed),
        "hashlib.sha256(compressed).hexdigest()": digest(compressed),
        "total": len(joined),
    }
    changed = {key: 0 for key in (*replacements, "manifest", "expected_names", "stream.read")}

    class InputsOnly(ast.NodeTransformer):
        def visit_Assign(self, node):
            names = [target.id for target in node.targets if isinstance(target, ast.Name)]
            for name, value in (("manifest", manifest), ("expected_names", [item[0] for item in manifest])):
                if name in names:
                    node.value = ast.parse(repr(value), mode="eval").body
                    changed[name] += 1
            return self.generic_visit(node)

        def visit_Compare(self, node):
            key = ast.unparse(node.left)
            if key in replacements and isinstance(node.ops[0], ast.Eq):
                node.comparators[0] = ast.Constant(replacements[key])
                changed[key] += 1
            return self.generic_visit(node)

        def visit_Call(self, node):
            if ast.unparse(node.func) == "stream.read" and len(node.args) == 1:
                node.args[0] = ast.Constant(len(transport) + 1)
                changed["stream.read"] += 1
            return self.generic_visit(node)

    tree = InputsOnly().visit(ast.parse(original))
    if any(count != 1 for count in changed.values()):
        raise AssertionError(f"Actual decoder envelope format changed; review adapter: {changed}")
    return ast.unparse(ast.fix_missing_locations(tree)) + "\n", transport


class BundleLoadingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="dev786-bundle-tests-")
        cls.owner = Path(cls.temporary.name).resolve()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.counter = 0
        cls.source = cls.owner / "source"
        cls.source.mkdir(mode=0o700)
        for name in ("build.py", "preflight.py"):
            path = INPUTS / name
            if path.is_symlink() or not path.is_file():
                raise RuntimeError(f"Required regular test input missing: {name}")
            shutil.copyfile(path, cls.source / name)
        fixture_source = INPUTS / "fixtures"
        if fixture_source.is_symlink() or {path.name for path in fixture_source.iterdir()} != set(FIXTURES):
            raise RuntimeError("Recovery fixture directory differs from the nine fixed inputs")
        (cls.source / "fixtures").mkdir(mode=0o700)
        for name, (size, sha256) in FIXTURES.items():
            path = fixture_source / name
            if path.is_symlink() or not path.is_file():
                raise RuntimeError(f"Required regular fixture missing: {name}")
            raw = path.read_bytes()
            if (len(raw), digest(raw)) != (size, sha256):
                raise RuntimeError(f"Recovery fixture identity differs: {name}")
            (cls.source / "fixtures" / name).write_bytes(raw)
        cls.original_driver = ast.parse((cls.source / "preflight.py").read_bytes())
        cls.helper_manifest = literal(cls.original_driver, "HELPER_MANIFEST")
        if not isinstance(cls.helper_manifest, tuple) or not cls.helper_manifest:
            raise AssertionError("The real baseline must retain its trusted helper manifest")
        for name, size, sha256, module_name in cls.helper_manifest:
            if name not in HELPERS or module_name != MODULES[HELPERS.index(name)]:
                raise AssertionError("Only the two fixed real helper identities are in scope")
            path = HERE / name
            if path.is_symlink() or not path.is_file():
                raise AssertionError("A declared helper must be real regular source")
            with path.open("rb") as stream:
                raw = stream.read(size + 1)
            if (len(raw), digest(raw)) != (size, sha256):
                raise AssertionError("Real sibling helper identity differs from the reviewed manifest")
            (cls.source / name).write_bytes(raw)
        result = launch(cls.source / "build.py", cls.owner / "builder")
        if result[0] != 0:
            raise AssertionError(f"Actual baseline builder failed before new behavior: {result!r}")
        cls.workflow = (cls.source / "native-materialization-preflight.yml").read_text()
        cls.decoder, cls.transport = generated(cls.workflow)
        cls.manifest, cls.contents = payloads(cls.decoder, cls.transport)
        cls.harness = cls.owner / "inspect_child.py"
        cls.harness.write_text(CHILD)
        cls.decoder_harness = cls.owner / "decoder_child.py"
        cls.decoder_harness.write_text(DECODER_CHILD)

    def location(self, label: str) -> Path:
        type(self).counter += 1
        path = self.owner / f"{type(self).counter:03d}-{label}"
        path.mkdir(mode=0o700)
        return path

    def require_delivered_helper(self):
        manifest = literal(self.original_driver, "HELPER_MANIFEST")
        self.assertEqual(tuple(item[0] for item in manifest), HELPERS,
                         "NEW actual bundle must deliver both real helpers")
        self.assertEqual(tuple(item[3] for item in manifest), MODULES)
        self.assertEqual({name for name, _ in self.contents},
                         {"preflight.py", *HELPERS, *("fixtures/" + name for name in FIXTURES)})

    def extract(self, decoder: str | None = None, transport: bytes | None = None):
        owner = self.location("extraction")
        runner = owner / "runner"
        runner.mkdir(mode=0o700)
        root = runner / "native-materialization-preflight"
        root.mkdir(mode=0o700)
        (root / "transport.b64").write_bytes(self.transport if transport is None else transport)
        script = owner / "actual_generated_decoder.py"
        script.write_text(self.decoder if decoder is None else decoder)
        receipt = owner / "helper-executions.json"
        result = launch(self.decoder_harness, owner / "child", str(script), str(root), str(receipt),
                        runner_temp=runner)
        self.assertTrue(receipt.is_file(), "Actual generated decoder must be entered and observed")
        self.assertEqual(json.loads(receipt.read_text()), [], "Extraction cannot execute helper source")
        return root, result

    def inspect_child(self, root: Path, action: str = "inspect", poison: bool = False):
        owner = self.location("loader")
        sentinel = owner / "poison-ran"
        if poison:
            body = f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('executed')\n"
            for name in (*HELPERS, *(name + ".py" for name in MODULES)):
                (owner / name).write_text(body)
        result = launch(self.harness, owner, str(root), action)
        self.assertEqual(result[0], 0, f"Isolated child failed outside intended assertions: {result!r}")
        self.assertEqual(result[2], b"", "Unexpected child diagnostic is not a guard refusal")
        value = json.loads(result[1])
        self.assertFalse(sentinel.exists(), "Ambient poison helper executed")
        return value

    def assert_loaded(self, value, root: Path):
        self.assertEqual(value["state"], "LOADED", "NEW actual extracted _load_helpers must initialize both real sources")
        self.assertTrue(value["path_unchanged"])
        self.assertEqual(value["module_name"], MODULES[0])
        self.assertEqual(Path(value["file"]), root / HELPERS[0])
        self.assertEqual(Path(value["spec_origin"]), root / HELPERS[0])
        self.assertTrue(value["registered"], "Accepted dataclasses require the fixed registered identity")
        self.assertEqual(value["helper_execution_count"], 2)
        self.assertEqual(value["helper_executions"], [str(root / name) for name in HELPERS])
        self.assertEqual(value["modules"], [
            {"name": module_name, "file": str(root / name), "spec_origin": str(root / name), "registered": True}
            for name, module_name in zip(HELPERS, MODULES)
        ])
        self.assertTrue(value["initialization_immutable"])
        self.assertEqual(value["initialization_helpers"], list(HELPERS))
        self.assertGreater(value["initialization_reads"], 0)
        initialization = value["initialization"]
        self.assertEqual(initialization["helper_identities"], [
            {"name": name, "byte_length": size, "sha256": sha256, "module_name": module_name}
            for name, size, sha256, module_name in self.helper_manifest
        ])
        for name, size, _, _ in self.helper_manifest:
            for operation, requested in (("source-read", size + 1), ("source-hash", size), ("source-submit", size)):
                visits = [item for item in initialization["bounded_reads"]
                          if item["name"] == name and item["operation"] == operation]
                self.assertEqual(len(visits), 1)
                self.assertEqual((visits[0]["requested_bytes"], visits[0]["delivered_bytes"]), (requested, size))
        self.assertGreaterEqual(initialization["prepaid_envelope"]["traversal_bytes"],
                                initialization["measured_usage"]["traversal_bytes"]
                                + initialization["conservative_debit"]["traversal_bytes"]
                                + initialization["adoption_reserved"]["traversal_bytes"])
        self.assertGreater(initialization["adoption_reserved"]["traversal_bytes"], 0)
        for operation in ("identity-compare", "order-compare", "receipt-copy", "directory-entry", "adoption-compare"):
            self.assertTrue(any(item["operation"] == operation and item["requested_bytes"] > 0
                                for item in initialization["bounded_reads"]), "NEW initialization must prepay " + operation)

    def assert_ref(self, value, start: int, line: int, record: bytes):
        self.assertEqual(value, {"member": {"value": "m-parent"}, "byte_start": start,
                                 "byte_stop": start + len(record), "physical_line": line})

    def test_real_generated_bundle_reaches_accepted_inspect_and_raw_refusals(self):
        root, result = self.extract()
        self.assertEqual(result[0], 0, f"Real generated decoder failed: {result!r}")
        value = self.inspect_child(root)
        self.assert_loaded(value, root)
        complete = value["complete"]
        self.assertEqual((complete["origin"], complete["origin_label"], complete["stage"], complete["status"]),
                         ("Synthetic", "bundle-complete", "synthetic-observer-unit", "observed"))
        self.assertEqual(complete["reasons"], [])
        self.assertEqual(complete["operation"]["before"]["basis"],
                         {"session_id": "synthetic-bundle-session", "operation_sequence": 0})
        self.assertEqual(complete["operation"]["before"]["scope"], "synthetic-observer-unit")
        self.assertEqual(complete["operation"]["newly_charged"]["physical_records"], 4)
        self.assertEqual(complete["operation"]["encountered"]["physical_records"], 4)
        for reference in complete["operation"]["coverage"]:
            self.assertNotIn("member", reference, "New coverage carries canonical IDs, never another payload")
            self.assertNotIn("data", reference)
        task = {"stage": "synthetic-observer-unit", "tid": 100, "birth_generation": 0}
        argv = [{"bytes_hex": arg.hex()} for arg in (b"/owned/bin/first", b"literal,...")]
        environment = [[{"bytes_hex": key.hex()}, {"bytes_hex": val.hex()}] for key, val in ENVIRONMENT]
        self.assertEqual(complete["launch"]["task"], task)
        self.assertEqual(complete["launch"]["argv"], argv)
        self.assertEqual(complete["launch"]["environment"], environment)
        self.assertEqual(complete["launch"]["cwd"], {"bytes_hex": b"/owned/work".hex()})
        self.assertEqual(complete["end"], {"trigger": "returned", "wait": {"code": 0},
                         "cleanup": {"tracer_reaped": True, "owned_group_empty": True}})
        raw = EXEC_RECORD + OPEN_RECORD + EXIT_RECORD + TERMINAL_RECORD
        self.assertEqual(len(complete["members"]), 3)
        members = {item["member_id"]["value"]: item for item in complete["members"]}
        self.assertEqual(members, {
            "m-parent": {"member_id": {"value": "m-parent"}, "name": "trace.100",
                         "data": {"bytes_hex": raw.hex()}, "byte_length": len(raw), "sha256": digest(raw)},
            "m-stdout": {"member_id": {"value": "m-stdout"}, "name": "stdout",
                         "data": {"bytes_hex": ""}, "byte_length": 0, "sha256": digest(b"")},
            "m-stderr": {"member_id": {"value": "m-stderr"}, "name": "stderr",
                         "data": {"bytes_hex": ""}, "byte_length": 0, "sha256": digest(b"")},
        })
        self.assertEqual(complete["tracer_diagnostics"], members["m-stderr"])
        self.assertEqual(len(complete["exec_attempts"]), 1)
        attempt = complete["exec_attempts"][0]
        self.assertEqual(attempt["task"], task)
        self.assertEqual(attempt["argv"], argv)
        self.assertEqual(attempt["environment"], environment)
        self.assertEqual(attempt["executable"], {"bytes_hex": b"/owned/bin/first".hex()})
        self.assertEqual(attempt["previous_image"], {"task": task, "generation": 0})
        image = {"task": task, "generation": 1}
        self.assertEqual(attempt["result"], {"image": image})
        self.assertEqual(attempt["cwd"]["value"], {"bytes_hex": b"/owned/work".hex()})
        self.assertEqual(len(attempt["raw_refs"]), 1)
        self.assert_ref(attempt["raw_refs"][0], 0, 1, EXEC_RECORD)
        bound_image = next(item for item in complete["images"] if item["key"] == image)
        self.assertEqual(bound_image["binary"]["value"], {
            "spelling": {"bytes_hex": b"/owned/bin/first".hex()},
            "realpath": {"bytes_hex": b"/owned/libexec/first".hex()},
            "byte_length": len(BINARY_BYTES), "sha256": digest(BINARY_BYTES),
        })
        self.assertEqual(len(complete["path_uses"]), 1)
        use = complete["path_uses"][0]
        self.assertEqual(use["task"], task)
        self.assertEqual(use["image"], image)
        self.assertEqual(use["raw_path"], {"bytes_hex": b"direct".hex()})
        self.assertEqual(use["resolution"]["value"], {"bytes_hex": b"/owned/work/direct".hex()})
        self.assertEqual(use["resolution"]["basis"], "direct-operation")
        self.assertEqual(use["result"], 3)
        self.assertIsNone(use["errno"])
        self.assertEqual(len(use["raw_refs"]), 1)
        self.assert_ref(use["raw_refs"][0], len(EXEC_RECORD), 2, OPEN_RECORD)
        self.assertEqual(len(complete["tasks"]), 1)
        self.assertEqual(complete["tasks"][0]["key"], task)
        terminal = complete["tasks"][0]["terminal"]
        self.assertEqual(terminal["value"], {"code": 0})
        self.assertEqual(len(terminal["raw_refs"]), 1)
        self.assert_ref(terminal["raw_refs"][0], len(raw) - len(TERMINAL_RECORD), 4, TERMINAL_RECORD)
        malformed = value["malformed"]
        self.assertEqual((malformed["origin"], malformed["origin_label"], malformed["status"]),
                         ("Synthetic", "bundle-malformed", "incomplete"))
        self.assertEqual(malformed["reasons"], [{"code": "raw-sha256-mismatch", "task": task, "raw_refs": []}])
        for field in ("tasks", "images", "exec_attempts", "path_uses"):
            self.assertEqual(malformed[field], [], "Unbound raw bytes must retain their accepted refusal")

    def test_closed_delivery_preserves_fixed_inputs_and_existing_driver_owners(self):
        self.require_delivered_helper()
        builder = ast.parse((self.source / "build.py").read_bytes())
        prefix, suffix = literal(builder, "PREFIX"), literal(builder, "SUFFIX")
        self.assertEqual(digest(prefix.encode()), PREFIX_SHA)
        self.assertEqual(digest(suffix.encode()), SUFFIX_SHA)
        self.assertTrue(self.workflow.startswith(prefix))
        self.assertTrue(self.workflow.endswith(suffix), "Existing actual/control/lifecycle commands stay fixed")
        self.assertEqual(literal(ast.parse(self.decoder), "HELPER_MANIFEST"), self.helper_manifest,
                         "Actual generated decoder must retain the derived trusted helper identity")
        expected = {"preflight.py", *HELPERS} | {f"fixtures/{name}" for name in FIXTURES}
        self.assertEqual({name for name, _, _ in self.manifest}, expected)
        self.assertEqual(len(self.manifest), len(expected))
        for name, size, sha256, _ in self.helper_manifest:
            raw = dict(self.contents)[name]
            self.assertEqual(raw, (HERE / name).read_bytes())
            self.assertEqual((len(raw), digest(raw)), (size, sha256))
        self.assertLessEqual(sum(size for _, size, _ in self.manifest), SOURCE_CAP)
        root, result = self.extract()
        self.assertEqual(result[0], 0, f"Actual extraction failed: {result!r}")
        self.assertEqual({path.name for path in root.iterdir()}, {"preflight.py", "fixtures", *HELPERS})
        for name, identity in FIXTURES.items():
            raw = (root / "fixtures" / name).read_bytes()
            self.assertEqual((len(raw), digest(raw)), identity)
        extracted_source = (root / "preflight.py").read_text()
        extracted = ast.parse(extracted_source)
        original_owners = [(node.name, ast.dump(node)) for node in self.original_driver.body
                           if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in ORIGINAL_OWNERS]
        extracted_owners = [(node.name, ast.dump(node)) for node in extracted.body
                            if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in ORIGINAL_OWNERS]
        self.assertEqual(extracted_owners, original_owners,
                         "Packaging cannot replace original policy/transport/lifetime owners")
        self.assertEqual(tuple(name for name, _ in extracted_owners), ORIGINAL_OWNERS)
        lines = extracted_source.splitlines(keepends=True)
        owner_sources = [(node.name, "".join(lines[
            min([node.lineno] + [item.lineno for item in node.decorator_list]) - 1:node.end_lineno]))
            for node in extracted.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))
            and node.name in ORIGINAL_OWNERS]
        self.assertEqual(digest(json.dumps(owner_sources, separators=(",", ":")).encode()), OWNER_SOURCE_SHA,
                         "All existing driver owners, including the 18-position schedule, are frozen")
        constants = [(target.id, ast.get_source_segment(extracted_source, node.value)) for node in extracted.body
                     if isinstance(node, ast.Assign) for target in node.targets
                     if isinstance(target, ast.Name) and target.id in
                     ("P", "I", "C", "M", "MODULES", "RELEASE", "FIXTURE_HASHES")]
        self.assertEqual(digest(json.dumps(constants, separators=(",", ":")).encode()), CONSTANT_SOURCE_SHA,
                         "Original P/module/release/fixture authority cannot change")

    def test_ambient_same_name_poison_cannot_supply_missing_or_valid_helper(self):
        root, result = self.extract()
        self.assertEqual(result[0], 0, f"Actual extraction failed: {result!r}")
        self.assert_loaded(self.inspect_child(root, poison=True), root)
        self.require_delivered_helper()
        for name in HELPERS:
            with self.subTest(helper=name):
                root, result = self.extract()
                self.assertEqual(result[0], 0, f"Actual extraction failed: {result!r}")
                (root / name).unlink()
                value = self.inspect_child(root, poison=True)
                self.assertEqual(value["state"], "REFUSED", "Ambient module cannot replace absent verified helper")
                self.assertEqual(value["helper_execution_count"], 0)
                self.assertTrue(value["path_unchanged"])

    def test_extracted_loader_refuses_each_helper_change_before_execution(self):
        self.require_delivered_helper()
        cases = ((entry, mutation) for entry in self.helper_manifest for mutation in
                 ("missing", "renamed", "extra", "length", "sha256", "symlink", "directory", "preloaded"))
        for (name, size, _, _), mutation in cases:
            with self.subTest(helper=name, mutation=mutation):
                root, result = self.extract()
                self.assertEqual(result[0], 0, f"Valid extraction failed: {result!r}")
                self.assert_loaded(self.inspect_child(root), root)
                helper = root / name
                sentinel = root.parent / "helper-executed"
                poison = f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('executed')\n".encode()
                poison += b" " * (size - len(poison))
                action = "inspect"
                if mutation == "missing":
                    helper.unlink()
                elif mutation == "renamed":
                    helper.rename(root / "renamed.py")
                elif mutation == "extra":
                    (root / "extra.py").write_bytes(poison)
                elif mutation == "length":
                    helper.write_bytes(helper.read_bytes()[:-1])
                elif mutation == "sha256":
                    helper.write_bytes(poison)
                elif mutation == "symlink":
                    target = root.parent / "poison.py"
                    target.write_bytes(poison)
                    helper.unlink()
                    helper.symlink_to(target)
                elif mutation == "directory":
                    helper.unlink()
                    helper.mkdir()
                elif mutation == "preloaded":
                    action = "preloaded-" + name
                value = self.inspect_child(root, action)
                self.assertEqual(value["state"], "REFUSED", "NEW_LOADER_UNAVAILABLE is never a guard refusal")
                self.assertEqual(value["helper_execution_count"], 0)
                self.assertTrue(value["path_unchanged"])
                self.assertFalse(sentinel.exists(), "Unverified helper executed before refusal")

    def test_actual_decoder_rejects_coherent_untrusted_helper_metadata_and_source_cap(self):
        self.require_delivered_helper()
        root, valid = self.extract()
        self.assertEqual(valid[0], 0, f"Valid actual extraction failed: {valid!r}")
        self.assert_loaded(self.inspect_child(root), root)
        cases = ((entry, mutation) for entry in self.helper_manifest for mutation in
                 ("missing", "extra", "renamed", "altered", "length", "sha256", "self-rehashed", "source-cap", "fixture"))
        for (name, size, sha256, _), mutation in cases:
            with self.subTest(helper=name, mutation=mutation):
                marker_owner = self.location("payload-marker")
                sentinel = marker_owner / "helper-executed"
                poison = f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('executed')\n".encode()
                poison += b" " * (size - len(poison))
                contents, manifest = list(self.contents), list(self.manifest)
                index = next(i for i, entry in enumerate(manifest) if entry[0] == name)
                if mutation == "missing":
                    del contents[index]
                    del manifest[index]
                elif mutation == "extra":
                    contents.append(("extra.py", poison))
                    manifest.append(("extra.py", len(poison), digest(poison)))
                elif mutation == "renamed":
                    contents[index] = ("renamed.py", contents[index][1])
                    manifest[index] = ("renamed.py", size, sha256)
                elif mutation == "altered":
                    contents[index] = (name, poison)
                elif mutation == "length":
                    manifest[index] = (name, size + 1, sha256)
                elif mutation == "sha256":
                    manifest[index] = (name, size, "0" * 64)
                elif mutation == "self-rehashed":
                    contents[index] = (name, poison)
                    manifest[index] = (name, len(poison), digest(poison))
                elif mutation == "source-cap":
                    driver_index = next(i for i, entry in enumerate(manifest) if entry[0] == "preflight.py")
                    changed = contents[driver_index][1] + b" " * (SOURCE_CAP + 1)
                    contents[driver_index] = ("preflight.py", changed)
                    manifest[driver_index] = ("preflight.py", len(changed), digest(changed))
                elif mutation == "fixture":
                    fixture_index = next(i for i, entry in enumerate(manifest) if entry[0] == "fixtures/main.json")
                    old = contents[fixture_index][1]
                    contents[fixture_index] = ("fixtures/main.json", bytes([old[0] ^ 1]) + old[1:])
                decoder, transport = perturbed_decoder(self.decoder, manifest, contents)
                original_tree, changed_tree = ast.parse(self.decoder), ast.parse(decoder)
                self.assertEqual(literal(changed_tree, "HELPER_MANIFEST"), literal(original_tree, "HELPER_MANIFEST"),
                                 "Payload perturbation cannot alter trusted helper authority")
                self.assertIn("256 * 1024", ast.unparse(changed_tree), "Decoded-source cap must stay unchanged")
                _, rejected = self.extract(decoder, transport)
                self.assertNotEqual(rejected[0], 0, f"Actual decoder accepted {mutation}")
                self.assertEqual(rejected[1], b"", "Decoder refusal must not execute helper output")
                self.assertFalse(sentinel.exists(), "Untrusted helper executed during extraction")

    def test_builder_checks_fixed_helper_identity_before_packaging(self):
        self.require_delivered_helper()
        cases = ((entry, mutation) for entry in self.helper_manifest
                 for mutation in ("missing", "renamed", "length", "sha256"))
        for (name, size, _, _), mutation in cases:
            with self.subTest(helper=name, mutation=mutation):
                owner = self.location("builder-negative")
                source = owner / "source"
                shutil.copytree(self.source, source)
                (source / "native-materialization-preflight.yml").unlink()
                helper = source / name
                if mutation == "missing":
                    helper.unlink()
                elif mutation == "renamed":
                    helper.rename(source / "renamed.py")
                elif mutation == "length":
                    helper.write_bytes(helper.read_bytes()[:-1])
                elif mutation == "sha256":
                    sentinel = owner / "helper-executed"
                    poison = f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('executed')\n".encode()
                    helper.write_bytes(poison + b" " * (size - len(poison)))
                result = launch(source / "build.py", owner / "child")
                self.assertNotEqual(result[0], 0, f"Actual builder accepted untrusted helper {mutation}")
                self.assertFalse((owner / "helper-executed").exists(), "Builder executed unverified helper")
                self.assertFalse((source / "native-materialization-preflight.yml").exists(),
                                 "Rejected source cannot produce a new workflow")


if __name__ == "__main__":
    unittest.main(verbosity=2)
