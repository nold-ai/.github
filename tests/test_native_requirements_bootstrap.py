from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from copy import deepcopy
from dataclasses import FrozenInstanceError, asdict
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType

import pytest


ROOT = Path(__file__).resolve().parents[1]
CALLER, POLICY, RUN_ID = "1" * 40, "2" * 40, 540001
NOW = datetime(2026, 10, 26, 12, tzinfo=UTC)
EXPIRY = datetime(2026, 11, 4, 23, tzinfo=UTC)
FIXED = {
    "repository": "nold-ai/specfact-cli", "repository_id": 1085706003,
    "policy_repository": "nold-ai/.github", "policy_repository_id": 1110267669,
    "owner_id": 225190663, "pull_request": 786, "base_ref": "dev",
    "head_branch": "codex/security-dependencies-0-55-11-dev",
    "proof_base": "9b5ad1e78430cc0b061cb16de42f73de96f4f312",
    "main_commit": "5262efb0881e4fac7697d629b0530250342bc656",
    "red_commit": "4ae6175a4d337296d0347e73b66c9da1f0e43f7f",
    "red_tree": "baeb88acf0d2a5015810ad12dbfccfa7fdf9a21e",
    "module_commit": "69f075819be5e1ceca1446b026b0417f19e584ca",
    "module_tree": "5d0b8e66c6cd467e6b1ad9d582e24c66b907e205",
    "mapping_sha256": "7025a000601cc44c1a1e6168367f2188681471d68ea5f044cfc81a94b734f8ff",
    "plan_sha256": "dc90453d191b282ba5e47127bf067ee23b475072d7e94a0859c7c6a26677ce3a",
    "operator_login": "djm81", "operator_id": 39115308, "expires_at": EXPIRY,
}
CALLER_BYTES = (
    "name: Native Requirements RED\non:\n  workflow_dispatch:\npermissions:\n"
    "  contents: read\n  actions: read\njobs:\n  native-red:\n"
    f"    uses: nold-ai/.github/.github/workflows/native-requirements-bootstrap.yml@{POLICY}\n"
    f"    with:\n      red_commit: {FIXED['red_commit']}\n"
).encode()
FILENAMES = ("build-locked.txt", "build-requirements.in", "locked.txt", "requirements.in")
MISSING = object()


@pytest.fixture(scope="module")
def bootstrap() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "native_requirements_bootstrap", ROOT / ".github/scripts/native_requirements_bootstrap.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _repository(policy: bool = False) -> dict:
    return {
        "id": 1110267669 if policy else 1085706003,
        "name": ".github" if policy else "specfact-cli",
        "full_name": "nold-ai/.github" if policy else "nold-ai/specfact-cli",
        "owner": {"login": "nold-ai", "id": 225190663, "type": "Organization"},
        "default_branch": "main", "description": "Unrestricted API extra field",
    }


def _snapshot() -> dict:
    actor = {"login": "djm81", "id": 39115308, "type": "User"}
    return {
        "runtime": {
            "GITHUB_ACTIONS": "true", "event_name": "workflow_dispatch",
            "repository": "nold-ai/specfact-cli", "repository_id": "1085706003",
            "repository_owner": "nold-ai", "repository_owner_id": "225190663",
            "sha": CALLER, "ref": "refs/heads/codex/security-dev-native-red",
            "workflow_ref": "nold-ai/specfact-cli/.github/workflows/specfact.yml@refs/heads/codex/security-dev-native-red",
            "workflow_sha": CALLER,
            "run_id": str(RUN_ID), "run_attempt": "1",
            "actor": "djm81", "actor_id": "39115308", "triggering_actor": "djm81",
        },
        "repository": _repository(), "policy_repository": _repository(True),
        "pull_request": {
            "number": 786, "state": "open", "merged": False, "merged_at": None,
            "base": {"ref": "dev", "sha": FIXED["proof_base"], "repo": _repository()},
            "head": {"ref": FIXED["head_branch"], "sha": FIXED["red_commit"], "repo": _repository()},
        },
        "red_commit": {
            "sha": FIXED["red_commit"], "tree": {"sha": FIXED["red_tree"]},
            "parents": [{"sha": FIXED["proof_base"]}],
            "verification": {"verified": True, "reason": "valid", "signature": "synthetic signature", "payload": "synthetic payload"},
        },
        "dev_ref": {"ref": "refs/heads/dev", "object": {"type": "commit", "sha": FIXED["proof_base"]}},
        "main_ref": {"ref": "refs/heads/main", "object": {"type": "commit", "sha": FIXED["main_commit"]}},
        "caller_run": {
            "id": RUN_ID, "run_attempt": 1, "path": ".github/workflows/specfact.yml",
            "event": "workflow_dispatch", "head_branch": "codex/security-dev-native-red",
            "head_sha": CALLER, "status": "in_progress", "repository": _repository(),
            "head_repository": _repository(), "actor": actor, "triggering_actor": deepcopy(actor),
        },
        "caller_workflow_bytes": CALLER_BYTES,
        "policy_compare": {"base_commit": {"sha": POLICY}, "merge_base_commit": {"sha": POLICY}, "status": "ahead"},
        "actor_permission": {"permission": "write", "user": deepcopy(actor)},
    }


def _edit(snapshot: dict, path: str, value: object = MISSING) -> None:
    parts = path.split("/")
    parent = snapshot
    for key in parts[:-1]:
        parent = parent[int(key)] if isinstance(parent, list) else parent[key]
    key = int(parts[-1]) if isinstance(parent, list) else parts[-1]
    if value is MISSING:
        del parent[key]
    else:
        parent[key] = value


@pytest.mark.parametrize("run_path", [
    ".github/workflows/specfact.yml",
    ".github/workflows/specfact.yml@codex/security-dev-native-red",
    ".github/workflows/specfact.yml@refs/heads/codex/security-dev-native-red",
])
@pytest.mark.parametrize("permission,status", [("write", "ahead"), ("admin", "identical")])
def test_exact_context_returns_frozen_subject_and_source_roles(bootstrap, permission, status, run_path):
    snapshot = _snapshot()
    snapshot["caller_run"]["path"] = run_path
    snapshot["actor_permission"]["permission"] = permission
    snapshot["policy_compare"]["status"] = status
    for key in set(snapshot) - {"runtime", "caller_workflow_bytes"}:
        snapshot[key]["future_api_field"] = {"unrestricted": True}
    receipt = bootstrap.authorize_red_context(POLICY, snapshot, NOW)
    assert asdict(receipt) == FIXED | {
        "caller_commit": CALLER, "policy_commit": POLICY, "run_id": RUN_ID, "run_attempt": 1,
    }
    with pytest.raises(FrozenInstanceError):
        receipt.red_commit = CALLER


REPOSITORY_PATHS = (
    "repository", "policy_repository", "pull_request/base/repo",
    "pull_request/head/repo", "caller_run/repository", "caller_run/head_repository",
)
ACTOR_PATHS = ("caller_run/actor", "caller_run/triggering_actor", "actor_permission/user")
API_INTEGER_IDENTITIES = [
    ("pull_request/number", 786), ("caller_run/id", RUN_ID), ("caller_run/run_attempt", 1),
] + [
    (f"{prefix}/id", 1110267669 if prefix == "policy_repository" else 1085706003)
    for prefix in REPOSITORY_PATHS
] + [(f"{prefix}/owner/id", 225190663) for prefix in REPOSITORY_PATHS] + [
    (f"{prefix}/id", 39115308) for prefix in ACTOR_PATHS
]


MUTATIONS = [
    ("runtime/GITHUB_ACTIONS", "false"), ("runtime/event_name", "pull_request"),
    ("runtime/repository", "elsewhere/specfact-cli"), ("runtime/repository_id", "01085706003"),
    ("runtime/repository_owner", "elsewhere"), ("runtime/repository_owner_id", "1"),
    ("runtime/sha", FIXED["red_commit"]), ("runtime/ref", "refs/heads/dev"),
    ("runtime/workflow_ref", "nold-ai/specfact-cli/.github/workflows/other.yml@refs/heads/codex/security-dev-native-red"),
    ("runtime/workflow_sha", FIXED["proof_base"]), ("runtime/run_id", "540002"),
    ("runtime/run_attempt", "2"), ("runtime/run_attempt", 1),
    ("runtime/actor", "other"), ("runtime/actor_id", "1"), ("runtime/triggering_actor", "other"),
    ("policy_repository/default_branch", "dev"),
    ("pull_request/number", 785), ("pull_request/number", True),
    ("pull_request/state", "closed"), ("pull_request/merged", True), ("pull_request/merged", 0),
    ("pull_request/merged_at", "2026-10-26T00:00:00Z"), ("pull_request/base/ref", "main"),
    ("pull_request/base/sha", CALLER), ("pull_request/head/ref", "other"), ("pull_request/head/sha", CALLER),
    ("red_commit/sha", CALLER), ("red_commit/tree/sha", CALLER),
    ("red_commit/parents", []), ("red_commit/parents", [{"sha": FIXED["proof_base"]}] * 2),
    ("red_commit/parents/0/sha", CALLER), ("red_commit/verification/verified", False),
    ("red_commit/verification/verified", 1), ("red_commit/verification/reason", "unsigned"),
    ("red_commit/verification/signature", " "), ("red_commit/verification/payload", ""),
    ("dev_ref/ref", "refs/heads/main"), ("dev_ref/object/sha", CALLER), ("dev_ref/object/type", "tag"),
    ("main_ref/ref", "refs/heads/dev"), ("main_ref/object/sha", CALLER), ("main_ref/object/type", "tag"),
    ("caller_run/id", True),
    ("caller_run/run_attempt", 2), ("caller_run/run_attempt", True), ("caller_run/path", ".github/workflows/other.yml"),
    ("caller_run/event", "pull_request"), ("caller_run/head_branch", FIXED["head_branch"]),
    ("caller_run/head_sha", FIXED["red_commit"]), ("caller_run/status", "completed"),
    ("policy_compare/base_commit/sha", CALLER), ("policy_compare/merge_base_commit/sha", CALLER),
    ("policy_compare/status", "behind"), ("policy_compare/status", "diverged"),
    ("actor_permission/permission", "read"), ("actor_permission/permission", "maintain"),
    ("caller_workflow_bytes", CALLER_BYTES.decode()),
    ("pull_request/base", None), ("pull_request/head", []), ("red_commit/tree", []),
    ("red_commit/parents", [None]), ("red_commit/verification", None),
    ("dev_ref/object", None), ("main_ref/object", []),
    ("caller_run/actor", None), ("caller_run/triggering_actor", []),
    ("policy_compare/base_commit", None), ("policy_compare/merge_base_commit", []),
    ("actor_permission/user", None),
] + [
    (f"{prefix}/{field}", value)
    for prefix in REPOSITORY_PATHS
    for field, value in (("id", True), ("id", 1), ("name", "wrong"), ("full_name", "foreign/repo"), ("owner/login", "foreign"), ("owner/id", True), ("owner/type", "User"))
] + [
    (f"{prefix}/{field}", value)
    for prefix in ACTOR_PATHS
    for field, value in (("login", "other"), ("id", 1), ("id", True), ("type", "Bot"))
] + [(path, variant) for path, value in API_INTEGER_IDENTITIES for variant in (float(value), str(value))] + [
    (f"{prefix}/owner", value)
    for prefix in REPOSITORY_PATHS for value in (None, [], "nold-ai", 225190663)
] + [
    (f"red_commit/verification/{field}", value)
    for field in ("signature", "payload") for value in (None, True, 1, [], {}, b"synthetic")
] + [("caller_run/path", value) for value in (
    ".github/workflows/specfact.yml@main", ".github/workflows/specfact.yml@refs/heads/main",
    ".github/workflows/specfact.yml@other", ".github/workflows/specfact.yml@refs/heads/other",
    ".github/workflows/specfact.yml@", ".github/workflows/specfact.yml@@codex/security-dev-native-red",
    ".github/workflows/specfact.yml@codex/security-dev-native-red@main",
    ".github/workflows/specfact.yml@refs/heads/codex/security-dev-native-red@main",
    ".github/workflows/specfact.yml@heads/codex/security-dev-native-red",
    ".github/workflows/other.yml@codex/security-dev-native-red",
)] + [("caller_workflow_bytes", value) for value in (
    CALLER_BYTES.replace(POLICY.encode(), b"main"), CALLER_BYTES.replace(FIXED["red_commit"].encode(), CALLER.encode()),
    CALLER_BYTES.replace(b"actions: read", b"actions: write"), CALLER_BYTES + b"    secrets: inherit\n",
    CALLER_BYTES + b"    environment: production\n", CALLER_BYTES + b"    steps: []\n",
    CALLER_BYTES + b"  extra:\n    runs-on: ubuntu-latest\n    steps: []\n", CALLER_BYTES.replace(b"\n", b"\r\n"),
)]


@pytest.mark.parametrize("path,value", MUTATIONS, ids=[path for path, _ in MUTATIONS])
def test_changed_context_refuses(bootstrap, path, value):
    snapshot = _snapshot()
    _edit(snapshot, path, value)
    with pytest.raises(ValueError, match="native bootstrap rejected"):
        bootstrap.authorize_red_context(POLICY, snapshot, NOW)


@pytest.mark.parametrize("path", sorted({path for path, _ in MUTATIONS} | set(_snapshot())))
def test_missing_context_fields_refuse(bootstrap, path):
    snapshot = _snapshot()
    _edit(snapshot, path)
    with pytest.raises(ValueError, match="native bootstrap rejected"):
        bootstrap.authorize_red_context(POLICY, snapshot, NOW)


@pytest.mark.parametrize("key", list(_snapshot()) + ["unexpected"])
def test_malformed_context_objects_or_unknown_top_level_refuse(bootstrap, key):
    snapshot = _snapshot()
    snapshot[key] = None
    with pytest.raises(ValueError, match="native bootstrap rejected"):
        bootstrap.authorize_red_context(POLICY, snapshot, NOW)


@pytest.mark.parametrize("snapshot", [None, [], "context"])
def test_nonmapping_snapshot_refuses(bootstrap, snapshot):
    with pytest.raises(ValueError, match="native bootstrap rejected"):
        bootstrap.authorize_red_context(POLICY, snapshot, NOW)


@pytest.mark.parametrize("key,value", [
    ("deployed", True),
    ("job_workflow_ref", f"nold-ai/.github/.github/workflows/native-requirements-bootstrap.yml@{POLICY}"),
    ("job_workflow_sha", POLICY),
])
def test_unknown_runtime_field_refuses(bootstrap, key, value):
    snapshot = _snapshot()
    snapshot["runtime"][key] = value
    with pytest.raises(ValueError, match="native bootstrap rejected"):
        bootstrap.authorize_red_context(POLICY, snapshot, NOW)


@pytest.mark.parametrize("value", [None, True, "main", "A" * 40, "g" * 40, "2" * 39, "2" * 41, "3" * 40])
def test_policy_sha_must_be_full_canonical_and_match_selected_declaration(bootstrap, value):
    with pytest.raises(ValueError, match="native bootstrap rejected"):
        bootstrap.authorize_red_context(value, _snapshot(), NOW)


@pytest.mark.parametrize("role,target", [("caller", "policy"), ("caller", "proof_base"), ("caller", "red_commit"), ("policy", "proof_base"), ("policy", "red_commit")])
def test_consistently_swapped_source_roles_refuse(bootstrap, role, target):
    snapshot = _snapshot()
    replacement = POLICY if target == "policy" else FIXED[target]
    if role == "caller":
        for path in ("runtime/sha", "runtime/workflow_sha", "caller_run/head_sha"):
            _edit(snapshot, path, replacement)
        expected = POLICY
    else:
        for path in ("policy_compare/base_commit/sha", "policy_compare/merge_base_commit/sha"):
            _edit(snapshot, path, replacement)
        snapshot["caller_workflow_bytes"] = CALLER_BYTES.replace(POLICY.encode(), replacement.encode())
        expected = replacement
    with pytest.raises(ValueError, match="native bootstrap rejected"):
        bootstrap.authorize_red_context(expected, snapshot, NOW)


@pytest.mark.parametrize("policy", ["", "main", "A" * 40, "g" * 40, "2" * 39, "2" * 41])
def test_consistently_malformed_policy_sha_refuses(bootstrap, policy):
    snapshot = _snapshot()
    for path in ("policy_compare/base_commit/sha", "policy_compare/merge_base_commit/sha"):
        _edit(snapshot, path, policy)
    snapshot["caller_workflow_bytes"] = CALLER_BYTES.replace(POLICY.encode(), policy.encode())
    with pytest.raises(ValueError, match="native bootstrap rejected"):
        bootstrap.authorize_red_context(policy, snapshot, NOW)


@pytest.mark.parametrize("caller", ["A" * 40, "g" * 40, "1" * 39, "1" * 41])
def test_consistently_malformed_caller_sha_refuses(bootstrap, caller):
    snapshot = _snapshot()
    for path in ("runtime/sha", "runtime/workflow_sha", "caller_run/head_sha"):
        _edit(snapshot, path, caller)
    with pytest.raises(ValueError, match="native bootstrap rejected"):
        bootstrap.authorize_red_context(POLICY, snapshot, NOW)


@pytest.mark.parametrize("run_id,encoded", [(0, "0"), (-1, "-1"), (RUN_ID, "0540001")])
def test_run_id_requires_canonical_positive_identity(bootstrap, run_id, encoded):
    snapshot = _snapshot()
    snapshot["caller_run"]["id"], snapshot["runtime"]["run_id"] = run_id, encoded
    with pytest.raises(ValueError, match="native bootstrap rejected"):
        bootstrap.authorize_red_context(POLICY, snapshot, NOW)


@pytest.mark.parametrize("now", [
    None, True, 1, 0.0, "2026-10-26T12:00:00Z", [], {},
    NOW.replace(tzinfo=None), EXPIRY, EXPIRY + timedelta(microseconds=1),
])
def test_wrong_type_naive_or_expired_clock_refuses(bootstrap, now):
    with pytest.raises(ValueError, match="native bootstrap rejected"):
        bootstrap.authorize_red_context(POLICY, _snapshot(), now)


def test_equivalent_timezone_and_last_valid_instant_accept(bootstrap):
    for now in (NOW.astimezone(timezone(timedelta(hours=1))), EXPIRY - timedelta(microseconds=1)):
        assert bootstrap.authorize_red_context(POLICY, _snapshot(), now).expires_at == EXPIRY


def _toolset(tmp_path):
    directory = tmp_path / "tools"
    directory.mkdir()
    digests = {}
    for name in FILENAMES:
        data = (name + "\n").encode()
        (directory / name).write_bytes(data)
        digests[name] = hashlib.sha256(data).hexdigest()
    (directory / "tool-files.json").write_text(json.dumps({"schema_version": 1, "files": digests}), encoding="utf-8")
    return directory, digests


def test_exact_tool_bytes_return_frozen_manifest_and_sorted_digests(bootstrap, tmp_path):
    directory, digests = _toolset(tmp_path)
    expected = hashlib.sha256((directory / "tool-files.json").read_bytes()).hexdigest()
    receipt = bootstrap.verify_tool_files(directory, expected)
    assert asdict(receipt) == {"directory": directory.resolve(), "manifest_sha256": expected, "file_sha256": tuple(sorted(digests.items()))}
    with pytest.raises(FrozenInstanceError):
        receipt.manifest_sha256 = "0" * 64
    with pytest.raises(TypeError):
        receipt.file_sha256[0] = ("other", "0" * 64)


FILE_BOUNDARY_CHILD = """
import importlib.util
import os
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("native_requirements_bootstrap", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
unopened = os.path.abspath(sys.argv[4]) if sys.argv[4] else None
attempted = []

def refuse_open(event, args):
    if unopened is not None and event == "open" and isinstance(args[0], (str, bytes)):
        if os.path.basename(os.fsdecode(args[0])) == os.path.basename(unopened):
            attempted.append(args[0])
            raise AssertionError("oversized file was opened")

sys.addaudithook(refuse_open)
try:
    module.verify_tool_files(Path(sys.argv[2]), sys.argv[3])
except ValueError as error:
    assert str(error).startswith("tool files rejected"), str(error)
    assert not attempted, "oversized file was opened before refusal"
    print("refused")
else:
    raise AssertionError("invalid tool files accepted")
"""


def _assert_file_boundary_refuses_in_child(directory, expected, unopened=None):
    arguments = [
        sys.executable, "-c", FILE_BOUNDARY_CHILD,
        str(ROOT / ".github/scripts/native_requirements_bootstrap.py"),
        str(directory), expected, str(unopened) if unopened is not None else "",
    ]
    try:
        result = subprocess.run(arguments, capture_output=True, text=True, timeout=5, check=False)
    except subprocess.TimeoutExpired:
        pytest.fail("file verification blocked; child was terminated", pytrace=False)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "refused\n"


@pytest.mark.parametrize("name", ["tool-files.json", "locked.txt"])
def test_no_writer_fifo_refuses_without_blocking(tmp_path, name):
    directory, _ = _toolset(tmp_path)
    expected = hashlib.sha256((directory / "tool-files.json").read_bytes()).hexdigest()
    path = directory / name
    path.unlink()
    os.mkfifo(path)
    _assert_file_boundary_refuses_in_child(directory, expected)


@pytest.mark.parametrize("name", ["tool-files.json", "requirements.in"])
def test_oversized_regular_file_refuses_before_open(tmp_path, name):
    directory, digests = _toolset(tmp_path)
    manifest = directory / "tool-files.json"
    path = directory / name
    if name == "tool-files.json":
        raw = manifest.read_bytes()
        raw += b" " * (16385 - len(raw))
    else:
        data = b"x" * 4194305
        path.write_bytes(data)
        digests[name] = hashlib.sha256(data).hexdigest()
        raw = json.dumps({"schema_version": 1, "files": digests}).encode()
    manifest.write_bytes(raw)
    _assert_file_boundary_refuses_in_child(directory, hashlib.sha256(raw).hexdigest(), path)


@pytest.mark.parametrize("name,kind,value", [
    ("tool-files.json", "missing", None), ("locked.txt", "missing", None),
    ("tool-files.json", "symlink", None), ("locked.txt", "symlink", None),
    ("tool-files.json", "directory", None), ("locked.txt", "directory", None),
    ("extra.txt", "write", b"extra"), ("nested", "directory", None),
    ("tool-files.json", "write", b""), ("requirements.in", "write", b""),
    ("tool-files.json", "write", b" " * 16385), ("build-locked.txt", "write", b"x" * 4194305),
    ("locked.txt", "write", b"changed"), ("tool-files.json", "write", b"{"),
    ("tool-files.json", "write", b"\xff"),
])
def test_missing_nonregular_extra_empty_oversized_or_changed_files_refuse(bootstrap, tmp_path, name, kind, value):
    directory, _ = _toolset(tmp_path)
    path = directory / name
    if kind in {"missing", "symlink", "directory"} and path.exists():
        data = path.read_bytes()
        path.unlink()
    if kind == "symlink":
        target = tmp_path / "outside"
        target.write_bytes(data)
        path.symlink_to(target)
    elif kind == "directory":
        path.mkdir()
    elif kind == "write":
        path.write_bytes(value)
    manifest = directory / "tool-files.json"
    expected = hashlib.sha256(manifest.read_bytes()).hexdigest() if manifest.is_file() else "0" * 64
    with pytest.raises(ValueError, match="tool files rejected"):
        bootstrap.verify_tool_files(directory, expected)


@pytest.mark.parametrize("case", ["schema-bool", "schema-version", "schema-string", "schema-float", "unknown-key", "missing-schema", "missing-files", "files-list", "root-list", "duplicate-top", "duplicate-file", "traversal", "absolute", "missing-file", "extra-file", "bad-digest", "short-digest", "nonhex-digest", "boolean-digest"])
def test_authenticated_manifest_schema_refuses_ambiguous_or_unbounded_names(bootstrap, tmp_path, case):
    directory, digests = _toolset(tmp_path)
    manifest = {"schema_version": 1, "files": digests}
    if case == "schema-bool": manifest["schema_version"] = True
    elif case == "schema-version": manifest["schema_version"] = 2
    elif case == "schema-string": manifest["schema_version"] = "1"
    elif case == "schema-float": manifest["schema_version"] = 1.0
    elif case == "unknown-key": manifest["deployed"] = True
    elif case == "missing-schema": del manifest["schema_version"]
    elif case == "missing-files": del manifest["files"]
    elif case == "files-list": manifest["files"] = list(digests)
    elif case == "root-list": manifest = []
    elif case == "missing-file": del digests["locked.txt"]
    elif case in {"traversal", "absolute", "extra-file"}: digests[{"traversal": "../locked.txt", "absolute": "/locked.txt", "extra-file": "extra.txt"}[case]] = "0" * 64
    elif case == "bad-digest": digests["locked.txt"] = "A" * 64
    elif case == "short-digest": digests["locked.txt"] = "a" * 63
    elif case == "nonhex-digest": digests["locked.txt"] = "g" * 64
    elif case == "boolean-digest": digests["locked.txt"] = True
    raw = json.dumps(manifest).encode()
    if case == "duplicate-top": raw = raw[:-1] + b', "schema_version": 1}'
    if case == "duplicate-file": raw = raw.replace(b'"files": {', b'"files": {"locked.txt": "' + digests["locked.txt"].encode() + b'", ')
    (directory / "tool-files.json").write_bytes(raw)
    with pytest.raises(ValueError, match="tool files rejected"):
        bootstrap.verify_tool_files(directory, hashlib.sha256(raw).hexdigest())


def test_raw_digest_refusal_precedes_json_interpretation(bootstrap, tmp_path):
    directory, _ = _toolset(tmp_path)
    (directory / "tool-files.json").write_bytes(b"\xff")
    with pytest.raises(ValueError, match="tool files rejected: manifest digest mismatch"):
        bootstrap.verify_tool_files(directory, "0" * 64)


def test_inclusive_input_and_manifest_size_limits_accept(bootstrap, tmp_path):
    directory, digests = _toolset(tmp_path)
    data = b"x" * 4194304
    (directory / "requirements.in").write_bytes(data)
    digests["requirements.in"] = hashlib.sha256(data).hexdigest()
    raw = json.dumps({"schema_version": 1, "files": digests}).encode()
    raw += b" " * (16384 - len(raw))
    (directory / "tool-files.json").write_bytes(raw)
    receipt = bootstrap.verify_tool_files(directory, hashlib.sha256(raw).hexdigest())
    assert receipt.file_sha256 == tuple(sorted(digests.items()))


@pytest.mark.parametrize("digest", ["0" * 64, "A" * 64, "g" * 64, "0" * 63, True, None])
def test_independent_raw_manifest_digest_is_required(bootstrap, tmp_path, digest):
    directory, _ = _toolset(tmp_path)
    with pytest.raises(ValueError, match="tool files rejected"):
        bootstrap.verify_tool_files(directory, digest)


@pytest.mark.parametrize("kind", ["missing", "file", "symlink"])
def test_tool_directory_must_be_an_existing_nonsymlink_directory(bootstrap, tmp_path, kind):
    directory, _ = _toolset(tmp_path)
    alias = tmp_path / "alias"
    if kind == "file": alias.write_bytes(b"file")
    if kind == "symlink": alias.symlink_to(directory, target_is_directory=True)
    expected = hashlib.sha256((directory / "tool-files.json").read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="tool files rejected"):
        bootstrap.verify_tool_files(alias, expected)
