from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
from copy import deepcopy
from dataclasses import FrozenInstanceError, asdict
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
I, P, E = "3" * 40, "2" * 40, "1" * 40
RUN = 540001
NOW = datetime(2026, 10, 26, 12, tzinfo=UTC)
EXPIRY = datetime(2026, 11, 4, 23, tzinfo=UTC)
CORE = "/repos/nold-ai/specfact-cli"
POLICY = "/repos/nold-ai/.github"
MAIN = POLICY + "/git/ref/heads/main"
INDEX_PATH = ".github/native-releases/dev786.json"
CALLER_PATH = ".github/workflows/specfact.yml"
INDEX_GET = f"{POLICY}/contents/{INDEX_PATH}?ref={I}"
CALLER_GET = f"{CORE}/contents/{CALLER_PATH}?ref={E}"
COMPARE = f"{POLICY}/compare/{P}...{I}"
MANIFEST = "969cabb52fc6db85de46967f62ffe4f0f9b0ca50a80b5a3e46255a89b51f78ad"
DESCRIPTOR = "a" * 64
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
    f"    uses: nold-ai/.github/.github/workflows/native-requirements-bootstrap.yml@{P}\n"
    f"    with:\n      red_commit: {FIXED['red_commit']}\n"
).encode()
INDEX = {
    "schema_version": 1, "scope_id": "security-dependencies-0-55-11-dev",
    "policy_commit": P, "tool_manifest_sha256": MANIFEST,
    "runtime_descriptor_sha256": DESCRIPTOR, "expires_at": "2026-11-04T23:00:00Z",
}


def _load(name, monkeypatch):
    spec = importlib.util.spec_from_file_location(name, ROOT / f".github/scripts/{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def modules(monkeypatch):
    bootstrap = _load("native_requirements_bootstrap", monkeypatch)
    transport = _load("late_cycle_admission", monkeypatch)
    acquisition = _load("native_requirements_acquisition", monkeypatch)
    return SimpleNamespace(bootstrap=bootstrap, acquisition=acquisition, transport=transport)


def _repository(policy=False):
    return {
        "id": 1110267669 if policy else 1085706003,
        "name": ".github" if policy else "specfact-cli",
        "full_name": "nold-ai/.github" if policy else "nold-ai/specfact-cli",
        "owner": {"login": "nold-ai", "id": 225190663, "type": "Organization"},
        "default_branch": "main", "future_field": {"permitted": True},
    }


def _runtime():
    return {
        "GITHUB_ACTIONS": "true", "event_name": "workflow_dispatch",
        "repository": "nold-ai/specfact-cli", "repository_id": "1085706003",
        "repository_owner": "nold-ai", "repository_owner_id": "225190663",
        "sha": E, "workflow_sha": E, "ref": "refs/heads/codex/security-dev-native-red",
        "workflow_ref": "nold-ai/specfact-cli/.github/workflows/specfact.yml@refs/heads/codex/security-dev-native-red",
        "run_id": str(RUN), "run_attempt": "1", "actor": "djm81",
        "actor_id": "39115308", "triggering_actor": "djm81",
    }


def _file(path, raw):
    return {
        "type": "file", "encoding": "base64", "path": path, "name": path.rsplit("/", 1)[1],
        "size": len(raw), "content": base64.encodebytes(raw).decode("ascii"),
        "sha": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(),
    }


def _routes():
    actor = {"login": "djm81", "id": 39115308, "type": "User"}
    return {
        CORE: _repository(), POLICY: _repository(True),
        MAIN: {"ref": "refs/heads/main", "object": {"type": "commit", "sha": I}},
        INDEX_GET: _file(INDEX_PATH, json.dumps(INDEX).encode()),
        COMPARE: {
            "url": "https://api.github.com" + COMPARE,
            "base_commit": {"sha": P}, "merge_base_commit": {"sha": P},
            "status": "ahead", "ahead_by": 1, "behind_by": 0,
        },
        CORE + "/pulls/786": {
            "number": 786, "state": "open", "merged": False, "merged_at": None,
            "base": {"ref": "dev", "sha": FIXED["proof_base"], "repo": _repository()},
            "head": {"ref": FIXED["head_branch"], "sha": FIXED["red_commit"], "repo": _repository()},
        },
        CORE + "/git/commits/" + FIXED["red_commit"]: {
            "sha": FIXED["red_commit"], "tree": {"sha": FIXED["red_tree"]},
            "parents": [{"sha": FIXED["proof_base"]}],
            "verification": {"verified": True, "reason": "valid", "signature": "fixture", "payload": "fixture"},
        },
        CORE + "/git/ref/heads/dev": {"ref": "refs/heads/dev", "object": {"type": "commit", "sha": FIXED["proof_base"]}},
        CORE + "/git/ref/heads/main": {"ref": "refs/heads/main", "object": {"type": "commit", "sha": FIXED["main_commit"]}},
        CORE + f"/actions/runs/{RUN}": {
            "id": RUN, "run_attempt": 1, "path": CALLER_PATH, "event": "workflow_dispatch",
            "head_branch": "codex/security-dev-native-red", "head_sha": E, "status": "in_progress",
            "repository": _repository(), "head_repository": _repository(),
            "actor": actor, "triggering_actor": deepcopy(actor),
        },
        CALLER_GET: _file(CALLER_PATH, CALLER_BYTES),
        CORE + "/collaborators/djm81/permission": {"permission": "write", "user": deepcopy(actor)},
    }


@pytest.fixture
def acquired_fixture(modules, monkeypatch):
    routes, requests, scope_reads = _routes(), [], []

    class RecordingGitHub(modules.transport.GitHub):
        def __init__(self):
            pass

        def get(self, path, *, archive=False):
            requests.append(path)
            assert not archive and path in routes, f"unexpected request {path}"
            value = routes[path]
            if isinstance(value, Exception):
                raise value
            if callable(value):
                value = value()
            return value if isinstance(value, bytes) else json.dumps(value).encode()

    def scope_view():
        scope_reads.append(True)
        return modules.bootstrap.RedScope()

    monkeypatch.setattr(modules.bootstrap, "red_scope", scope_view)
    monkeypatch.setattr(modules.acquisition, "_github", RecordingGitHub)
    return SimpleNamespace(**vars(modules), routes=routes, requests=requests, scope_reads=scope_reads)


def _acquire(fixture, runtime=None, now=NOW):
    return fixture.acquisition.acquire_red_context(runtime=_runtime() if runtime is None else runtime, now=now)


def test_scope_view_is_the_same_frozen_compiled_owner(modules):
    scope = modules.bootstrap.red_scope()
    assert type(scope) is modules.bootstrap.RedScope
    assert scope is modules.bootstrap.red_scope()
    assert asdict(scope) == FIXED | {
        "owner": "nold-ai", "policy_branch": "main", "caller_branch": "codex/security-dev-native-red",
        "caller_workflow": CALLER_PATH, "reusable_workflow": ".github/workflows/native-requirements-bootstrap.yml",
        "run_attempt": 1, "scope_id": "security-dependencies-0-55-11-dev", "release_index": INDEX_PATH,
        "tool_manifest_sha256": MANIFEST, "tool_filenames": ("build-locked.txt", "build-requirements.in", "locked.txt", "requirements.in"),
        "manifest_filename": "tool-files.json", "max_manifest_bytes": 16384, "max_input_bytes": 4194304,
    }
    with pytest.raises(FrozenInstanceError):
        scope.policy_branch = "dev"


def test_independent_selection_returns_exact_frozen_records(acquired_fixture):
    fixture = acquired_fixture
    result = _acquire(fixture)
    assert type(result) is fixture.acquisition.AcquiredRed
    assert type(result.selection) is fixture.acquisition.ProtectedSelection
    assert type(result.context) is fixture.bootstrap.AuthorizedRedContext
    assert asdict(result) == {
        "selection": {"index_commit": I, "policy_commit": P, "manifest_sha256": MANIFEST,
                      "runtime_descriptor_sha256": DESCRIPTOR, "expires_at": EXPIRY},
        "context": FIXED | {"caller_commit": E, "policy_commit": P, "run_id": RUN, "run_attempt": 1},
    }
    for record, field in ((result, "selection"), (result.selection, "policy_commit"), (result.context, "policy_commit")):
        with pytest.raises(FrozenInstanceError):
            setattr(record, field, None)
    assert fixture.scope_reads
    assert fixture.requests.count(MAIN) == 2
    assert set(fixture.routes) <= set(fixture.requests)
    assert fixture.requests[-1] == MAIN
    assert {INDEX_GET, CALLER_GET, COMPARE} <= set(fixture.requests)
    assert not any("...main" in path or "?ref=main" in path for path in fixture.requests)


def test_descriptor_is_selected_but_never_fetched_or_treated_as_runtime(acquired_fixture):
    index = INDEX | {"runtime_descriptor_sha256": "b" * 64}
    acquired_fixture.routes[INDEX_GET] = _file(INDEX_PATH, json.dumps(index).encode())
    assert _acquire(acquired_fixture).selection.runtime_descriptor_sha256 == "b" * 64


def test_comparison_need_not_include_optional_counts(acquired_fixture):
    for key in ("ahead_by", "behind_by"):
        del acquired_fixture.routes[COMPARE][key]
    assert _acquire(acquired_fixture).selection.index_commit == I


def test_largest_bounded_run_id_is_not_replaced_by_a_fixed_fixture_id(acquired_fixture):
    largest = 2**63 - 1
    run = acquired_fixture.routes.pop(CORE + f"/actions/runs/{RUN}")
    run["id"] = largest
    acquired_fixture.routes[CORE + f"/actions/runs/{largest}"] = run
    assert _acquire(acquired_fixture, runtime=_runtime() | {"run_id": str(largest)}).context.run_id == largest


@pytest.mark.parametrize("now", [NOW.astimezone(timezone(timedelta(hours=1))), EXPIRY - timedelta(microseconds=1)])
def test_aware_equivalent_clock_and_last_valid_instant_accept(acquired_fixture, now):
    assert _acquire(acquired_fixture, now=now).selection.expires_at == EXPIRY


@pytest.mark.parametrize("field,value", [
    ("schema_version", True), ("schema_version", 1.0), ("schema_version", "1"),
    ("scope_id", "other"), ("policy_commit", I), ("policy_commit", "A" * 40),
    ("tool_manifest_sha256", "b" * 64), ("runtime_descriptor_sha256", "A" * 64),
    ("expires_at", "2026-11-05T00:00:00+01:00"), ("deployed", True),
])
def test_index_closed_schema_and_independent_pins_refuse(acquired_fixture, field, value):
    index = INDEX | {field: value}
    acquired_fixture.routes[INDEX_GET] = _file(INDEX_PATH, json.dumps(index).encode())
    with pytest.raises(ValueError):
        _acquire(acquired_fixture)


@pytest.mark.parametrize("raw", [
    b"[]", b"\xff", b"{", json.dumps(INDEX).encode()[:-1] + b',"schema_version":1}',
    json.dumps({key: value for key, value in INDEX.items() if key != "policy_commit"}).encode(),
])
def test_index_raw_json_and_missing_selection_refuse(acquired_fixture, raw):
    acquired_fixture.routes[INDEX_GET] = _file(INDEX_PATH, raw)
    with pytest.raises(ValueError):
        _acquire(acquired_fixture)


def test_coordinated_caller_and_comparison_cannot_replace_index_policy(acquired_fixture):
    other = "4" * 40
    acquired_fixture.routes[CALLER_GET] = _file(CALLER_PATH, CALLER_BYTES.replace(P.encode(), other.encode()))
    acquired_fixture.routes[COMPARE].update({"base_commit": {"sha": other}, "merge_base_commit": {"sha": other}})
    with pytest.raises(ValueError):
        _acquire(acquired_fixture)


@pytest.mark.parametrize("field,value", [
    ("status", "identical"), ("status", "diverged"), ("base_commit", {"sha": E}),
    ("merge_base_commit", {"sha": E}), ("url", f"https://api.github.com{POLICY}/compare/{P}...main"),
    ("ahead_by", True), ("ahead_by", 0), ("behind_by", 1), ("behind_by", 0.0),
])
def test_pinned_comparison_requires_actual_ancestor_response(acquired_fixture, field, value):
    acquired_fixture.routes[COMPARE][field] = value
    with pytest.raises(ValueError):
        _acquire(acquired_fixture)


@pytest.mark.parametrize("field,value", [("ref", "refs/heads/dev"), ("object", {"type": "tag", "sha": I}), ("object", {"type": "commit", "sha": "A" * 40})])
@pytest.mark.parametrize("terminal", [False, True])
def test_both_policy_ref_records_must_be_exact(acquired_fixture, field, value, terminal):
    original = deepcopy(acquired_fixture.routes[MAIN])
    changed = original | {field: value}
    responses = iter([original, changed] if terminal else [changed])
    acquired_fixture.routes[MAIN] = lambda: next(responses)
    with pytest.raises(ValueError):
        _acquire(acquired_fixture)


def test_terminal_main_movement_revokes_initial_selection(acquired_fixture):
    caller = deepcopy(acquired_fixture.routes[CALLER_GET])

    def caller_after_main_moves():
        acquired_fixture.routes[MAIN]["object"]["sha"] = "5" * 40
        return caller

    acquired_fixture.routes[CALLER_GET] = caller_after_main_moves
    with pytest.raises(ValueError):
        _acquire(acquired_fixture)


@pytest.mark.parametrize("endpoint,field,value", [
    (POLICY, "id", 1085706003), (POLICY, "default_branch", "dev"), (POLICY, "default_branch", True),
    (CORE, "id", "1085706003"), (CORE + f"/actions/runs/{RUN}", "status", "completed"),
    (CORE + f"/actions/runs/{RUN}", "run_attempt", 2),
    (CORE + "/collaborators/djm81/permission", "permission", "read"),
    (CORE + "/collaborators/djm81/permission", "user", {"login": "other", "id": 39115308, "type": "User"}),
])
def test_acquired_snapshot_still_obeys_existing_pure_boundary(acquired_fixture, endpoint, field, value):
    acquired_fixture.routes[endpoint][field] = value
    with pytest.raises(ValueError):
        _acquire(acquired_fixture)


@pytest.mark.parametrize("endpoint", [INDEX_GET, CALLER_GET])
@pytest.mark.parametrize("field,value", [
    ("type", "symlink"), ("encoding", "none"), ("path", "elsewhere"), ("name", "other.json"),
    ("size", True), ("size", 1), ("sha", "0" * 40), ("content", "!!!!"),
    ("content", "Zh=="), ("content", "A" * 21849), ("size", 16385),
])
def test_immutable_contents_authenticates_bounded_actual_bytes(acquired_fixture, endpoint, field, value):
    acquired_fixture.routes[endpoint][field] = value
    with pytest.raises(ValueError):
        _acquire(acquired_fixture)


def _unwrapped_padded_index():
    raw = json.dumps(INDEX).encode()
    raw += b" " * ((1 - len(raw)) % 3)
    response = _file(INDEX_PATH, raw)
    response["content"] = base64.b64encode(raw).decode("ascii")
    return raw, response


def test_valid_unwrapped_padded_index_accepts(acquired_fixture):
    _, response = _unwrapped_padded_index()
    acquired_fixture.routes[INDEX_GET] = response
    assert _acquire(acquired_fixture).selection.policy_commit == P


@pytest.mark.parametrize("variant", ["padding_bits", "non_lf_junk"])
def test_otherwise_valid_index_requires_canonical_base64(acquired_fixture, variant):
    raw, response = _unwrapped_padded_index()
    encoded = response["content"]
    assert encoded.endswith("==")
    if variant == "padding_bits":
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        last = alphabet.index(encoded[-3])
        assert last % 16 == 0
        changed = encoded[:-3] + alphabet[last + 1] + "=="
    else:
        changed = encoded[:4] + "!" + encoded[4:]
    assert changed != encoded
    assert base64.b64decode(changed) == raw
    response["content"] = changed
    acquired_fixture.routes[INDEX_GET] = response
    with pytest.raises(ValueError):
        _acquire(acquired_fixture)


@pytest.mark.parametrize("endpoint", [INDEX_GET, CALLER_GET])
def test_missing_content_authentication_field_refuses(acquired_fixture, endpoint):
    del acquired_fixture.routes[endpoint]["sha"]
    with pytest.raises(ValueError):
        _acquire(acquired_fixture)


@pytest.mark.parametrize("endpoint", [INDEX_GET, CALLER_GET])
def test_oversized_encoded_content_refuses_before_decode(acquired_fixture, monkeypatch, endpoint):
    decoder = acquired_fixture.transport.base64.b64decode

    def bounded_decode(value, *args, **kwargs):
        assert len(value) <= 21848, "oversized content reached the decoder"
        return decoder(value, *args, **kwargs)

    monkeypatch.setattr(acquired_fixture.transport.base64, "b64decode", bounded_decode)
    acquired_fixture.routes[endpoint]["content"] = "A" * 21852
    with pytest.raises(ValueError):
        _acquire(acquired_fixture)


def test_correct_blob_hash_does_not_authorize_changed_caller_permissions(acquired_fixture):
    acquired_fixture.routes[CALLER_GET] = _file(CALLER_PATH, CALLER_BYTES.replace(b"actions: read", b"actions: write"))
    with pytest.raises(ValueError):
        _acquire(acquired_fixture)


@pytest.mark.parametrize("field,value", [
    ("run_id", "0"), ("run_id", "0540001"), ("run_id", "５４０００１"),
    ("run_id", str(2**63)), ("run_id", "540001/../../other"), ("run_id", 540001),
    ("sha", "A" * 40), ("sha", "../other"), ("sha", E + "?ref=main"),
])
def test_dynamic_path_inputs_refuse_before_unsafe_interpolation(acquired_fixture, field, value):
    runtime = _runtime() | {field: value}
    with pytest.raises(ValueError):
        _acquire(acquired_fixture, runtime=runtime)
    assert not any("/actions/runs/" in path or "/contents/" + CALLER_PATH in path for path in acquired_fixture.requests)


@pytest.mark.parametrize("extra", [{"job_workflow_sha": P}, {"deployed": "true"}])
def test_runtime_mapping_remains_closed(acquired_fixture, extra):
    with pytest.raises(ValueError):
        _acquire(acquired_fixture, runtime=_runtime() | extra)


@pytest.mark.parametrize("now", [NOW.replace(tzinfo=None), EXPIRY, EXPIRY + timedelta(microseconds=1)])
def test_actual_clock_must_precede_fixed_expiry(acquired_fixture, now):
    with pytest.raises(ValueError):
        _acquire(acquired_fixture, now=now)


@pytest.mark.parametrize("failure", [OSError("API unavailable"), TimeoutError("timed out"), b"[]", b"{"])
def test_transport_or_malformed_response_returns_only_valueerror(acquired_fixture, failure):
    acquired_fixture.routes[INDEX_GET] = failure
    with pytest.raises(ValueError):
        _acquire(acquired_fixture)


@pytest.mark.parametrize("redirect", [False, True])
def test_existing_transport_keeps_token_at_fixed_api_host(modules, monkeypatch, redirect):
    routes, observed = _routes(), []
    monkeypatch.setenv("GH_TOKEN", "fixture-token")
    monkeypatch.setenv("GITHUB_API_URL", "https://api.github.com")
    monkeypatch.setattr(modules.bootstrap, "red_scope", lambda: modules.bootstrap.RedScope())

    class Connection:
        def __init__(self, host, timeout):
            assert host == "api.github.com"
            self.path = None

        def request(self, method, target, headers):
            assert method == "GET" and target in routes
            observed.append((target, headers.get("Authorization")))
            self.path = target

        def getresponse(self):
            raw = json.dumps(routes[self.path]).encode()
            status = 302 if redirect and self.path == INDEX_GET else 200
            return SimpleNamespace(status=status, read=lambda limit: raw[:limit],
                                   getheader=lambda name, default="": "https://foreign.example/index")

        def close(self):
            pass

    monkeypatch.setattr(modules.transport.http.client, "HTTPSConnection", Connection)
    if redirect:
        with pytest.raises(ValueError):
            modules.acquisition.acquire_red_context(runtime=_runtime(), now=NOW)
    else:
        assert modules.acquisition.acquire_red_context(runtime=_runtime(), now=NOW).selection.policy_commit == P
    assert observed and all(token == "Bearer fixture-token" for _, token in observed)
