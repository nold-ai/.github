from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ".github/native-tools/dev786"
I, P = "3" * 40, "2" * 40
NOW = datetime(2026, 10, 26, 12, tzinfo=UTC)
EXPIRY = datetime(2026, 11, 4, 23, tzinfo=UTC)
POLICY = "/repos/nold-ai/.github"
MAIN = POLICY + "/git/ref/heads/main"
INDEX_PATH = ".github/native-releases/dev786.json"
INDEX_GET = f"{POLICY}/contents/{INDEX_PATH}?ref={I}"
COMPARE = f"{POLICY}/compare/{P}...{I}"
MANIFEST = "969cabb52fc6db85de46967f62ffe4f0f9b0ca50a80b5a3e46255a89b51f78ad"


def load(name, monkeypatch):
    spec = importlib.util.spec_from_file_location(name, ROOT / f".github/scripts/{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


def file_response(path, raw):
    return {
        "type": "file", "encoding": "base64", "path": path,
        "name": path.rsplit("/", 1)[-1], "size": len(raw),
        "content": base64.encodebytes(raw).decode(),
        "sha": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(),
    }


@pytest.fixture
def release(monkeypatch):
    bootstrap = load("native_requirements_bootstrap", monkeypatch)
    transport = load("late_cycle_admission", monkeypatch)
    acquisition = load("native_requirements_acquisition", monkeypatch)
    raw = {name: (ROOT / DIRECTORY / name).read_bytes() for name in (
        "requirements.in", "locked.txt", "build-requirements.in", "build-locked.txt", "tool-files.json", "runtime.json",
    )}
    descriptor_digest = hashlib.sha256(raw["runtime.json"]).hexdigest()
    selection = acquisition.ProtectedSelection(I, P, MANIFEST, descriptor_digest, EXPIRY)
    index = {
        "schema_version": 1, "scope_id": "security-dependencies-0-55-11-dev", "policy_commit": P,
        "tool_manifest_sha256": MANIFEST, "runtime_descriptor_sha256": descriptor_digest,
        "expires_at": "2026-11-04T23:00:00Z",
    }
    routes = {
        POLICY: {"id": 1110267669, "name": ".github", "full_name": "nold-ai/.github",
                 "owner": {"login": "nold-ai", "id": 225190663, "type": "Organization"}, "default_branch": "main"},
        MAIN: {"ref": "refs/heads/main", "object": {"type": "commit", "sha": I}},
        INDEX_GET: file_response(INDEX_PATH, json.dumps(index).encode()),
        COMPARE: {"url": "https://api.github.com" + COMPARE, "base_commit": {"sha": P},
                  "merge_base_commit": {"sha": P}, "status": "ahead", "ahead_by": 1, "behind_by": 0},
    }
    for name, content in raw.items():
        path = DIRECTORY + "/" + name
        routes[f"{POLICY}/contents/{path}?ref={P}"] = file_response(path, content)
    requests = []
    monkeypatch.setenv("GH_TOKEN", "fixture-token")
    monkeypatch.setenv("GITHUB_API_URL", "https://api.github.com")

    class Connection:
        def __init__(self, host, timeout):
            assert host == "api.github.com"

        def request(self, method, target, headers):
            assert method == "GET" and target in routes, f"unexpected endpoint {target}"
            assert headers["Authorization"] == "Bearer fixture-token"
            self.path = target
            requests.append(target)

        def getresponse(self):
            value = routes[self.path]
            if callable(value):
                value = value()
            if isinstance(value, Exception):
                raise value
            data = value if isinstance(value, bytes) else json.dumps(value).encode()
            return SimpleNamespace(status=200, read=lambda limit: data[:limit], getheader=lambda key, default=None: default)

        def close(self):
            pass

    monkeypatch.setattr(transport.http.client, "HTTPSConnection", Connection)
    return SimpleNamespace(bootstrap=bootstrap, transport=transport, acquisition=acquisition,
                           raw=raw, selection=selection, routes=routes, requests=requests, index=index)


def acquire(release, *, selection=None, now=NOW):
    return release.acquisition.acquire_tool_release(now=now, expected_selection=release.selection if selection is None else selection)


def tool_endpoint(name):
    return f"{POLICY}/contents/{DIRECTORY}/{name}?ref={P}"


def test_fresh_tool_release_contains_exact_owned_bytes_and_actual_selection(release):
    result = acquire(release)
    assert type(result) is release.acquisition.ToolRelease
    assert result.selection == release.selection
    assert result.runtime_descriptor == release.raw["runtime.json"]
    assert result.manifest == release.raw["tool-files.json"]
    assert result.requirements == release.raw["requirements.in"]
    assert result.locked == release.raw["locked.txt"] and len(result.locked) == 65303
    assert result.build_requirements == release.raw["build-requirements.in"]
    assert result.build_locked == release.raw["build-locked.txt"]
    with pytest.raises(FrozenInstanceError):
        result.locked = b"replacement"
    assert release.requests.count(MAIN) == 2
    assert release.requests[-1] == MAIN
    assert set(release.routes) == set(release.requests)
    assert not any("actions/runs" in path or "?ref=main" in path for path in release.requests)


@pytest.mark.parametrize("field,value", [("index_commit", "4" * 40), ("policy_commit", "5" * 40),
    ("manifest_sha256", "b" * 64), ("runtime_descriptor_sha256", "c" * 64),
    ("expires_at", datetime(2026, 11, 3, tzinfo=UTC))])
def test_caller_selection_is_only_a_consistency_filter(release, field, value):
    expected = replace(release.selection, **{field: value})
    with pytest.raises(ValueError):
        acquire(release, selection=expected)
    assert INDEX_GET in release.requests
    if field in {"policy_commit", "index_commit"}:
        assert not any(value in path for path in release.requests)


@pytest.mark.parametrize("name", ["runtime.json", "tool-files.json", "locked.txt", "build-locked.txt", "requirements.in", "build-requirements.in"])
def test_changed_bytes_with_valid_git_blob_metadata_still_refuse(release, name):
    path = DIRECTORY + "/" + name
    release.routes[tool_endpoint(name)] = file_response(path, release.raw[name] + b"\n")
    with pytest.raises(ValueError):
        acquire(release)


@pytest.mark.parametrize("target", ["runtime.json", "tool-files.json"])
def test_small_release_metadata_cannot_borrow_large_lock_bound(release, target):
    path = DIRECTORY + "/" + target
    release.routes[tool_endpoint(target)] = file_response(path, b" " * 16385)
    with pytest.raises(ValueError):
        acquire(release)


@pytest.mark.parametrize("mutation", ["duplicate", "unknown", "boolean_version", "wrong_manifest", "missing"])
def test_index_authentication_is_not_bypassed_for_materialization(release, mutation):
    index = deepcopy(release.index)
    if mutation == "duplicate":
        raw = json.dumps(index).encode()[:-1] + b',"schema_version":1}'
    else:
        if mutation == "unknown":
            index["deployed"] = True
        elif mutation == "boolean_version":
            index["schema_version"] = True
        elif mutation == "wrong_manifest":
            index["tool_manifest_sha256"] = "b" * 64
        else:
            del index["scope_id"]
        raw = json.dumps(index).encode()
    release.routes[INDEX_GET] = file_response(INDEX_PATH, raw)
    with pytest.raises(ValueError):
        acquire(release)


@pytest.mark.parametrize("now", [NOW.replace(tzinfo=None), EXPIRY])
def test_materialization_selection_keeps_exclusive_expiry(release, now):
    with pytest.raises(ValueError):
        acquire(release, now=now)


def test_main_recheck_happens_after_last_release_byte(release):
    endpoint = tool_endpoint("locked.txt")
    response = release.routes[endpoint]

    def move_main():
        release.routes[MAIN]["object"]["sha"] = "7" * 40
        return response

    release.routes[endpoint] = move_main
    with pytest.raises(ValueError):
        acquire(release)
    assert release.requests[-1] == MAIN


@pytest.mark.parametrize("field,value", [("id", True), ("full_name", "foreign/.github"), ("default_branch", "dev")])
def test_active_policy_repository_identity_is_independent(release, field, value):
    release.routes[POLICY][field] = value
    with pytest.raises(ValueError):
        acquire(release)


def test_p_must_be_deployed_ancestor_of_exact_i(release):
    release.routes[COMPARE]["merge_base_commit"] = {"sha": "4" * 40}
    with pytest.raises(ValueError):
        acquire(release)


@pytest.mark.parametrize("failure", [TimeoutError("unavailable"), b"[]", b"{"])
def test_no_partial_release_on_api_failure(release, failure):
    release.routes[tool_endpoint("build-locked.txt")] = failure
    with pytest.raises(ValueError):
        acquire(release)
