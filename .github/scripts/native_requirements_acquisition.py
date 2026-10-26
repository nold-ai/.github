from __future__ import annotations

import base64
import hashlib
import http.client
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime

import native_requirements_bootstrap as bootstrap
from late_cycle_admission import MAX_FILE, GitHub, json_object


@dataclass(frozen=True, slots=True)
class ProtectedSelection:
    index_commit: str
    policy_commit: str
    manifest_sha256: str
    runtime_descriptor_sha256: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class AcquiredRed:
    selection: ProtectedSelection
    context: bootstrap.AuthorizedRedContext


def _github():
    return GitHub()


def _hex(value: object, length: int) -> str:
    if (
        type(value) is not str or len(value) != length
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError("native acquisition rejected: invalid digest")
    return value


def _fields(value: Mapping[str, object], expected: Mapping[str, object]) -> None:
    for path, required in expected.items():
        actual: object = value
        for name in path.split("/"):
            if not isinstance(actual, Mapping) or name not in actual:
                raise ValueError("native acquisition rejected: missing API field")
            actual = actual[name]
        if type(actual) is not type(required) or actual != required:
            raise ValueError("native acquisition rejected: mismatched API field")


def _policy_main(api: GitHub, scope: bootstrap.RedScope) -> str:
    value = api.obj(f"/repos/{scope.policy_repository}/git/ref/heads/{scope.policy_branch}")
    _fields(value, {"ref": f"refs/heads/{scope.policy_branch}", "object/type": "commit"})
    return _hex(value["object"]["sha"], 40)


def _contents(api: GitHub, repository: str, path: str, revision: str) -> bytes:
    value = api.obj(f"/repos/{repository}/contents/{path}?ref={revision}")
    _fields(value, {
        "type": "file", "encoding": "base64", "path": path,
        "name": path.rsplit("/", 1)[-1],
    })
    limit = min(16384, MAX_FILE)
    size = value.get("size")
    content = value.get("content")
    blob = _hex(value.get("sha"), 40)
    encoded_limit = 4 * ((limit + 2) // 3)
    if (
        type(size) is not int or not 0 <= size <= limit
        or type(content) is not str or len(content) > 2 * encoded_limit
    ):
        raise ValueError("native acquisition rejected: invalid contents size")
    encoded = content.replace("\n", "")
    if len(encoded) > encoded_limit:
        raise ValueError("native acquisition rejected: oversized base64")
    raw = base64.b64decode(encoded, validate=True)
    if (
        len(raw) > limit or len(raw) != size
        or base64.b64encode(raw).decode("ascii") != encoded
    ):
        raise ValueError("native acquisition rejected: noncanonical contents")
    # Git's blob identity includes the object kind and byte length, not just bytes.
    actual_blob = hashlib.sha1(
        b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw,
        usedforsecurity=False,
    ).hexdigest()
    if actual_blob != blob:
        raise ValueError("native acquisition rejected: contents blob mismatch")
    return raw


def _selection(
    api: GitHub, scope: bootstrap.RedScope, index_commit: str
) -> ProtectedSelection:
    raw = _contents(api, scope.policy_repository, scope.release_index, index_commit)
    raw.decode("utf-8")
    index = json_object(raw)
    if set(index) != {
        "schema_version", "scope_id", "policy_commit", "tool_manifest_sha256",
        "runtime_descriptor_sha256", "expires_at",
    }:
        raise ValueError("native acquisition rejected: invalid index fields")
    _fields(index, {
        "schema_version": 1, "scope_id": scope.scope_id,
        "tool_manifest_sha256": scope.tool_manifest_sha256,
        "expires_at": scope.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    })
    policy_commit = _hex(index["policy_commit"], 40)
    if policy_commit == index_commit:
        raise ValueError("native acquisition rejected: index must follow policy")
    return ProtectedSelection(
        index_commit, policy_commit, scope.tool_manifest_sha256,
        _hex(index["runtime_descriptor_sha256"], 64), scope.expires_at,
    )


def acquire_red_context(*, runtime: Mapping[str, str], now: datetime) -> AcquiredRed:
    """Select protected policy and acquire the fresh fixed RED context."""
    try:
        scope = bootstrap.red_scope()
        if type(now) is not datetime or now.utcoffset() is None or now >= scope.expires_at:
            raise ValueError("native acquisition rejected: invalid or expired clock")
        if not isinstance(runtime, Mapping):
            raise ValueError("native acquisition rejected: invalid runtime mapping")
        caller_commit = _hex(runtime.get("sha"), 40)
        run_id = runtime.get("run_id")
        if (
            type(run_id) is not str or not 1 <= len(run_id) <= 19
            or run_id[0] == "0" or any(character not in "0123456789" for character in run_id)
            or int(run_id) >= 2**63
        ):
            raise ValueError("native acquisition rejected: invalid run ID")
        api = _github()
        core = f"/repos/{scope.repository}"
        policy = f"/repos/{scope.policy_repository}"
        policy_repository = api.obj(policy)
        _fields(policy_repository, {
            "id": scope.policy_repository_id,
            "name": scope.policy_repository.split("/")[1],
            "full_name": scope.policy_repository, "owner/login": scope.owner,
            "owner/id": scope.owner_id, "owner/type": "Organization",
            "default_branch": scope.policy_branch,
        })
        index_commit = _policy_main(api, scope)
        selection = _selection(api, scope, index_commit)
        compare_path = f"{policy}/compare/{selection.policy_commit}...{index_commit}"
        comparison = api.obj(compare_path)
        _fields(comparison, {
            "url": "https://api.github.com" + compare_path, "status": "ahead",
            "base_commit/sha": selection.policy_commit,
            "merge_base_commit/sha": selection.policy_commit,
        })
        for name in ("ahead_by", "behind_by"):
            if name in comparison:
                count = comparison[name]
                if type(count) is not int or (count <= 0 if name == "ahead_by" else count != 0):
                    raise ValueError("native acquisition rejected: invalid comparison count")
        snapshot = {
            "runtime": runtime,
            "policy_repository": policy_repository,
            "policy_compare": comparison,
            "repository": api.obj(core),
            "pull_request": api.obj(f"{core}/pulls/{scope.pull_request}"),
            "red_commit": api.obj(f"{core}/git/commits/{scope.red_commit}"),
            "dev_ref": api.obj(f"{core}/git/ref/heads/{scope.base_ref}"),
            "main_ref": api.obj(f"{core}/git/ref/heads/main"),
            "caller_run": api.obj(f"{core}/actions/runs/{run_id}"),
            "caller_workflow_bytes": _contents(
                api, scope.repository, scope.caller_workflow, caller_commit
            ),
            "actor_permission": api.obj(f"{core}/collaborators/{scope.operator_login}/permission"),
        }
        context = bootstrap.authorize_red_context(selection.policy_commit, snapshot, now)
        if _policy_main(api, scope) != index_commit:
            raise ValueError("native acquisition rejected: policy main changed")
        return AcquiredRed(selection, context)
    except (
        ValueError, TypeError, KeyError, OSError, http.client.HTTPException,
        OverflowError, RecursionError,
    ):
        raise ValueError("native acquisition rejected: invalid or unavailable context") from None


@dataclass(frozen=True, slots=True)
class ToolRelease:
    selection: ProtectedSelection
    runtime_descriptor: bytes
    manifest: bytes
    requirements: bytes
    locked: bytes
    build_requirements: bytes
    build_locked: bytes


def acquire_tool_release(*, now: datetime, expected_selection: ProtectedSelection) -> ToolRelease:
    """Authenticate active I/P independently and capture its exact immutable release bytes."""
    raise NotImplementedError
