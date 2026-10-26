from __future__ import annotations

import hashlib
import http.client
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime

import native_requirements_bootstrap as bootstrap
from late_cycle_admission import GitHub, json_object


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


def _selection(
    api: GitHub, scope: bootstrap.RedScope, index_commit: str
) -> ProtectedSelection:
    raw = api.immutable_contents(
        scope.policy_repository, scope.release_index, index_commit, max_bytes=16384
    )
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


def _active_selection(
    api: GitHub, scope: bootstrap.RedScope
) -> tuple[ProtectedSelection, dict[str, object], dict[str, object]]:
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
    return selection, policy_repository, comparison


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
        selection, policy_repository, comparison = _active_selection(api, scope)
        index_commit = selection.index_commit
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
            "caller_workflow_bytes": api.immutable_contents(
                scope.repository, scope.caller_workflow, caller_commit, max_bytes=16384
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
    try:
        scope = bootstrap.red_scope()
        if type(now) is not datetime or now.utcoffset() is None or now >= scope.expires_at:
            raise ValueError("native acquisition rejected: invalid or expired clock")
        api = _github()
        selection, _, _ = _active_selection(api, scope)
        if type(expected_selection) is not ProtectedSelection or expected_selection != selection:
            raise ValueError("native acquisition rejected: active selection differs")
        captured: dict[str, bytes] = {}
        for name in (*scope.tool_filenames, scope.manifest_filename, scope.runtime_descriptor_filename):
            limit = 128 * 1024 if name in scope.tool_filenames else 16384
            captured[name] = api.immutable_contents(
                scope.policy_repository, f"{scope.tool_directory}/{name}",
                selection.policy_commit, max_bytes=limit,
            )
        descriptor = captured.pop(scope.runtime_descriptor_filename)
        if hashlib.sha256(descriptor).hexdigest() != selection.runtime_descriptor_sha256:
            raise ValueError("native acquisition rejected: runtime descriptor digest differs")
        bootstrap.verify_tool_bytes(captured, selection.manifest_sha256)
        if _policy_main(api, scope) != selection.index_commit:
            raise ValueError("native acquisition rejected: policy main changed")
        return ToolRelease(
            selection, descriptor, captured[scope.manifest_filename],
            captured["requirements.in"], captured["locked.txt"],
            captured["build-requirements.in"], captured["build-locked.txt"],
        )
    except (
        ValueError, TypeError, KeyError, OSError, http.client.HTTPException,
        OverflowError, RecursionError,
    ):
        raise ValueError("native acquisition rejected: invalid or unavailable release") from None
