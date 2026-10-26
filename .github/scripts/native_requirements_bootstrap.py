from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


@dataclass(frozen=True, slots=True)
class _Scope:
    repository: str = "nold-ai/specfact-cli"
    repository_id: int = 1085706003
    policy_repository: str = "nold-ai/.github"
    policy_repository_id: int = 1110267669
    owner: str = "nold-ai"
    owner_id: int = 225190663
    pull_request: int = 786
    base_ref: str = "dev"
    head_branch: str = "codex/security-dependencies-0-55-11-dev"
    proof_base: str = "9b5ad1e78430cc0b061cb16de42f73de96f4f312"
    main_commit: str = "5262efb0881e4fac7697d629b0530250342bc656"
    red_commit: str = "4ae6175a4d337296d0347e73b66c9da1f0e43f7f"
    red_tree: str = "baeb88acf0d2a5015810ad12dbfccfa7fdf9a21e"
    module_commit: str = "69f075819be5e1ceca1446b026b0417f19e584ca"
    module_tree: str = "5d0b8e66c6cd467e6b1ad9d582e24c66b907e205"
    mapping_sha256: str = "7025a000601cc44c1a1e6168367f2188681471d68ea5f044cfc81a94b734f8ff"
    plan_sha256: str = "dc90453d191b282ba5e47127bf067ee23b475072d7e94a0859c7c6a26677ce3a"
    operator_login: str = "djm81"
    operator_id: int = 39115308
    policy_branch: str = "main"
    caller_branch: str = "codex/security-dev-native-red"
    caller_workflow: str = ".github/workflows/specfact.yml"
    reusable_workflow: str = ".github/workflows/native-requirements-bootstrap.yml"
    run_attempt: int = 1
    expires_at: datetime = datetime(2026, 11, 4, 23, tzinfo=UTC)
    tool_filenames: tuple[str, ...] = (
        "build-locked.txt", "build-requirements.in", "locked.txt", "requirements.in"
    )
    manifest_filename: str = "tool-files.json"
    max_manifest_bytes: int = 16384
    max_input_bytes: int = 4194304


_SCOPE = _Scope()


@dataclass(frozen=True, slots=True)
class AuthorizedRedContext:
    repository: str
    repository_id: int
    policy_repository: str
    policy_repository_id: int
    owner_id: int
    pull_request: int
    base_ref: str
    head_branch: str
    proof_base: str
    main_commit: str
    red_commit: str
    red_tree: str
    module_commit: str
    module_tree: str
    mapping_sha256: str
    plan_sha256: str
    caller_commit: str
    policy_commit: str
    run_id: int
    run_attempt: int
    operator_login: str
    operator_id: int
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class VerifiedToolFiles:
    directory: Path
    manifest_sha256: str
    file_sha256: tuple[tuple[str, str], ...]


def _canonical_caller_workflow(policy_commit: str) -> bytes:
    return (
        "name: Native Requirements RED\non:\n  workflow_dispatch:\npermissions:\n"
        "  contents: read\n  actions: read\njobs:\n  native-red:\n"
        f"    uses: {_SCOPE.policy_repository}/{_SCOPE.reusable_workflow}@{policy_commit}\n"
        f"    with:\n      red_commit: {_SCOPE.red_commit}\n"
    ).encode("utf-8")


def _hex_digest(value: object, length: int, message: str) -> str:
    if type(value) is not str or len(value) != length:
        raise ValueError(message)
    if any(character not in "0123456789abcdef" for character in value):
        raise ValueError(message)
    return value


def _context_value(value: object, path: str) -> object:
    for key in path.split("/"):
        if not isinstance(value, Mapping) or key not in value:
            raise ValueError(f"native bootstrap rejected: missing or malformed {path}")
        value = value[key]
    return value


def _require_context_fields(
    snapshot: Mapping[str, object], expected: Mapping[str, object]
) -> None:
    for path, required in expected.items():
        actual = _context_value(snapshot, path)
        if path.rsplit("/", 1)[-1] in {"sha", "head_sha", "workflow_sha"}:
            _hex_digest(actual, 40, f"native bootstrap rejected: invalid {path}")
        if type(actual) is not type(required) or actual != required:
            raise ValueError(f"native bootstrap rejected: mismatched {path}")


def authorize_red_context(
    expected_policy: str, snapshot: Mapping[str, object], now: datetime
) -> AuthorizedRedContext:
    """Authorize fixed R and separate E/P context, without accepting native proof."""
    keys = {
        "runtime", "repository", "policy_repository", "pull_request", "red_commit",
        "dev_ref", "main_ref", "caller_run", "caller_workflow_bytes", "policy_compare",
        "actor_permission",
    }
    if not isinstance(snapshot, Mapping) or set(snapshot) != keys:
        raise ValueError("native bootstrap rejected: invalid snapshot fields")
    try:
        valid_time = (
            type(now) is datetime and now.utcoffset() is not None
            and now < _SCOPE.expires_at
        )
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError("native bootstrap rejected: invalid clock") from error
    if not valid_time:
        raise ValueError("native bootstrap rejected: naive, invalid or expired clock")
    policy_commit = _hex_digest(
        expected_policy, 40, "native bootstrap rejected: invalid policy commit"
    )
    caller_commit = _hex_digest(
        _context_value(snapshot, "runtime/sha"), 40,
        "native bootstrap rejected: invalid caller commit",
    )
    if len({_SCOPE.proof_base, _SCOPE.red_commit, caller_commit, policy_commit}) != 4:
        raise ValueError("native bootstrap rejected: source and subject roles overlap")
    run_id = _context_value(snapshot, "caller_run/id")
    if type(run_id) is not int or run_id <= 0:
        raise ValueError("native bootstrap rejected: invalid run ID")
    try:
        encoded_run_id = str(run_id)
    except ValueError as error:
        raise ValueError("native bootstrap rejected: unrepresentable run ID") from error
    runtime = _context_value(snapshot, "runtime")
    expected_runtime = {
        "GITHUB_ACTIONS": "true", "event_name": "workflow_dispatch",
        "repository": _SCOPE.repository, "repository_id": str(_SCOPE.repository_id),
        "repository_owner": _SCOPE.owner, "repository_owner_id": str(_SCOPE.owner_id),
        "sha": caller_commit, "ref": f"refs/heads/{_SCOPE.caller_branch}",
        "workflow_ref": (
            f"{_SCOPE.repository}/{_SCOPE.caller_workflow}@refs/heads/{_SCOPE.caller_branch}"
        ),
        "workflow_sha": caller_commit, "run_id": encoded_run_id,
        "run_attempt": str(_SCOPE.run_attempt), "actor": _SCOPE.operator_login,
        "actor_id": str(_SCOPE.operator_id), "triggering_actor": _SCOPE.operator_login,
    }
    if not isinstance(runtime, Mapping) or set(runtime) != set(expected_runtime):
        raise ValueError("native bootstrap rejected: invalid runtime fields")
    _require_context_fields(snapshot, {
        f"runtime/{name}": value for name, value in expected_runtime.items()
    })
    _require_context_fields(snapshot, {
        "policy_repository/default_branch": _SCOPE.policy_branch,
        "pull_request/number": _SCOPE.pull_request,
        "pull_request/state": "open", "pull_request/merged": False,
        "pull_request/merged_at": None,
        "pull_request/base/ref": _SCOPE.base_ref,
        "pull_request/base/sha": _SCOPE.proof_base,
        "pull_request/head/ref": _SCOPE.head_branch,
        "pull_request/head/sha": _SCOPE.red_commit,
        "red_commit/sha": _SCOPE.red_commit, "red_commit/tree/sha": _SCOPE.red_tree,
        "red_commit/verification/verified": True,
        "red_commit/verification/reason": "valid",
        "dev_ref/ref": f"refs/heads/{_SCOPE.base_ref}",
        "dev_ref/object/type": "commit", "dev_ref/object/sha": _SCOPE.proof_base,
        "main_ref/ref": "refs/heads/main",
        "main_ref/object/type": "commit", "main_ref/object/sha": _SCOPE.main_commit,
        "caller_run/run_attempt": _SCOPE.run_attempt,
        "caller_run/event": "workflow_dispatch",
        "caller_run/head_branch": _SCOPE.caller_branch,
        "caller_run/head_sha": caller_commit, "caller_run/status": "in_progress",
        "policy_compare/base_commit/sha": policy_commit,
        "policy_compare/merge_base_commit/sha": policy_commit,
        "caller_workflow_bytes": _canonical_caller_workflow(policy_commit),
    })
    repositories = {
        "repository": (_SCOPE.repository, _SCOPE.repository_id),
        "policy_repository": (_SCOPE.policy_repository, _SCOPE.policy_repository_id),
        "pull_request/base/repo": (_SCOPE.repository, _SCOPE.repository_id),
        "pull_request/head/repo": (_SCOPE.repository, _SCOPE.repository_id),
        "caller_run/repository": (_SCOPE.repository, _SCOPE.repository_id),
        "caller_run/head_repository": (_SCOPE.repository, _SCOPE.repository_id),
    }
    for path, (name, repository_id) in repositories.items():
        _require_context_fields(snapshot, {
            f"{path}/id": repository_id, f"{path}/name": name.split("/")[1],
            f"{path}/full_name": name, f"{path}/owner/login": _SCOPE.owner,
            f"{path}/owner/id": _SCOPE.owner_id, f"{path}/owner/type": "Organization",
        })
    for path in ("caller_run/actor", "caller_run/triggering_actor", "actor_permission/user"):
        _require_context_fields(snapshot, {
            f"{path}/login": _SCOPE.operator_login,
            f"{path}/id": _SCOPE.operator_id, f"{path}/type": "User",
        })
    parents = _context_value(snapshot, "red_commit/parents")
    if type(parents) is not list or len(parents) != 1:
        raise ValueError("native bootstrap rejected: RED must have one parent")
    _require_context_fields({"parent": parents[0]}, {"parent/sha": _SCOPE.proof_base})
    for field in ("signature", "payload"):
        value = _context_value(snapshot, f"red_commit/verification/{field}")
        if type(value) is not str or not value.strip():
            raise ValueError(f"native bootstrap rejected: invalid commit {field}")
    choices = {
        "caller_run/path": (
            _SCOPE.caller_workflow,
            f"{_SCOPE.caller_workflow}@{_SCOPE.caller_branch}",
            f"{_SCOPE.caller_workflow}@refs/heads/{_SCOPE.caller_branch}",
        ),
        "policy_compare/status": ("identical", "ahead"),
        "actor_permission/permission": ("write", "admin"),
    }
    for path, allowed in choices.items():
        value = _context_value(snapshot, path)
        if type(value) is not str or value not in allowed:
            raise ValueError(f"native bootstrap rejected: invalid {path}")
    return AuthorizedRedContext(
        repository=_SCOPE.repository, repository_id=_SCOPE.repository_id,
        policy_repository=_SCOPE.policy_repository,
        policy_repository_id=_SCOPE.policy_repository_id, owner_id=_SCOPE.owner_id,
        pull_request=_SCOPE.pull_request, base_ref=_SCOPE.base_ref,
        head_branch=_SCOPE.head_branch, proof_base=_SCOPE.proof_base,
        main_commit=_SCOPE.main_commit, red_commit=_SCOPE.red_commit,
        red_tree=_SCOPE.red_tree, module_commit=_SCOPE.module_commit,
        module_tree=_SCOPE.module_tree, mapping_sha256=_SCOPE.mapping_sha256,
        plan_sha256=_SCOPE.plan_sha256, caller_commit=caller_commit,
        policy_commit=policy_commit, run_id=run_id, run_attempt=_SCOPE.run_attempt,
        operator_login=_SCOPE.operator_login, operator_id=_SCOPE.operator_id,
        expires_at=_SCOPE.expires_at,
    )


def _regular_file_size(metadata: os.stat_result, limit: int) -> None:
    if not stat.S_ISREG(metadata.st_mode) or not 1 <= metadata.st_size <= limit:
        raise ValueError("tool files rejected: nonregular, empty or oversized file")


def _read_tool_file(directory_fd: int, name: str, limit: int) -> bytes:
    before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    _regular_file_size(before, limit)
    descriptor = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd
    )
    try:
        opened = os.fstat(descriptor)
        _regular_file_size(opened, limit)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("tool files rejected: file replaced during open")
        remaining = limit + 1
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        _regular_file_size(after, limit)
        if (
            len(data) != opened.st_size or len(data) != after.st_size
            or (opened.st_mtime_ns, opened.st_ctime_ns) != (after.st_mtime_ns, after.st_ctime_ns)
        ):
            raise ValueError("tool files rejected: file changed during read")
        return data
    finally:
        os.close(descriptor)


def _unique_manifest_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("tool files rejected: duplicate manifest key")
        result[name] = value
    return result


def verify_tool_files(
    directory: Path, expected_manifest_sha256: str
) -> VerifiedToolFiles:
    """Bind bounded local bytes to an independent digest, without tool authority."""
    expected_digest = _hex_digest(
        expected_manifest_sha256, 64, "tool files rejected: invalid expected manifest digest"
    )
    if not isinstance(directory, Path) or "\0" in str(directory):
        raise ValueError("tool files rejected: invalid directory path")
    if (
        not all(hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK"))
        or os.open not in os.supports_dir_fd or os.stat not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks or os.listdir not in os.supports_fd
    ):
        raise ValueError("tool files rejected: safe descriptor operations unavailable")
    entries = {*_SCOPE.tool_filenames, _SCOPE.manifest_filename}
    try:
        before = directory.lstat()
        if not stat.S_ISDIR(before.st_mode):
            raise ValueError("tool files rejected: directory is missing, nonregular or symlinked")
        resolved = directory.resolve(strict=True)
        directory_fd = os.open(
            directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
        )
        try:
            opened = os.fstat(directory_fd)
            if not stat.S_ISDIR(opened.st_mode) or (
                opened.st_dev, opened.st_ino
            ) != (before.st_dev, before.st_ino):
                raise ValueError("tool files rejected: directory replaced during open")
            if set(os.listdir(directory_fd)) != entries:
                raise ValueError("tool files rejected: unexpected directory entries")
            raw_manifest = _read_tool_file(
                directory_fd, _SCOPE.manifest_filename, _SCOPE.max_manifest_bytes
            )
            manifest_digest = hashlib.sha256(raw_manifest).hexdigest()
            if manifest_digest != expected_digest:
                raise ValueError("tool files rejected: manifest digest mismatch")
            try:
                manifest = json.loads(
                    raw_manifest.decode("utf-8"), object_pairs_hook=_unique_manifest_object
                )
            except (ValueError, RecursionError) as error:
                raise ValueError("tool files rejected: invalid manifest JSON") from error
            if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "files"}:
                raise ValueError("tool files rejected: invalid manifest fields")
            if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
                raise ValueError("tool files rejected: invalid manifest schema version")
            files = manifest["files"]
            if not isinstance(files, dict) or set(files) != set(_SCOPE.tool_filenames):
                raise ValueError("tool files rejected: invalid manifest filenames")
            digests: list[tuple[str, str]] = []
            for name in _SCOPE.tool_filenames:
                recorded_digest = _hex_digest(
                    files[name], 64, f"tool files rejected: invalid digest for {name}"
                )
                data = _read_tool_file(directory_fd, name, _SCOPE.max_input_bytes)
                digest = hashlib.sha256(data).hexdigest()
                if digest != recorded_digest:
                    raise ValueError(f"tool files rejected: digest mismatch for {name}")
                digests.append((name, digest))
            if set(os.listdir(directory_fd)) != entries:
                raise ValueError("tool files rejected: directory entries changed")
            return VerifiedToolFiles(resolved, manifest_digest, tuple(sorted(digests)))
        finally:
            os.close(directory_fd)
    except (OSError, UnicodeError, RuntimeError) as error:
        raise ValueError("tool files rejected: filesystem access failed") from error
