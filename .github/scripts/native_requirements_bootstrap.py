from __future__ import annotations

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
    raise NotImplementedError


def authorize_red_context(
    expected_policy: str, snapshot: Mapping[str, object], now: datetime
) -> AuthorizedRedContext:
    """Authorize fixed R and separate E/P context, without accepting native proof."""
    raise NotImplementedError


def verify_tool_files(
    directory: Path, expected_manifest_sha256: str
) -> VerifiedToolFiles:
    """Bind bounded local bytes to an independent digest, without tool authority."""
    raise NotImplementedError
