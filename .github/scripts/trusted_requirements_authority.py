"""Validate one expiring member authority for an exact SpecFact pull-request tree."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import ssl
import sys
import urllib.parse
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

HEADER = "SPECFACT_TRUSTED_REQUIREMENTS_AUTHORITY_V1"
API_HOST = "api.github.com"
EXPECTED_REPOSITORY = "nold-ai/specfact-cli"
ALLOWED_BASE_REFS = frozenset({"dev", "main"})
ALLOWED_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})
AUTHORITY_FIELDS = frozenset(
    {
        "authority_version",
        "base_ref",
        "capability",
        "expires_at",
        "head_branch",
        "head_commit",
        "head_tree",
        "pull_request",
        "repository",
        "signer_login",
    }
)
GIT_OBJECT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
MAX_EVENT_BYTES = 1_000_000
MAX_RESPONSE_BYTES = 5_000_000
MAX_COMMENT_BYTES = 8_192
MAX_COMMENT_PAGES = 10
AUTHORITY_LIFETIME = timedelta(days=7)


def _reject() -> ValueError:
    """Return one stable fail-closed error without reflecting attacker-controlled values."""
    return ValueError("trusted authority rejected")


def _object(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise _reject()
    return cast(Mapping[str, object], value)


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise _reject()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise _reject() from error
    if parsed.tzinfo is None:
        raise _reject()
    return parsed.astimezone(UTC)


def _event_boundary(event: Mapping[str, object]) -> dict[str, object]:
    repository = _object(event.get("repository"))
    pull_request = _object(event.get("pull_request"))
    base = _object(pull_request.get("base"))
    head = _object(pull_request.get("head"))
    boundary = {
        "repository": repository.get("full_name"),
        "pull_request": pull_request.get("number"),
        "base_ref": base.get("ref"),
        "head_branch": head.get("ref"),
        "head_commit": head.get("sha"),
    }
    if not (
        boundary["repository"] == EXPECTED_REPOSITORY
        and isinstance(boundary["pull_request"], int)
        and not isinstance(boundary["pull_request"], bool)
        and cast(int, boundary["pull_request"]) > 0
        and boundary["base_ref"] in ALLOWED_BASE_REFS
        and isinstance(boundary["head_branch"], str)
        and bool(boundary["head_branch"])
        and isinstance(boundary["head_commit"], str)
        and GIT_OBJECT_PATTERN.fullmatch(cast(str, boundary["head_commit"])) is not None
    ):
        raise _reject()
    return boundary


def _commit_tree(commit: Mapping[str, object], expected_commit: str) -> str:
    tree = _object(commit.get("tree"))
    commit_sha = commit.get("sha")
    tree_sha = tree.get("sha")
    if (
        commit_sha != expected_commit
        or not isinstance(tree_sha, str)
        or GIT_OBJECT_PATTERN.fullmatch(tree_sha) is None
    ):
        raise _reject()
    return tree_sha


def _parsed_authority(comment: Mapping[str, object]) -> dict[str, object] | None:
    body = comment.get("body")
    user = comment.get("user")
    if (
        not isinstance(body, str)
        or len(body.encode("utf-8")) > MAX_COMMENT_BYTES
        or not isinstance(user, Mapping)
        or comment.get("created_at") != comment.get("updated_at")
        or comment.get("author_association") not in ALLOWED_ASSOCIATIONS
    ):
        return None
    header, separator, encoded = body.partition("\n")
    if header != HEADER or not separator or "\n" in encoded:
        return None
    try:
        decoded = json.loads(encoded)
    except json.JSONDecodeError:
        return None
    if not isinstance(decoded, dict) or frozenset(decoded) != AUTHORITY_FIELDS:
        return None
    authority = cast(dict[str, object], decoded)
    canonical = json.dumps(authority, sort_keys=True, separators=(",", ":"))
    typed_user = cast(Mapping[str, object], user)
    if canonical != encoded or authority.get("signer_login") != typed_user.get("login"):
        return None
    return authority


def _authority_matches(
    authority: Mapping[str, object],
    comment: Mapping[str, object],
    boundary: Mapping[str, object],
    tree_sha: str,
    now: datetime,
) -> bool:
    if (
        type(authority.get("authority_version")) is not int
        or type(authority.get("pull_request")) is not int
    ):
        return False
    try:
        created_at = _timestamp(comment.get("created_at"))
        expires_at = _timestamp(authority.get("expires_at"))
    except ValueError:
        return False
    expected = {
        **boundary,
        "authority_version": 1,
        "capability": "trusted-requirements-authority",
        "head_tree": tree_sha,
    }
    return (
        all(authority.get(key) == value for key, value in expected.items())
        and created_at <= now < expires_at <= created_at + AUTHORITY_LIFETIME
    )


def _matching_authority(
    event: Mapping[str, object],
    comments: Sequence[Mapping[str, object]],
    commit: Mapping[str, object],
    now: datetime,
) -> tuple[Mapping[str, object], dict[str, object]]:
    boundary = _event_boundary(event)
    head_commit = cast(str, boundary["head_commit"])
    tree_sha = _commit_tree(commit, head_commit)
    matches: list[tuple[Mapping[str, object], dict[str, object]]] = []
    for comment in comments:
        authority = _parsed_authority(comment)
        if authority is not None and _authority_matches(
            authority, comment, boundary, tree_sha, now
        ):
            matches.append((comment, authority))
    if len(matches) != 1:
        raise _reject()
    return matches[0]


def validate_authority(
    event: Mapping[str, object],
    comments: Sequence[Mapping[str, object]],
    commit: Mapping[str, object],
    permission: Mapping[str, object],
    now: datetime,
) -> dict[str, object]:
    """Return an immutable receipt for one exact live authority capability."""
    comment, authority = _matching_authority(event, comments, commit, now)
    permission_user = _object(permission.get("user"))
    if permission.get("permission") not in {"write", "admin"} or permission_user.get(
        "login"
    ) != authority.get("signer_login"):
        raise _reject()
    canonical = json.dumps(authority, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return {
        **authority,
        "authority_digest": f"sha256:{hashlib.sha256(canonical).hexdigest()}",
        "comment_id": comment.get("id"),
        "validated_at": now.isoformat().replace("+00:00", "Z"),
    }


def _read_json(path: Path, maximum: int) -> Mapping[str, object]:
    try:
        if path.is_symlink() or path.stat().st_size > maximum:
            raise _reject()
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _reject() from error
    return _object(payload)


def _api_json(path: str, token: str) -> tuple[object, Mapping[str, str]]:
    if (
        not path.startswith("/")
        or path.startswith("//")
        or "\r" in path
        or "\n" in path
    ):
        raise _reject()
    connection: http.client.HTTPSConnection | None = None
    try:
        connection = http.client.HTTPSConnection(
            API_HOST,
            timeout=20,
            context=ssl.create_default_context(),
        )
        connection.request(
            "GET",
            path,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "nold-ai-trusted-requirements-authority",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        response = connection.getresponse()
        if response.status != 200:
            raise _reject()
        payload = response.read(MAX_RESPONSE_BYTES + 1)
        if len(payload) > MAX_RESPONSE_BYTES:
            raise _reject()
        return json.loads(payload), dict(response.getheaders())
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        http.client.HTTPException,
    ) as error:
        raise _reject() from error
    finally:
        if connection is not None:
            connection.close()


def _comments(
    token: str, repository: str, pull_request: int
) -> list[Mapping[str, object]]:
    comments: list[Mapping[str, object]] = []
    for page in range(1, MAX_COMMENT_PAGES + 1):
        payload, _ = _api_json(
            f"/repos/{repository}/issues/{pull_request}/comments?per_page=100&page={page}",
            token,
        )
        if not isinstance(payload, list):
            raise _reject()
        page_items = [_object(item) for item in payload]
        comments.extend(page_items)
        if len(page_items) < 100:
            return comments
    raise _reject()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Authenticate the current pull-request head without executing pull-request bytes."""
    arguments = _build_parser().parse_args(argv)
    try:
        event = _read_json(arguments.event, MAX_EVENT_BYTES)
        boundary = _event_boundary(event)
        token = os.environ.get("GITHUB_TOKEN", "")
        api_url = os.environ.get("GITHUB_API_URL", "")
        if not token or api_url != "https://api.github.com":
            raise _reject()
        repository = cast(str, boundary["repository"])
        pull_request = cast(int, boundary["pull_request"])
        head_commit = cast(str, boundary["head_commit"])
        commit, _ = _api_json(f"/repos/{repository}/git/commits/{head_commit}", token)
        comments = _comments(token, repository, pull_request)
        _, provisional = _matching_authority(
            event, comments, _object(commit), datetime.now(UTC)
        )
        signer = cast(str, provisional["signer_login"])
        encoded_signer = urllib.parse.quote(signer, safe="")
        permission, _ = _api_json(
            f"/repos/{repository}/collaborators/{encoded_signer}/permission",
            token,
        )
        receipt = validate_authority(
            event,
            comments,
            _object(commit),
            _object(permission),
            datetime.now(UTC),
        )
    except ValueError as error:
        sys.stderr.write(f"Trusted Requirements authority failed: {error}\n")
        return 1
    sys.stdout.write(
        "Trusted Requirements authority accepted exact head "
        + cast(str, receipt["head_commit"])
        + ".\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
