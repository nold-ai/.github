from __future__ import annotations

import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / ".github" / "scripts" / "trusted_requirements_authority.py"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "trusted-requirements-authority.yml"
HEADER = "SPECFACT_TRUSTED_REQUIREMENTS_AUTHORITY_V1"
HEAD = "0123456789abcdef0123456789abcdef01234567"
TREE = "89abcdef0123456789abcdef0123456789abcdef"
NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)


def _module() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "trusted_requirements_authority", MODULE_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _authority(**updates: object) -> dict[str, object]:
    authority: dict[str, object] = {
        "authority_version": 1,
        "base_ref": "dev",
        "capability": "trusted-requirements-authority",
        "expires_at": "2026-09-05T12:00:00Z",
        "head_branch": "bugfix/692-clean-replay",
        "head_commit": HEAD,
        "head_tree": TREE,
        "pull_request": 702,
        "repository": "nold-ai/specfact-cli",
        "signer_login": "reviewer",
    }
    authority.update(updates)
    return authority


def _comment(
    authority: dict[str, object] | None = None, **updates: object
) -> dict[str, object]:
    payload = authority or _authority()
    created_at = "2026-09-01T11:30:00Z"
    comment: dict[str, object] = {
        "author_association": "MEMBER",
        "body": HEADER
        + "\n"
        + json.dumps(payload, sort_keys=True, separators=(",", ":")),
        "created_at": created_at,
        "updated_at": created_at,
        "user": {"login": "reviewer"},
    }
    comment.update(updates)
    return comment


def _event() -> dict[str, object]:
    return {
        "repository": {"full_name": "nold-ai/specfact-cli"},
        "pull_request": {
            "number": 702,
            "base": {"ref": "dev"},
            "head": {
                "ref": "bugfix/692-clean-replay",
                "sha": HEAD,
            },
        },
    }


def test_exact_unedited_member_authority_accepts_complete_current_tree() -> None:
    module = _module()

    receipt = module.validate_authority(
        _event(),
        [_comment()],
        {"sha": HEAD, "tree": {"sha": TREE}},
        {"permission": "write", "user": {"login": "reviewer"}},
        NOW,
    )

    assert receipt["head_commit"] == HEAD
    assert receipt["head_tree"] == TREE
    assert receipt["signer_login"] == "reviewer"
    assert receipt["authority_digest"].startswith("sha256:")


@pytest.mark.parametrize(
    "comment",
    (
        _comment(updated_at="2026-09-01T11:31:00Z"),
        _comment(author_association="CONTRIBUTOR"),
        _comment(user={"login": "someone-else"}),
        _comment(_authority(expires_at="2026-09-01T11:59:59Z")),
        _comment(_authority(expires_at="2026-09-09T11:30:01Z")),
        _comment(_authority(authority_version=True)),
        _comment(_authority(head_commit="f" * 40)),
        _comment(_authority(head_tree="e" * 40)),
    ),
)
def test_stale_edited_untrusted_or_mismatched_authority_is_rejected(
    comment: dict[str, object],
) -> None:
    module = _module()

    with pytest.raises(ValueError, match="trusted authority rejected"):
        module.validate_authority(
            _event(),
            [comment],
            {"sha": HEAD, "tree": {"sha": TREE}},
            {"permission": "write", "user": {"login": "reviewer"}},
            NOW,
        )


def test_noncanonical_json_is_rejected() -> None:
    module = _module()
    comment = _comment()
    comment["body"] = HEADER + "\n" + json.dumps(_authority(), sort_keys=False)

    with pytest.raises(ValueError, match="trusted authority rejected"):
        module.validate_authority(
            _event(),
            [comment],
            {"sha": HEAD, "tree": {"sha": TREE}},
            {"permission": "write", "user": {"login": "reviewer"}},
            NOW,
        )


def test_multiple_matching_capabilities_are_rejected_as_ambiguous() -> None:
    module = _module()

    with pytest.raises(ValueError, match="trusted authority rejected"):
        module.validate_authority(
            _event(),
            [_comment(), _comment()],
            {"sha": HEAD, "tree": {"sha": TREE}},
            {"permission": "write", "user": {"login": "reviewer"}},
            NOW,
        )


@pytest.mark.parametrize(
    "permission",
    (
        {"permission": "read", "user": {"login": "reviewer"}},
        {"permission": "none", "user": {"login": "reviewer"}},
        {"permission": "write", "user": {"login": "former-reviewer"}},
    ),
)
def test_removed_read_only_or_mismatched_signer_is_rejected_live(
    permission: dict[str, object],
) -> None:
    module = _module()

    with pytest.raises(ValueError, match="trusted authority rejected"):
        module.validate_authority(
            _event(),
            [_comment()],
            {"sha": HEAD, "tree": {"sha": TREE}},
            permission,
            NOW,
        )


def test_required_workflow_never_checks_out_or_executes_candidate_content() -> None:
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "pull_request:" in workflow
    assert "pull_request_target" not in workflow
    assert "github.event.pull_request.head" not in workflow
    assert "nold-ai/.github" in workflow
    assert "github.workflow_sha" in workflow
    assert "trusted_requirements_authority.py" in workflow
    assert "persist-credentials: false" in workflow


def test_api_transport_is_fixed_to_github_and_rejects_absolute_urls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    requests: list[tuple[str, str]] = []

    class Response:
        status = 200

        @staticmethod
        def read(_maximum: int) -> bytes:
            return b"{}"

        @staticmethod
        def getheaders() -> list[tuple[str, str]]:
            return []

    class Connection:
        def __init__(self, host: str, **_kwargs: object) -> None:
            assert host == "api.github.com"

        @staticmethod
        def request(method: str, path: str, **_kwargs: object) -> None:
            requests.append((method, path))

        @staticmethod
        def getresponse() -> Response:
            return Response()

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(module.http.client, "HTTPSConnection", Connection)
    monkeypatch.setattr(module.ssl, "create_default_context", object)

    assert module._api_json("/rate_limit", "token") == ({}, {})
    assert requests == [("GET", "/rate_limit")]

    with pytest.raises(ValueError, match="trusted authority rejected"):
        module._api_json("https://attacker.invalid/", "token")

    assert requests == [("GET", "/rate_limit")]
