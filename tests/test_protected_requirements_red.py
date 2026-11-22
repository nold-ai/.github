"""Check the exact PR identity and native proof bindings without GitHub credentials."""

from copy import deepcopy
import importlib.util
from pathlib import Path

import pytest


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / ".github/actions/protected-requirements-red/produce.py"
)
SPEC = importlib.util.spec_from_file_location("protected_requirements_red", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
PRODUCER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PRODUCER)


def _event():
    repository = {"full_name": "nold-ai/specfact-cli", "id": 1085706003}
    return {
        "repository": repository,
        "number": 799,
        "pull_request": {
            "state": "open",
            "number": 799,
            "base": {
                "ref": "dev",
                "sha": "afae348be2989350ac7c56e5a0e1c7c2c8b283a2",
                "repo": repository.copy(),
            },
            "head": {
                "ref": "codex/797-retire-core-semgrep",
                "sha": "c" * 40,
                "repo": repository.copy(),
            },
        },
    }


@pytest.mark.parametrize(
    "path,value",
    [
        (("number",), 798),
        (("number",), 799.0),
        (("repository", "id"), 1110267669),
        (("pull_request", "state"), "closed"),
        (("pull_request", "base", "ref"), "main"),
        (("pull_request", "base", "sha"), "b" * 40),
        (("pull_request", "head", "repo", "full_name"), "fork/specfact-cli"),
        (("pull_request", "head", "ref"), "codex/other"),
        (("pull_request", "head", "sha"), "refs/heads/dev"),
        (("pull_request", "head", "sha"), "01f4685bce54889f97d4af0e62542caa685caaa5"),
    ],
)
def test_exact_pull_request_scope(path, value):
    event = deepcopy(_event())
    assert PRODUCER.authorize_event(event) == "c" * 40
    target = event
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValueError, match="pull request scope"):
        PRODUCER.authorize_event(event)


def test_plan_requires_exact_approved_identity():
    plan = {
        "gate_decision": "pass",
        "mapping_digest": "sha256:975cdd6409a302557d05edfc590c09ae432bdb3e83cd703d97175c0a294e236e",
        "plan_identity_digest": "sha256:9e1305345379d7ded355ec1580ab623599c42d2ff801bfa3d2cf9a61e7f20aac",
        "plan": {
            "plan_digest": "sha256:39e8fd772719092a8e4989a728219e62ec25ae3fc034218b736a9011d747ddac"
        },
    }
    PRODUCER.verify_plan_identity(plan)
    for field in ("gate_decision", "mapping_digest", "plan_identity_digest", "plan"):
        changed = {**plan, field: None}
        with pytest.raises(ValueError, match="approved plan identity"):
            PRODUCER.verify_plan_identity(changed)
