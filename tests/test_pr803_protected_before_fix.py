"""Validate the GitHub event scope of the audited #803 proof."""

import importlib.util
from pathlib import Path

import pytest


def _producer():
    path = Path(__file__).resolve().parents[1] / ".github/actions/protected-requirements-red-803/produce.py"
    spec = importlib.util.spec_from_file_location("pr803_protected_before_fix", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def event():
    repo = {"id": 1085706003, "full_name": "nold-ai/specfact-cli"}
    return {
        "number": 803,
        "repository": repo.copy(),
        "pull_request": {
            "number": 803,
            "state": "open",
            "base": {
                "ref": "main",
                "sha": "5262efb0881e4fac7697d629b0530250342bc656",
                "repo": repo.copy(),
            },
            "head": {
                "ref": "codex/trusted-signed-topic-promotion",
                "sha": "a" * 40,
                "repo": repo.copy(),
            },
        },
    }


def test_producer_accepts_only_the_expected_live_pr(event):
    assert _producer().authorize_event(event) == "a" * 40


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("number",), 799),
        (("pull_request", "number"), 804),
        (("pull_request", "state"), "closed"),
        (("pull_request", "base", "ref"), "dev"),
        (("pull_request", "base", "sha"), "b" * 40),
        (("pull_request", "head", "ref"), "other/branch"),
        (("pull_request", "head", "repo", "id"), 42),
        (("pull_request", "head", "sha"), "c2421f77c63470f42d2274ecec14f11b02417a5b"),
    ],
)
def test_producer_refuses_a_different_event(event, path, value):
    target = event
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value

    with pytest.raises(ValueError, match="pull request scope mismatch"):
        _producer().authorize_event(event)
