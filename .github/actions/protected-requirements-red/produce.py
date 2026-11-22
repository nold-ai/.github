"""Produce native before-fix evidence for the bounded protected subject."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


CORE_REPOSITORY = "nold-ai/specfact-cli"
CORE_REPOSITORY_ID = 1085706003
BASE = "afae348be2989350ac7c56e5a0e1c7c2c8b283a2"
RED = "01f4685bce54889f97d4af0e62542caa685caaa5"
RED_TREE = "3bb51d0811cd127ef397f6bb9c7a07207a34d07a"
GRAPH = "c2f08e33295119e5dba9905f0fb25f02956bb3e2"
GRAPH_TREE = "df03e94253452d1d5c2d8b21f19a004280505397"
GRAPH_DIGEST = "a51e2c490370dc7038b06fc0294a43211cfff38c2e7d23d179ed427b4bc2aea3"
FIXTURE = "69f075819be5e1ceca1446b026b0417f19e584ca"
FIXTURE_TREE = "5d0b8e66c6cd467e6b1ad9d582e24c66b907e205"
CHANGE = "openspec/changes/retire-core-semgrep"
MAPPING_DIGEST = (
    "sha256:975cdd6409a302557d05edfc590c09ae432bdb3e83cd703d97175c0a294e236e"
)
PLAN_DIGEST = "sha256:39e8fd772719092a8e4989a728219e62ec25ae3fc034218b736a9011d747ddac"
PLAN_IDENTITY = (
    "sha256:9e1305345379d7ded355ec1580ab623599c42d2ff801bfa3d2cf9a61e7f20aac"
)


def _object(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _core_repository(record: object) -> bool:
    repo = _object(record)
    return (
        repo.get("full_name") == CORE_REPOSITORY
        and type(repo.get("id")) is int
        and repo["id"] == CORE_REPOSITORY_ID
    )


def authorize_event(event: object) -> str:
    """Select a final head from the one same-repository pull request."""
    event = _object(event)
    pull = _object(event.get("pull_request"))
    base = _object(pull.get("base"))
    head = _object(pull.get("head"))
    head_sha = head.get("sha")
    if (
        type(event.get("number")) is not int
        or event["number"] != 799
        or type(pull.get("number")) is not int
        or pull["number"] != 799
        or pull.get("state") != "open"
        or not all(
            _core_repository(repo)
            for repo in (event.get("repository"), base.get("repo"), head.get("repo"))
        )
        or base.get("ref") != "dev"
        or base.get("sha") != BASE
        or head.get("ref") != "codex/797-retire-core-semgrep"
        or not isinstance(head_sha, str)
        or not re.fullmatch(r"[0-9a-f]{40}", head_sha)
        or head_sha in {BASE, RED}
    ):
        raise ValueError("pull request scope mismatch")
    return head_sha


def verify_plan_identity(plan: object) -> None:
    """Require the same accepted mapping and test plan as native final execution."""
    report = _object(plan)
    if (
        report.get("gate_decision") != "pass"
        or report.get("mapping_digest") != MAPPING_DIGEST
        or report.get("plan_identity_digest") != PLAN_IDENTITY
        or _object(report.get("plan")).get("plan_digest") != PLAN_DIGEST
    ):
        raise ValueError("approved plan identity mismatch")


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        check=True,
        timeout=20,
    ).stdout.strip()


def _verify_checkout(root: Path, sha: str, tree: str) -> None:
    if _git(root, "rev-parse", "HEAD", "HEAD^{tree}").splitlines() != [sha, tree]:
        raise ValueError("checkout identity mismatch")
    if _git(root, "status", "--porcelain", "--untracked-files=no"):
        raise ValueError("tracked checkout files changed")


def verify_inputs(subject: Path, fixture: Path, graph: Path, final_head: str) -> None:
    """Verify all source and dependency snapshots before installing or executing code."""
    _verify_checkout(subject, RED, RED_TREE)
    _verify_checkout(fixture, FIXTURE, FIXTURE_TREE)
    _verify_checkout(graph, GRAPH, GRAPH_TREE)
    if _git(subject, "rev-list", "--parents", "-n", "1", RED).split() != [RED, BASE]:
        raise ValueError("tests-only commit parent mismatch")
    _git(subject, "merge-base", "--is-ancestor", RED, final_head)
    if (
        hashlib.sha256((graph / "requirements/ci/locked.txt").read_bytes()).hexdigest()
        != GRAPH_DIGEST
    ):
        raise ValueError("audited requirements digest mismatch")


def _load(path: Path) -> object:
    with path.open("rb") as stream:
        raw = stream.read(4 * 1024 * 1024 + 1)
    if not raw or len(raw) > 4 * 1024 * 1024:
        raise ValueError("JSON input outside permitted size")
    return json.loads(raw)


def _produce_evidence(subject: Path, fixture: Path, output: Path) -> None:
    """Use the native planner, pytest executor, reconciliation and provenance binder."""
    packages = fixture / "packages"
    fixture_sources = [
        packages / package / "src"
        for package in ("specfact-requirements", "specfact-project")
    ]
    sys.path[:0] = [
        str(subject),
        str(subject / "src"),
        *(str(root) for root in fixture_sources),
    ]
    from scripts.requirements_proof_executor import execute_plan
    from scripts.requirements_proof_provenance import bind_red_proof
    from specfact_requirements.requirements.evidence import write_requirements_evidence
    from specfact_requirements.requirements.lifecycle import (
        ReconciliationContext,
        reconcile_junit,
    )

    output.mkdir(mode=0o700)
    plan_path = output / "requirements-evidence-plan.json"
    if write_requirements_evidence(
        subject,
        output.parent / "planning.json",
        base_ref=BASE,
        required_maturity="test-authored",
        review_evidence_path=subject
        / CHANGE
        / "requirements-proof/review-evidence.json",
        plan_output_path=plan_path,
    ):
        raise ValueError("native plan validation failed")
    plan = _load(plan_path)
    verify_plan_identity(plan)
    os.environ["SPECFACT_MODULES_REPO"] = str(fixture)
    os.environ["SPECFACT_MODULES_ROOTS"] = str(packages)
    junit = output / "requirements-proof.xml"
    if execute_plan(_object(plan), subject, junit) != 1:
        raise ValueError(
            "expected the native RED test process to exit with failing tests"
        )
    report = reconcile_junit(_object(plan), junit, ReconciliationContext("red", RED))
    if report["gate_decision"] != "pass":
        raise ValueError(f"native RED reconciliation failed: {report['findings']}")
    proof_path = output / "requirements-evidence.json"
    proof_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    bind_red_proof(proof_path, subject, base_ref=BASE, junit_path=junit)
    _verify_checkout(subject, RED, RED_TREE)
    _verify_checkout(fixture, FIXTURE, FIXTURE_TREE)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("event", type=Path)
    parser.add_argument("subject", type=Path)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("graph", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    subject, fixture, graph = (
        root.resolve(strict=True) for root in (args.subject, args.fixture, args.graph)
    )
    verify_inputs(subject, fixture, graph, authorize_event(_load(args.event)))
    if args.output is not None:
        _produce_evidence(subject, fixture, args.output.resolve())


if __name__ == "__main__":
    main()
