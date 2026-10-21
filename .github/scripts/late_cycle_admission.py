from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import io
import json
import math
import os
import re
import stat
import subprocess
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

HEADER = "SPECFACT_LATE_CYCLE_PROVENANCE_ADMISSION_V1"
REPO = "nold-ai/specfact-cli"
POLICY_REPO = "nold-ai/.github"
WORKFLOW = ".github/workflows/requirements-evidence.yml"
SOURCE = "openspec/changes/isolate-semgrep-security-runtime"
SCOPE = {
    "repository": REPO,
    "issue": 780,
    "change_id": "isolate-semgrep-security-runtime",
    "base_ref": "dev",
    "head_branch": "codex/dependency-hotfix-admission",
    "capability": "late-cycle-provenance-admission",
    "obligation": "native-failing-first-provenance",
}
SELECTORS = (
    "tests/unit/scripts/test_requirements_late_cycle_workflow.py::test_all_three_lanes_preserve_native_bytes_and_enforce_policy_exit",
    "tests/unit/scripts/test_requirements_late_cycle_workflow.py::test_fresh_and_final_preserve_scope_and_invalid_red_guards",
    "tests/unit/scripts/test_requirements_late_cycle_workflow.py::test_origin_attestation_survives_producer_failure",
    "tests/unit/scripts/test_security_audit_gate.py::test_committed_mcp_exception_is_exact_and_time_bounded[exact-cve]",
    "tests/unit/scripts/test_security_audit_gate.py::test_committed_mcp_exception_is_exact_and_time_bounded[exact-ghsa]",
    "tests/unit/scripts/test_security_audit_gate.py::test_committed_mcp_exception_is_exact_and_time_bounded[expired]",
    "tests/unit/scripts/test_security_audit_gate.py::test_committed_mcp_exception_is_exact_and_time_bounded[expiry-day]",
    "tests/unit/scripts/test_security_audit_gate.py::test_committed_mcp_exception_is_exact_and_time_bounded[future-review]",
    "tests/unit/scripts/test_security_audit_gate.py::test_committed_mcp_exception_is_exact_and_time_bounded[mixed-advisories]",
    "tests/unit/scripts/test_security_audit_gate.py::test_committed_mcp_exception_is_exact_and_time_bounded[other-version]",
    "tests/unit/scripts/test_security_audit_gate.py::test_committed_mcp_exception_is_exact_and_time_bounded[skipped]",
    "tests/unit/scripts/test_security_audit_gate.py::test_committed_mcp_exception_is_exact_and_time_bounded[unrelated-advisory]",
    "tests/unit/security/test_frozen_dependency_artifacts.py::test_frozen_certifi_bundle_excludes_compromised_root",
    "tests/unit/security/test_release_promotion_security_gates.py::test_frozen_graph_uses_official_semgrep_with_bounded_mcp_exception",
)
NATIVE_FILES = (
    "requirements-evidence.json",
    "requirements-evidence-plan.json",
    "requirements-proof.xml",
)
SOURCE_DIGEST = (
    "sha256:c3fd8ebfa8b872f5ba12eee146ae2bdf9fa60a4c9c9a318450d528c4b4215318"
)
SOURCE_BYTES_DIGEST = (
    "sha256:c87d29e8f58006fc37632279ca6799b19ebfe7c9f032750c25aa2bdb1e5f4135"
)
MAPPING_DIGEST = (
    "sha256:f35a011f01afd89ec0bed94fe840233ed6af4ff4a8ac4f707026146ab8127223"
)
PLAN_DIGEST = "sha256:1982a9fe578424763d42e4eb5bdde669235930522211e9f3a25255a10852cb3c"
MAX_FILE = 4 * 1024 * 1024
MAX_ZIP = 16 * 1024 * 1024
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\Z")
EVIDENCE_FIELDS = {
    "report_digest",
    "plan_file_digest",
    "junit_digest",
    "source_mapping_digest",
    "source_bytes_digest",
    "mapping_digest",
    "plan_digest",
    "allowed_finding",
}
REQUEST_FIELDS = (
    set(SCOPE)
    | EVIDENCE_FIELDS
    | {
        "pull_request",
        "version",
        "head_commit",
        "head_tree",
        "policy_revision",
        "run_id",
        "run_attempt",
        "artifact_id",
        "origin_artifact_id",
        "artifact_digest",
        "origin_digest",
        "workflow_sha",
        "selectors",
        "missing_native_red",
        "signer_login",
        "issued_at",
        "expires_at",
    }
)
ORIGIN_FIELDS = {
    "schema_version",
    "repository",
    "run_id",
    "run_attempt",
    "head_commit",
    "workflow_path",
    "workflow_sha",
    "artifact_id",
    "artifact_digest",
}


class Refused(ValueError):
    pass


def require(condition: bool, code: str) -> None:
    if not condition:
        raise Refused(code)


def canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def requirements_schema2_digest(value: object) -> str:

    def tagged(item: object) -> list[object]:
        if item is None:
            return ["none"]
        if type(item) is bool:
            return ["bool", item]
        if type(item) is str:
            return ["str", item]
        if type(item) is int:
            return ["int", str(item)]
        if type(item) is float:
            return ["float", item.hex()]
        if type(item) is list:
            return ["list", [tagged(child) for child in item]]
        require(type(item) is dict, "native-digest-type")
        entries = [[tagged(key), tagged(child)] for key, child in item.items()]
        return [
            "mapping",
            sorted(
                entries, key=lambda entry: (canonical(entry[0]), canonical(entry[1]))
            ),
        ]

    return digest(canonical(tagged(value)))


def object_value(value: object) -> dict[str, Any]:
    require(type(value) is dict, "object-required")
    return value


def json_value(raw: bytes) -> Any:
    require(len(raw) <= MAX_FILE, "json-size")

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            require(key not in result, "json-duplicate")
            result[key] = value
        return result

    try:
        result = json.loads(
            raw,
            object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(Refused("json-number")),
        )
        pending = [(result, 0)]
        count = 0
        while pending:
            value, depth = pending.pop()
            count += 1
            require(not isinstance(value, float) or math.isfinite(value), "json-number")
            require(depth <= 32 and count <= 20000, "json-complexity")
            if isinstance(value, dict):
                pending.extend((v, depth + 1) for v in value.values())
            elif isinstance(value, list):
                pending.extend((v, depth + 1) for v in value)
        return result
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Refused("json-invalid") from error


def json_object(raw: bytes) -> dict[str, Any]:
    return object_value(json_value(raw))


def read_file(path: Path) -> bytes:
    require(not path.is_symlink() and path.is_file(), "file-kind")
    with path.open("rb") as stream:
        raw = stream.read(MAX_FILE + 1)
    require(len(raw) <= MAX_FILE, "file-size")
    return raw


def utc(value: object) -> datetime:
    require(isinstance(value, str), "timestamp-type")
    try:
        result = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        require(result.strftime("%Y-%m-%dT%H:%M:%SZ") == value, "timestamp-canonical")
        return result
    except ValueError as error:
        raise Refused("timestamp-invalid") from error


def selectors(value: object) -> None:
    require(
        type(value) is list and all(type(x) is str for x in value), "selectors-type"
    )
    require(sorted(value) == list(SELECTORS), "selectors-inventory")


def validate_junit(raw: bytes) -> None:
    require(
        len(raw) <= MAX_FILE
        and b"<!DOCTYPE" not in raw.upper()
        and b"<!ENTITY" not in raw.upper()
        and b"\x00" not in raw,
        "junit-unsafe",
    )
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as error:
        raise Refused("junit-invalid") from error
    pending = [(root, 0)]
    count = 0
    while pending:
        element, depth = pending.pop()
        count += 1
        require(depth <= 12 and count <= 1000, "junit-complexity")
        require(
            element.tag
            in {
                "testsuites",
                "testsuite",
                "testcase",
                "properties",
                "property",
                "system-out",
                "system-err",
            },
            "junit-result",
        )
        pending.extend((child, depth + 1) for child in element)
    require(
        root.tag == "testsuites" and len(root.findall("testsuite")) == 1, "junit-suites"
    )
    suite = root.find("testsuite")
    require(
        suite is not None
        and suite.get("tests") == str(len(SELECTORS))
        and all(suite.get(x) == "0" for x in ("failures", "errors", "skipped")),
        "junit-counts",
    )
    nodes = []
    for case in root.iter("testcase"):
        found = [
            x.get("value")
            for x in case.findall("./properties/property")
            if x.get("name") == "specfact.selector"
        ]
        require(len(found) == 1, "junit-selector")
        node = (
            case.get("classname", "").replace(".", "/") + ".py::" + case.get("name", "")
        )
        require(found[0] == node, "junit-identity")
        nodes.append(node)
    selectors(nodes)


def validate_packet(
    report_raw: bytes, plan_raw: bytes, junit_raw: bytes, head: str
) -> dict[str, Any]:
    report, plan = json_object(report_raw), json_object(plan_raw)
    expected = {
        "schema_version": "2",
        "verdict": "failed",
        "gate_decision": "fail",
        "delivery_status": "incomplete",
        "observed_maturity": "incomplete",
        "implementation_evidence": "not-available",
        "required_maturity": "verified",
        "mapping_digest": MAPPING_DIGEST,
        "plan_digest": PLAN_DIGEST,
    }
    require(
        all(report.get(k) == v for k, v in expected.items()), "native-failed-contract"
    )
    require(
        report.get("findings")
        in (["prior-red-proof-invalid"], ["prior-red-proof-missing"]),
        "native-extra-findings",
    )
    require(
        plan.get("schema_version") == "2"
        and plan.get("gate_decision") == "pass"
        and plan.get("verdict") == "passed"
        and plan.get("mapping_digest") == MAPPING_DIGEST,
        "plan-contract",
    )
    require(
        plan.get("sources") == [{"source": SOURCE, "mapping_digest": SOURCE_DIGEST}],
        "source-mapping",
    )
    execution = object_value(report.get("execution_plan"))
    require(execution == plan.get("plan") == report.get("plan"), "plan-correspondence")
    require(
        execution.get("mapping_digest") == MAPPING_DIGEST
        and execution.get("plan_digest") == PLAN_DIGEST,
        "plan-identity",
    )
    require(
        requirements_schema2_digest(
            {k: v for k, v in execution.items() if k != "plan_digest"}
        )
        == PLAN_DIGEST,
        "plan-bytes",
    )
    cases = execution.get("cases")
    require(type(cases) is list, "plan-cases")
    selectors([object_value(case).get("node_id") for case in cases])
    proof = object_value(report.get("execution_proof"))
    require(
        proof.get("run_stage") == "final"
        and proof.get("source_ref") == head
        and proof.get("junit_digest") == digest(junit_raw),
        "proof-identity",
    )
    selectors(proof.get("selectors"))
    validate_junit(junit_raw)
    return {
        "report_digest": digest(report_raw),
        "plan_file_digest": digest(plan_raw),
        "junit_digest": digest(junit_raw),
        "source_mapping_digest": SOURCE_DIGEST,
        "source_bytes_digest": SOURCE_BYTES_DIGEST,
        "mapping_digest": MAPPING_DIGEST,
        "plan_digest": PLAN_DIGEST,
        "allowed_finding": report["findings"][0],
    }


def validate_request(request: dict[str, Any], now: datetime) -> None:
    require(set(request) == REQUEST_FIELDS, "request-fields")
    require(
        all(
            type(request.get(k)) is type(v) and request[k] == v
            for k, v in SCOPE.items()
        ),
        "request-scope",
    )
    require(
        type(request["version"]) is int
        and request["version"] == 1
        and request["missing_native_red"] is True,
        "request-version",
    )
    for key in ("head_commit", "head_tree", "policy_revision", "workflow_sha"):
        require(
            type(request[key]) is str and bool(SHA.fullmatch(request[key])),
            "request-sha",
        )
    for key in (
        "pull_request",
        "run_id",
        "run_attempt",
        "artifact_id",
        "origin_artifact_id",
    ):
        require(type(request[key]) is int and 0 < request[key] < 2**63, "request-id")
    for key in EVIDENCE_FIELDS - {"allowed_finding"} | {
        "artifact_digest",
        "origin_digest",
    }:
        require(
            type(request[key]) is str and bool(DIGEST.fullmatch(request[key])),
            "request-digest",
        )
    require(
        request["allowed_finding"]
        in {"prior-red-proof-invalid", "prior-red-proof-missing"},
        "request-finding",
    )
    require(
        request["source_mapping_digest"] == SOURCE_DIGEST
        and request["source_bytes_digest"] == SOURCE_BYTES_DIGEST
        and request["mapping_digest"] == MAPPING_DIGEST
        and request["plan_digest"] == PLAN_DIGEST,
        "request-mapping",
    )
    selectors(request["selectors"])
    require(
        type(request["signer_login"]) is str
        and bool(LOGIN.fullmatch(request["signer_login"])),
        "request-signer",
    )
    issued, expires = utc(request["issued_at"]), utc(request["expires_at"])
    require(issued <= now < expires <= issued + timedelta(days=7), "request-expiry")


def approval(comment: dict[str, Any], now: datetime) -> dict[str, Any]:
    body = comment.get("body")
    require(type(body) is str and len(body.encode()) < 16384, "approval-size")
    header, separator, encoded = body.partition("\n")
    require(header == HEADER and separator == "\n", "approval-header")
    request = json_object(encoded.encode())
    require(canonical(request).decode() == encoded, "approval-canonical")
    validate_request(request, now)
    user = object_value(comment.get("user"))
    require(
        user.get("type") == "User"
        and user.get("login") == request["signer_login"]
        and comment.get("author_association") in {"OWNER", "MEMBER", "COLLABORATOR"},
        "approval-human",
    )
    require(comment.get("created_at") == comment.get("updated_at"), "approval-edited")
    created = utc(comment.get("created_at"))
    require(
        utc(request["issued_at"])
        <= created
        <= now
        < utc(request["expires_at"])
        <= created + timedelta(days=7),
        "approval-expiry",
    )
    require(type(comment.get("id")) is int and comment["id"] > 0, "approval-id")
    return request


def unpack(raw: bytes, names: set[str]) -> dict[str, bytes]:
    require(len(raw) <= MAX_ZIP, "archive-size")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            require(
                len(entries) == len(names)
                and {entry.filename for entry in entries} == names,
                "archive-members",
            )
            require(
                sum(entry.file_size for entry in entries) <= MAX_ZIP, "archive-expanded"
            )
            result = {}
            for entry in entries:
                mode = entry.external_attr >> 16
                require(
                    not entry.is_dir()
                    and (stat.S_IFMT(mode) in {0, stat.S_IFREG})
                    and not entry.flag_bits & 1
                    and entry.compress_type
                    in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                    and entry.file_size <= MAX_FILE,
                    "archive-entry",
                )
                with archive.open(entry) as stream:
                    data = stream.read(MAX_FILE + 1)
                require(len(data) == entry.file_size, "archive-length")
                result[entry.filename] = data
            return result
    except (zipfile.BadZipFile, RuntimeError, OSError) as error:
        raise Refused("archive-invalid") from error


class GitHub:
    def __init__(self) -> None:
        self.token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        require(bool(self.token), "api-token")
        require(
            os.environ.get("GITHUB_API_URL", "https://api.github.com")
            == "https://api.github.com",
            "api-host",
        )

    def get(self, path: str, *, archive: bool = False) -> bytes:
        require(
            path.startswith("/repos/")
            and "\r" not in path
            and "\n" not in path
            and "#" not in path,
            "api-path",
        )
        host, target = "api.github.com", path
        for redirect in range(3):
            headers = {
                "Accept": "application/vnd.github+json",
                "User-Agent": "specfact-late-cycle-policy",
                "X-GitHub-Api-Version": "2022-11-28",
            }
            if redirect == 0:
                headers["Authorization"] = "Bearer " + self.token
            connection = http.client.HTTPSConnection(host, timeout=30)
            try:
                connection.request("GET", target, headers=headers)
                response = connection.getresponse()
                if archive and response.status in {301, 302, 303, 307, 308}:
                    location = urllib.parse.urlsplit(response.getheader("Location", ""))
                    require(
                        location.scheme == "https"
                        and location.hostname is not None
                        and (
                            location.hostname.endswith(".blob.core.windows.net")
                            or location.hostname.endswith(
                                ".actions.githubusercontent.com"
                            )
                        )
                        and location.port is None
                        and location.username is None
                        and location.password is None
                        and not location.fragment,
                        "archive-redirect",
                    )
                    host, target = (
                        location.hostname,
                        urllib.parse.urlunsplit(
                            ("", "", location.path, location.query, "")
                        ),
                    )
                    continue
                require(response.status == 200, "api-status")
                maximum = MAX_ZIP if archive else MAX_FILE
                raw = response.read(maximum + 1)
                require(len(raw) <= maximum, "api-size")
                return raw
            finally:
                connection.close()
        raise Refused("api-redirect-limit")

    def obj(self, path: str) -> dict[str, Any]:
        return json_object(self.get(path))

    def contents(self, path: str, revision: str, repository: str = REPO) -> bytes:
        value = self.obj(f"/repos/{repository}/contents/{path}?ref={revision}")
        require(
            value.get("encoding") == "base64" and type(value.get("content")) is str,
            "contents-encoding",
        )
        try:
            raw = base64.b64decode(value["content"].replace("\n", ""), validate=True)
        except ValueError as error:
            raise Refused("contents-base64") from error
        require(len(raw) <= MAX_FILE, "contents-size")
        return raw

    def comments(self, pull_request: int) -> list[dict[str, Any]]:
        result = []
        for page in range(1, 11):
            raw = self.get(
                f"/repos/{REPO}/issues/{pull_request}/comments?per_page=100&page={page}"
            )
            values = json_value(raw)
            require(type(values) is list and len(values) <= 100, "comments-shape")
            result.extend(object_value(value) for value in values)
            if len(values) < 100:
                return result
        raise Refused("comments-pagination")


def live_subject(api: GitHub, event: dict[str, Any]) -> dict[str, Any]:
    require(
        object_value(event.get("repository")).get("full_name") == REPO,
        "event-repository",
    )
    candidate = object_value(event.get("pull_request"))
    require(
        type(candidate.get("number")) is int and 0 < candidate["number"] < 2**63,
        "event-pr",
    )
    number = candidate["number"]
    listing = json_value(
        api.get(
            f"/repos/{REPO}/pulls?state=open&base=dev&head=nold-ai:{SCOPE['head_branch']}&per_page=100"
        )
    )
    require(
        type(listing) is list
        and len(listing) == 1
        and object_value(listing[0]).get("number") == number,
        "subject-unique",
    )
    live = api.obj(f"/repos/{REPO}/pulls/{number}")
    require(live.get("state") == "open" and live.get("number") == number, "live-pr")
    for item in (candidate, live):
        require(
            object_value(item.get("base")).get("ref") == "dev"
            and object_value(item.get("head")).get("ref") == SCOPE["head_branch"]
            and object_value(object_value(item.get("head")).get("repo")).get(
                "full_name"
            )
            == REPO,
            "subject-scope",
        )
    head = object_value(live.get("head")).get("sha")
    require(
        type(head) is str
        and bool(SHA.fullmatch(head))
        and object_value(candidate.get("head")).get("sha") == head,
        "subject-head",
    )
    commit = api.obj(f"/repos/{REPO}/git/commits/{head}")
    tree = object_value(commit.get("tree")).get("sha")
    require(
        commit.get("sha") == head and type(tree) is str and bool(SHA.fullmatch(tree)),
        "subject-tree",
    )
    return {
        "pull_request": number,
        "head_commit": head,
        "head_tree": tree,
        "merge_commit_sha": live.get("merge_commit_sha"),
    }


def deployed(api: GitHub, revision: str) -> None:
    require(type(revision) is str and bool(SHA.fullmatch(revision)), "policy-revision")
    comparison = api.obj(f"/repos/{POLICY_REPO}/compare/{revision}...main")
    require(
        comparison.get("status") in {"ahead", "identical"}
        and object_value(comparison.get("merge_base_commit")).get("sha") == revision,
        "policy-not-deployed",
    )
    remote = api.contents(
        ".github/scripts/late_cycle_admission.py", revision, POLICY_REPO
    )
    require(remote == Path(__file__).read_bytes(), "policy-code-mismatch")


def artifact(
    api: GitHub, artifact_id: int, run_id: int, head: str, name: str
) -> tuple[dict[str, Any], bytes]:
    value = api.obj(f"/repos/{REPO}/actions/artifacts/{artifact_id}")
    run = object_value(value.get("workflow_run"))
    require(
        value.get("id") == artifact_id
        and value.get("name") == name
        and value.get("expired") is False
        and run.get("id") == run_id
        and run.get("head_sha") == head,
        "artifact-association",
    )
    require(
        type(value.get("size_in_bytes")) is int
        and 0 < value["size_in_bytes"] <= MAX_ZIP,
        "artifact-size",
    )
    raw = api.get(f"/repos/{REPO}/actions/artifacts/{artifact_id}/zip", archive=True)
    require(value.get("digest") == digest(raw), "artifact-digest")
    return value, raw


def verify_origin(origin: bytes, bundle: bytes, workflow_sha: str) -> None:
    with tempfile.TemporaryDirectory(prefix="specfact-native-origin-") as directory:
        root = Path(directory)
        (root / "origin.json").write_bytes(origin)
        (root / "origin.bundle.jsonl").write_bytes(bundle)
        command = [
            "gh",
            "attestation",
            "verify",
            str(root / "origin.json"),
            "--bundle",
            str(root / "origin.bundle.jsonl"),
            "--repo",
            REPO,
            "--signer-workflow",
            REPO + "/" + WORKFLOW,
            "--signer-digest",
            workflow_sha,
            "--source-digest",
            workflow_sha,
            "--deny-self-hosted-runners",
        ]
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=90,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise Refused("origin-verifier-unavailable") from error
        require(result.returncode == 0, "origin-signature")


def historical(
    api: GitHub,
    subject: dict[str, Any],
    run_id: int,
    attempt: int,
    artifact_id: int,
    origin_id: int,
) -> dict[str, Any]:
    require(type(attempt) is int and attempt > 0, "run-attempt")
    run = api.obj(f"/repos/{REPO}/actions/runs/{run_id}/attempts/{attempt}")
    require(
        type(run.get("run_attempt")) is int and run["run_attempt"] == attempt,
        "run-attempt",
    )
    head = subject["head_commit"]
    require(
        run.get("id") == run_id
        and run.get("event") == "pull_request"
        and run.get("path") == WORKFLOW
        and run.get("head_sha") == head
        and run.get("head_branch") == SCOPE["head_branch"]
        and object_value(run.get("repository")).get("full_name") == REPO
        and object_value(run.get("head_repository")).get("full_name") == REPO,
        "run-association",
    )
    prs = run.get("pull_requests")
    require(
        type(prs) is list
        and any(
            object_value(pr).get("number") == subject["pull_request"]
            and object_value(object_value(pr).get("head")).get("sha") == head
            for pr in prs
        ),
        "run-pr",
    )
    jobs = api.obj(
        f"/repos/{REPO}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100"
    )
    entries = jobs.get("jobs")
    require(
        type(entries) is list
        and jobs.get("total_count") == len(entries)
        and len(entries) <= 100,
        "jobs-pagination",
    )
    matched = [
        job
        for job in entries
        if object_value(job).get("name") == "Native Requirements Origin"
    ]
    require(
        len(matched) == 1
        and matched[0].get("conclusion") == "success"
        and matched[0].get("run_id") == run_id,
        "origin-job",
    )
    _, origin_zip = artifact(
        api, origin_id, run_id, head, f"requirements-native-origin-{run_id}-{attempt}"
    )
    files = unpack(origin_zip, {"origin.json", "origin.bundle.jsonl"})
    origin = json_object(files["origin.json"])
    require(
        set(origin) == ORIGIN_FIELDS and canonical(origin) == files["origin.json"],
        "origin-fields",
    )
    expected = {
        "schema_version": 1,
        "repository": REPO,
        "run_id": run_id,
        "run_attempt": attempt,
        "head_commit": head,
        "workflow_path": WORKFLOW,
        "artifact_id": artifact_id,
    }
    require(
        all(
            type(origin.get(k)) is type(v) and origin[k] == v
            for k, v in expected.items()
        ),
        "origin-association",
    )
    revision = origin.get("workflow_sha")
    require(
        type(revision) is str and bool(SHA.fullmatch(revision)), "origin-workflow-sha"
    )
    require(revision in {head, subject["merge_commit_sha"]}, "origin-source")
    if revision != head:
        merge = api.obj(f"/repos/{REPO}/git/commits/{revision}")
        require(
            merge.get("sha") == revision
            and head
            in [object_value(parent).get("sha") for parent in merge.get("parents", [])],
            "origin-merge",
        )
    require(
        api.contents(WORKFLOW, revision) == api.contents(WORKFLOW, head),
        "origin-workflow-bytes",
    )
    verify_origin(files["origin.json"], files["origin.bundle.jsonl"], revision)
    _, native = artifact(api, artifact_id, run_id, head, "requirements-evidence")
    require(origin.get("artifact_digest") == digest(native), "origin-native-digest")
    native_files = unpack_native(native)
    evidence = validate_packet(*(native_files[name] for name in NATIVE_FILES), head)
    require(
        digest(api.contents(SOURCE + "/requirements-evidence.yaml", head))
        == SOURCE_BYTES_DIGEST,
        "live-source-mapping",
    )
    return {
        **evidence,
        "run_id": run_id,
        "run_attempt": attempt,
        "artifact_id": artifact_id,
        "origin_artifact_id": origin_id,
        "artifact_digest": digest(native),
        "origin_digest": digest(files["origin.json"]),
        "workflow_sha": revision,
    }


def unpack_native(raw: bytes) -> dict[str, bytes]:
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            names = {entry.filename for entry in archive.infolist()}
    except zipfile.BadZipFile as error:
        raise Refused("archive-invalid") from error
    allowed = set(NATIVE_FILES) | {
        "requirements-evidence.md",
        "requirements-promotion-reuse.json",
        "approved-legacy-tdd-ledger.md",
        "legacy-tdd-evidence.json",
    }
    require(
        set(NATIVE_FILES) <= names <= allowed and len(names) <= 8,
        "native-archive-members",
    )
    return unpack(raw, names)


def matching_approval(
    api: GitHub, subject: dict[str, Any], revision: str, now: datetime
) -> tuple[dict[str, Any], dict[str, Any]]:
    matches = []
    for comment in api.comments(subject["pull_request"]):
        if not str(comment.get("body", "")).startswith(HEADER):
            continue
        try:
            request = approval(comment, now)
        except Refused:
            continue
        if (
            request["pull_request"] == subject["pull_request"]
            and request["head_commit"] == subject["head_commit"]
            and request["head_tree"] == subject["head_tree"]
            and request["policy_revision"] == revision
        ):
            matches.append((comment, request))
    require(len(matches) == 1, "approval-missing-or-ambiguous")
    comment, request = matches[0]
    permission = api.obj(
        f"/repos/{REPO}/collaborators/{request['signer_login']}/permission"
    )
    user = object_value(permission.get("user"))
    require(
        permission.get("permission") in {"write", "admin"}
        and user.get("login") == request["signer_login"]
        and user.get("type") == "User",
        "approval-permission",
    )
    return comment, request


def decide(
    api: GitHub,
    event: dict[str, Any],
    report: bytes,
    plan: bytes,
    junit: bytes,
    revision: str,
    now: datetime,
) -> dict[str, Any]:
    subject = live_subject(api, event)
    deployed(api, revision)
    comment, request = matching_approval(api, subject, revision, now)
    observed = historical(
        api,
        subject,
        request["run_id"],
        request["run_attempt"],
        request["artifact_id"],
        request["origin_artifact_id"],
    )
    require(
        all(request[k] == value for k, value in observed.items()), "historical-binding"
    )
    current = validate_packet(report, plan, junit, subject["head_commit"])
    for key in (
        "source_mapping_digest",
        "source_bytes_digest",
        "mapping_digest",
        "plan_digest",
        "allowed_finding",
    ):
        require(current[key] == request[key], "current-binding")
    require(live_subject(api, event) == subject, "subject-race")
    final_comment, final_request = matching_approval(
        api, subject, revision, datetime.now(UTC)
    )
    require(final_comment == comment and final_request == request, "approval-race")
    return {
        "outcome": "HumanApprovedLateCycle",
        "audit_only": True,
        "missing_native_red": True,
        "request_digest": digest(canonical(request)),
        "comment_id": comment["id"],
        "head_commit": subject["head_commit"],
        "head_tree": subject["head_tree"],
        "policy_revision": revision,
        "native_gate_decision": "fail",
        "current_evidence": current,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate narrowly scoped late-cycle provenance admission."
    )
    sub = parser.add_subparsers(dest="operation", required=True)
    for operation in ("request", "decide"):
        command = sub.add_parser(operation)
        for name in ("event", "policy-revision", "output"):
            command.add_argument("--" + name, required=True)
        if operation == "decide":
            for name in ("report", "plan", "junit"):
                command.add_argument("--" + name, required=True)
        else:
            for name in ("run-id", "run-attempt", "artifact-id", "origin-artifact-id"):
                command.add_argument("--" + name, type=int, required=True)
            for name in ("expires-at", "signer"):
                command.add_argument("--" + name, required=True)
    args = parser.parse_args()
    output = Path(args.output)
    inputs = [Path(args.event)]
    if args.operation == "decide":
        inputs.extend(Path(getattr(args, name)) for name in ("report", "plan", "junit"))
    try:
        require(not output.is_symlink(), "output-alias")
        for source in inputs:
            require(output.resolve() != source.resolve(), "output-alias")
            if output.exists() and source.exists():
                require(not output.samefile(source), "output-alias")
    except (Refused, OSError, ValueError):
        print("Refused")
        return 1
    result: dict[str, Any]
    try:
        now = datetime.now(UTC)
        if args.operation == "decide":
            report, plan, junit = (
                read_file(Path(getattr(args, name)))
                for name in ("report", "plan", "junit")
            )
            result = decide(
                GitHub(),
                json_object(read_file(Path(args.event))),
                report,
                plan,
                junit,
                args.policy_revision,
                now,
            )
        else:
            api = GitHub()
            event = json_object(read_file(Path(args.event)))
            subject = live_subject(api, event)
            deployed(api, args.policy_revision)
            observed = historical(
                api,
                subject,
                args.run_id,
                args.run_attempt,
                args.artifact_id,
                args.origin_artifact_id,
            )
            result = {
                **SCOPE,
                **observed,
                "pull_request": subject["pull_request"],
                "version": 1,
                "head_commit": subject["head_commit"],
                "head_tree": subject["head_tree"],
                "policy_revision": args.policy_revision,
                "selectors": list(SELECTORS),
                "missing_native_red": True,
                "signer_login": args.signer,
                "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "expires_at": args.expires_at,
            }
            validate_request(result, now)
            require(live_subject(api, event) == subject, "subject-race")
            Path(args.output).write_bytes(HEADER.encode() + b"\n" + canonical(result))
            print("Canonical approval request written; no grant issued.")
            return 0
    except (
        Refused,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        RecursionError,
        OverflowError,
        http.client.HTTPException,
        subprocess.SubprocessError,
    ):
        result = {
            "outcome": "Refused",
            "audit_only": True,
            "reason": "late-cycle-policy-rejected",
        }
    try:
        Path(args.output).write_bytes(canonical(result) + b"\n")
    except OSError:
        print("Refused")
        return 1
    print(result["outcome"])
    return 1 if result["outcome"] == "Refused" else 0


if __name__ == "__main__":
    raise SystemExit(main())
