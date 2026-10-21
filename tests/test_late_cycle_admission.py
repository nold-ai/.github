import copy
import importlib.util
import io
import json
import subprocess
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github/scripts/late_cycle_admission.py"
SPEC = importlib.util.spec_from_file_location("late_cycle_admission", SCRIPT)
p = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = p
SPEC.loader.exec_module(p)
FIXTURE = ROOT / "tests/fixtures/late-cycle"
HEAD = "03423ac0ae9c148e2707bed6a21f6bb09fae3518"
NOW = datetime(2026, 10, 21, 12, tzinfo=UTC)


def packet():
    return tuple((FIXTURE / n).read_bytes() for n in p.NATIVE_FILES)


def request():
    report, plan, junit = packet()
    evidence = p.validate_packet(report, plan, junit, HEAD)
    return {
        **p.SCOPE,
        "pull_request": 800,
        "version": 1,
        "head_commit": HEAD,
        "head_tree": "b" * 40,
        "policy_revision": "c" * 40,
        "run_id": 12,
        "run_attempt": 1,
        "artifact_id": 13,
        "origin_artifact_id": 14,
        "artifact_digest": "sha256:" + "d" * 64,
        "origin_digest": "sha256:" + "e" * 64,
        "workflow_sha": HEAD,
        "selectors": list(p.SELECTORS),
        "missing_native_red": True,
        "signer_login": "owner",
        "issued_at": "2026-10-21T11:00:00Z",
        "expires_at": "2026-10-22T11:00:00Z",
        **evidence,
    }


def comment(req=None):
    return {
        "id": 123,
        "body": p.HEADER + "\n" + p.canonical(req or request()).decode(),
        "user": {"login": "owner", "type": "User"},
        "author_association": "OWNER",
        "created_at": "2026-10-21T11:01:00Z",
        "updated_at": "2026-10-21T11:01:00Z",
    }


def test_complete_failed_native_packet_is_preserved():
    raw = packet()
    result = p.validate_packet(*raw, HEAD)
    assert result["allowed_finding"] == "prior-red-proof-invalid"
    assert packet() == raw


@pytest.mark.parametrize(
    "field,value",
    [
        ("gate_decision", "pass"),
        ("verdict", "passed"),
        ("findings", []),
        ("findings", ["prior-red-proof-invalid", "other"]),
        ("observed_maturity", "verified"),
        ("delivery_status", "complete"),
        ("implementation_evidence", "available"),
        ("schema_version", "1"),
    ],
)
def test_native_other_findings_or_false_maturity_refuse(field, value):
    raw, plan, junit = packet()
    report = json.loads(raw)
    report[field] = value
    with pytest.raises(p.Refused):
        p.validate_packet(p.canonical(report), plan, junit, HEAD)


@pytest.mark.parametrize(
    "mutation",
    [
        "skip",
        "failure",
        "error",
        "duplicate",
        "missing",
        "entity",
        "wrong-count",
        "wrong-property",
    ],
)
def test_hostile_junit_refuses(mutation):
    raw = packet()[2]
    if mutation in ["skip", "failure", "error"]:
        tag = {"skip": "skipped", "failure": "failure", "error": "error"}[mutation]
        raw = raw.replace(b"</testcase>", ("<" + tag + "/></testcase>").encode(), 1)
    elif mutation == "duplicate":
        raw = raw.replace(
            b"</testsuite>",
            raw[raw.index(b"<testcase") : raw.index(b"</testcase>") + 11]
            + b"</testsuite>",
        )
    elif mutation == "missing":
        raw = raw.replace(
            raw[raw.index(b"<testcase") : raw.index(b"</testcase>") + 11], b""
        )
    elif mutation == "entity":
        raw = b'<!DOCTYPE x [<!ENTITY a "b">]>' + raw
    elif mutation == "wrong-count":
        raw = raw.replace(b'tests="14"', b'tests="15"')
    else:
        raw = raw.replace(b"specfact.selector", b"fake.selector", 1)
    with pytest.raises(p.Refused):
        p.validate_junit(raw)


def test_canonical_separate_human_comment():
    assert p.approval(comment(), NOW) == request()


@pytest.mark.parametrize(
    "mutation",
    [
        "edited",
        "bot",
        "different-author",
        "generic",
        "whitespace",
        "duplicate-field",
        "expired",
        "long-expiry",
        "future",
        "unknown",
        "bool-id",
        "false-red",
        "head",
        "selector",
        "issue",
    ],
)
def test_approval_hostile_variants(mutation):
    r = request()
    c = comment(r)
    if mutation == "edited":
        c["updated_at"] = "2026-10-21T11:02:00Z"
    elif mutation == "bot":
        c["user"]["type"] = "Bot"
    elif mutation == "different-author":
        c["user"]["login"] = "another"
    elif mutation == "generic":
        c["body"] = c["body"].replace(
            p.HEADER, "SPECFACT_TRUSTED_REQUIREMENTS_AUTHORITY_V1"
        )
    elif mutation == "whitespace":
        c["body"] += "\n"
    elif mutation == "duplicate-field":
        c["body"] = c["body"].replace("{", '{"version":1,', 1)
    else:
        key, val = {
            "expired": ("expires_at", "2026-10-21T11:30:00Z"),
            "long-expiry": ("expires_at", "2026-11-21T11:30:00Z"),
            "future": ("issued_at", "2026-10-21T13:00:00Z"),
            "unknown": ("unknown", 1),
            "bool-id": ("run_id", True),
            "false-red": ("missing_native_red", False),
            "head": ("head_commit", "short"),
            "selector": ("selectors", []),
            "issue": ("issue", 781),
        }[mutation]
        r[key] = val
        c["body"] = p.HEADER + "\n" + p.canonical(r).decode()
    with pytest.raises(p.Refused):
        p.approval(c, NOW)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b'{"a":1e999}',
        b'{"a":Infinity}',
        b"[]",
        b"{} trailing",
        b"[" * 1000,
        b"\xff",
    ],
)
def test_json_hostility(raw):
    with pytest.raises(p.Refused):
        p.json_object(raw)


@pytest.mark.parametrize(
    "name",
    ["../origin.json", "/origin.json", "x/origin.json", "origin.json/", "other.json"],
)
def test_archive_names_refused(name):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr(name, "{}")
    with pytest.raises(p.Refused):
        p.unpack(out.getvalue(), {"origin.json"})


def test_archive_duplicate_refused():
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("origin.json", "{}")
        with pytest.warns(UserWarning, match="Duplicate name"):
            z.writestr("origin.json", "{}")
    with pytest.raises(p.Refused):
        p.unpack(out.getvalue(), {"origin.json"})


def test_cli_refusal_stable_and_no_input_echo(tmp_path):
    event = tmp_path / "event"
    event.write_text('{"secret":"not-for-logs"}')
    output = tmp_path / "decision"
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            str(SCRIPT),
            "decide",
            "--event",
            str(event),
            "--report",
            str(event),
            "--plan",
            str(event),
            "--junit",
            str(event),
            "--policy-revision",
            "c" * 40,
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "not-for-logs" not in result.stdout + result.stderr
    assert json.loads(output.read_text())["outcome"] == "Refused"


def fake_live(monkeypatch, *, mutation=None):
    req = request()
    c = comment(req)
    subject = {
        "pull_request": 800,
        "head_commit": HEAD,
        "head_tree": "b" * 40,
        "merge_commit_sha": "f" * 40,
    }

    class API:
        def comments(self, number):
            return [copy.deepcopy(c)]

        def obj(self, path):
            return {"permission": "write", "user": {"login": "owner", "type": "User"}}

    api = API()
    monkeypatch.setattr(p, "live_subject", lambda *args: dict(subject))
    monkeypatch.setattr(p, "deployed", lambda *args: None)
    monkeypatch.setattr(
        p,
        "historical",
        lambda *args: {
            key: req[key]
            for key in p.EVIDENCE_FIELDS
            | {
                "run_id",
                "run_attempt",
                "artifact_id",
                "origin_artifact_id",
                "artifact_digest",
                "origin_digest",
                "workflow_sha",
            }
        },
    )

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW

    monkeypatch.setattr(p, "datetime", Clock)
    return api, c, req, subject


def test_live_decision_preserves_native_failure(monkeypatch):
    api, _, _, _ = fake_live(monkeypatch)
    raw = packet()
    decision = p.decide(api, {}, *raw, "c" * 40, NOW)
    assert decision["outcome"] == "HumanApprovedLateCycle"
    assert decision["native_gate_decision"] == "fail"
    assert decision["missing_native_red"] is True
    assert decision["audit_only"] is True
    assert packet() == raw


@pytest.mark.parametrize(
    "mutation",
    [
        "revoked",
        "bot",
        "ambiguous",
        "deleted",
        "head-race",
        "approval-race",
        "historical-run",
        "historical-origin",
        "historical-report",
        "historical-workflow",
    ],
)
def test_live_rechecks_and_bindings_refuse(monkeypatch, mutation):
    api, c, _req, subject = fake_live(monkeypatch)
    if mutation == "revoked":
        api.obj = lambda _: {
            "permission": "read",
            "user": {"login": "owner", "type": "User"},
        }
    elif mutation == "bot":
        api.obj = lambda _: {
            "permission": "admin",
            "user": {"login": "owner", "type": "Bot"},
        }
    elif mutation == "ambiguous":
        api.comments = lambda number: [c, c]
    elif mutation == "deleted":
        api.comments = lambda number: []
    elif mutation == "head-race":
        calls = iter([subject, {**subject, "head_commit": "d" * 40}])
        monkeypatch.setattr(p, "live_subject", lambda *args: next(calls))
    elif mutation == "approval-race":
        calls = iter([[c], []])
        api.comments = lambda number: next(calls)
    else:
        field = {
            "historical-run": "run_id",
            "historical-origin": "origin_digest",
            "historical-report": "report_digest",
            "historical-workflow": "workflow_sha",
        }[mutation]
        monkeypatch.setattr(p, "historical", lambda *args: {field: "changed"})
    with pytest.raises(p.Refused):
        p.decide(api, {}, *packet(), "c" * 40, NOW)


def test_attestation_cli_pins_identity_without_parsing_output(monkeypatch):
    seen = []

    def run(command, **kwargs):
        seen.append(command)
        assert kwargs["stdout"] == subprocess.DEVNULL
        assert kwargs["stderr"] == subprocess.DEVNULL
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(p.subprocess, "run", run)
    p.verify_origin(b"{}", b"{}", HEAD)
    command = seen[0]
    assert command[command.index("--signer-workflow") + 1] == p.REPO + "/" + p.WORKFLOW
    assert command[command.index("--signer-digest") + 1] == HEAD
    assert command[command.index("--source-digest") + 1] == HEAD
    assert "--deny-self-hosted-runners" in command


def test_attestation_failure_cannot_be_bypassed(monkeypatch):
    monkeypatch.setattr(
        p.subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess([], 1)
    )
    with pytest.raises(p.Refused, match="origin-signature"):
        p.verify_origin(b"{}", b"{}", HEAD)


@pytest.mark.parametrize(
    "comparison",
    [
        {"status": "behind", "merge_base_commit": {"sha": "c" * 40}},
        {"status": "ahead", "merge_base_commit": {"sha": "d" * 40}},
        {"status": "diverged", "merge_base_commit": {"sha": "c" * 40}},
    ],
)
def test_policy_must_be_on_main(comparison):
    class API:
        def obj(self, _):
            return comparison

    with pytest.raises(p.Refused, match="policy-not-deployed"):
        p.deployed(API(), "c" * 40)


def test_deployed_script_bytes_must_match():
    class API:
        def obj(self, _):
            return {"status": "ahead", "merge_base_commit": {"sha": "c" * 40}}

        def contents(self, *args):
            return b"different-code"

    with pytest.raises(p.Refused, match="policy-code-mismatch"):
        p.deployed(API(), "c" * 40)


def test_bare_passed_fields_cannot_rehabilitate_failed_native_command(tmp_path):
    report = tmp_path / "report"
    report.write_text('{"verdict":"passed","gate_decision":"pass"}')
    output = tmp_path / "decision"
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            str(SCRIPT),
            "decide",
            "--event",
            str(tmp_path / "absent"),
            "--report",
            str(report),
            "--plan",
            str(report),
            "--junit",
            str(report),
            "--policy-revision",
            "not-deployed",
            "--output",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
        env={},
    )
    assert result.returncode == 1
    assert json.loads(output.read_text())["outcome"] == "Refused"


def live_api():
    head = {"sha": HEAD, "ref": p.SCOPE["head_branch"], "repo": {"full_name": p.REPO}}
    pr = {
        "number": 800,
        "state": "open",
        "head": head,
        "base": {"ref": "dev"},
        "merge_commit_sha": "f" * 40,
    }
    event = {"repository": {"full_name": p.REPO}, "pull_request": copy.deepcopy(pr)}

    class API:
        def __init__(self):
            self.listing = [pr]

        def get(self, path, **kwargs):
            return p.canonical(self.listing)

        def obj(self, path):
            if "/pulls/" in path:
                return pr
            return {"sha": HEAD, "tree": {"sha": "b" * 40}}

    return API(), event, pr


def test_subject_binds_new_live_pr_number():
    api, event, _ = live_api()
    assert p.live_subject(api, event)["pull_request"] == 800


@pytest.mark.parametrize(
    "mutation",
    [
        "old-pr",
        "closed",
        "duplicate",
        "wrong-base",
        "wrong-branch",
        "fork",
        "stale-head",
        "false-number",
    ],
)
def test_subject_refuses_outside_unique_followup(mutation):
    api, event, pr = live_api()
    if mutation == "old-pr":
        event["pull_request"]["number"] = 782
    elif mutation == "closed":
        pr["state"] = "closed"
    elif mutation == "duplicate":
        api.listing = [pr, pr]
    elif mutation == "wrong-base":
        pr["base"]["ref"] = "main"
    elif mutation == "wrong-branch":
        pr["head"]["ref"] = "hotfix/isolate-semgrep-security-runtime"
    elif mutation == "fork":
        pr["head"]["repo"]["full_name"] = "attacker/specfact-cli"
    elif mutation == "stale-head":
        event["pull_request"]["head"]["sha"] = "a" * 40
    else:
        event["pull_request"]["number"] = True
    with pytest.raises(p.Refused):
        p.live_subject(api, event)


def zip_bytes(files):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return out.getvalue()


def historical_api(monkeypatch):
    source = b"reviewed mapping fixture"
    monkeypatch.setattr(p, "SOURCE_BYTES_DIGEST", p.digest(source))
    subject = {
        "pull_request": 800,
        "head_commit": HEAD,
        "head_tree": "b" * 40,
        "merge_commit_sha": "f" * 40,
    }
    native = zip_bytes(dict(zip(p.NATIVE_FILES, packet())))
    origin = {
        "schema_version": 1,
        "repository": p.REPO,
        "run_id": 12,
        "run_attempt": 1,
        "head_commit": HEAD,
        "workflow_path": p.WORKFLOW,
        "workflow_sha": HEAD,
        "artifact_id": 13,
        "artifact_digest": p.digest(native),
    }
    run = {
        "id": 12,
        "run_attempt": 1,
        "event": "pull_request",
        "path": p.WORKFLOW,
        "head_sha": HEAD,
        "head_branch": p.SCOPE["head_branch"],
        "repository": {"full_name": p.REPO},
        "head_repository": {"full_name": p.REPO},
        "pull_requests": [{"number": 800, "head": {"sha": HEAD}}],
    }
    jobs = {
        "total_count": 1,
        "jobs": [
            {
                "name": "Native Requirements Origin",
                "conclusion": "success",
                "run_id": 12,
            }
        ],
    }

    class API:
        def origin_zip(self):
            return zip_bytes(
                {
                    "origin.json": p.canonical(origin),
                    "origin.bundle.jsonl": b"fixture signature",
                }
            )

        def obj(self, path):
            if "/jobs?" in path:
                return jobs
            if "/artifacts/" in path:
                ident = int(path.rsplit("/", 1)[1])
                raw = native if ident == 13 else self.origin_zip()
                return {
                    "id": ident,
                    "name": "requirements-evidence"
                    if ident == 13
                    else "requirements-native-origin-12-1",
                    "expired": False,
                    "workflow_run": {"id": 12, "head_sha": HEAD},
                    "size_in_bytes": len(raw),
                    "digest": p.digest(raw),
                }
            if "/git/commits/" in path:
                return {"sha": "f" * 40, "parents": [{"sha": HEAD}]}
            return run

        def get(self, path, **kwargs):
            return native if "/13/" in path else self.origin_zip()

        def contents(self, path, *args):
            return source if path.endswith(".yaml") else b"reviewed workflow"

    verified = []
    monkeypatch.setattr(p, "verify_origin", lambda *args: verified.append(args))
    return API(), subject, origin, run, jobs, verified


def test_historical_origin_verifies_manifest_and_original_zip(monkeypatch):
    api, subject, _, _, _, verified = historical_api(monkeypatch)
    result = p.historical(api, subject, 12, 1, 13, 14)
    assert result["artifact_id"] == 13
    assert result["run_attempt"] == 1
    assert len(verified) == 1
    assert verified[0][2] == HEAD


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong-pr",
        "wrong-attempt",
        "wrong-origin-head",
        "wrong-native-digest",
        "wrong-workflow",
        "origin-failed",
        "duplicate-job",
        "bad-source",
        "workflow-bytes",
        "merge-parent",
    ],
)
def test_historical_origin_fails_closed(monkeypatch, mutation):
    api, subject, origin, run, jobs, _ = historical_api(monkeypatch)
    if mutation == "wrong-pr":
        run["pull_requests"][0]["number"] = 782
    elif mutation == "wrong-attempt":
        origin["run_attempt"] = 2
    elif mutation == "wrong-origin-head":
        origin["head_commit"] = "a" * 40
    elif mutation == "wrong-native-digest":
        origin["artifact_digest"] = "sha256:" + "a" * 64
    elif mutation == "wrong-workflow":
        origin["workflow_sha"] = "a" * 40
    elif mutation == "origin-failed":
        jobs["jobs"][0]["conclusion"] = "failure"
    elif mutation == "duplicate-job":
        jobs["jobs"] *= 2
        jobs["total_count"] = 2
    elif mutation == "bad-source":
        api.contents = lambda *args: b"changed"
    elif mutation == "workflow-bytes":
        origin["workflow_sha"] = "f" * 40
        api.contents = lambda path, revision: revision.encode()
    else:
        origin["workflow_sha"] = "f" * 40
        original = api.obj
        api.obj = lambda path: (
            {"sha": "f" * 40, "parents": [{"sha": "a" * 40}]}
            if "/git/commits/" in path
            else original(path)
        )
    with pytest.raises(p.Refused):
        p.historical(api, subject, 12, 1, 13, 14)


def equivalent_merge_api(monkeypatch):
    api, subject, origin, _, _, verified = historical_api(monkeypatch)
    origin["workflow_sha"] = "a" * 40
    commits = {
        revision: {
            "sha": revision,
            "tree": {"sha": subject["head_tree"]},
            "parents": [{"sha": "c" * 40}, {"sha": HEAD}],
            "verification": {"verified": True, "reason": "valid"},
        }
        for revision in (origin["workflow_sha"], subject["merge_commit_sha"])
    }
    original = api.obj
    api.obj = lambda path: (
        commits[path.rsplit("/", 1)[1]] if "/git/commits/" in path else original(path)
    )
    return api, subject, origin, commits, verified


def test_historical_equivalent_signed_merge_preserves_attested_source(monkeypatch):
    api, subject, origin, _, verified = equivalent_merge_api(monkeypatch)
    result = p.historical(api, subject, 12, 1, 13, 14)
    assert result["workflow_sha"] == origin["workflow_sha"]
    assert result["workflow_sha"] != subject["merge_commit_sha"]
    assert verified == [
        (p.canonical(origin), b"fixture signature", origin["workflow_sha"])
    ]


@pytest.mark.parametrize("side", ["origin", "current"])
@pytest.mark.parametrize(
    "field,value",
    [
        ("sha", "d" * 40),
        ("sha", True),
        ("tree", {"sha": "d" * 40}),
        ("tree", {"sha": True}),
        ("tree", {"sha": "short"}),
        ("tree", {}),
        ("tree", None),
        ("tree", []),
        ("verification", {"verified": False, "reason": "valid"}),
        ("verification", {"verified": 1, "reason": "valid"}),
        ("verification", {"verified": True, "reason": "unsigned"}),
        ("verification", {"verified": True}),
        ("verification", {}),
        ("verification", True),
        ("verification", []),
        ("parents", [{"sha": "d" * 40}, {"sha": HEAD}]),
        ("parents", [{"sha": HEAD}, {"sha": "c" * 40}]),
        ("parents", [{"sha": "c" * 40}, {"sha": "d" * 40}]),
        ("parents", [{"sha": HEAD}]),
        ("parents", [{"sha": "c" * 40}, {"sha": HEAD}, {"sha": "d" * 40}]),
        ("parents", [{"sha": True}, {"sha": HEAD}]),
        ("parents", [{"sha": "short"}, {"sha": HEAD}]),
        ("parents", [True, {"sha": HEAD}]),
        ("parents", [{}, {"sha": HEAD}]),
        ("parents", {}),
        ("parents", None),
    ],
)
def test_historical_equivalent_merge_metadata_refuses(monkeypatch, side, field, value):
    api, subject, origin, commits, verified = equivalent_merge_api(monkeypatch)
    revision = (
        origin["workflow_sha"] if side == "origin" else subject["merge_commit_sha"]
    )
    commits[revision][field] = value
    with pytest.raises(p.Refused):
        p.historical(api, subject, 12, 1, 13, 14)
    assert verified == []


@pytest.mark.parametrize("revision", [None, True, {}, [], "short", "A" * 40])
def test_historical_equivalent_merge_requires_current_identity(monkeypatch, revision):
    api, subject, _, _, verified = equivalent_merge_api(monkeypatch)
    subject["merge_commit_sha"] = revision
    with pytest.raises(p.Refused):
        p.historical(api, subject, 12, 1, 13, 14)
    assert verified == []


@pytest.mark.parametrize("record", [None, True, [], {}])
@pytest.mark.parametrize("side", ["origin", "current"])
def test_historical_equivalent_merge_requires_commit_object(monkeypatch, record, side):
    api, subject, origin, commits, verified = equivalent_merge_api(monkeypatch)
    revision = (
        origin["workflow_sha"] if side == "origin" else subject["merge_commit_sha"]
    )
    commits[revision] = record
    with pytest.raises(p.Refused):
        p.historical(api, subject, 12, 1, 13, 14)
    assert verified == []


@pytest.mark.parametrize(
    "parents",
    [
        [{"sha": "c" * 40}, {"sha": "d" * 40}],
        [{"sha": HEAD}, {"sha": "c" * 40}],
        [{"sha": HEAD}, {"sha": HEAD}],
        [{"sha": True}, {"sha": HEAD}],
        [{"sha": "short"}, {"sha": HEAD}],
    ],
)
def test_historical_matching_ancestry_still_requires_head_and_full_shas(
    monkeypatch, parents
):
    api, subject, _, commits, verified = equivalent_merge_api(monkeypatch)
    for commit in commits.values():
        commit["parents"] = parents
    with pytest.raises(p.Refused, match="origin-source"):
        p.historical(api, subject, 12, 1, 13, 14)
    assert verified == []


@pytest.mark.parametrize("tree", [None, True, {}, "short"])
def test_historical_matching_trees_still_require_full_subject_tree(monkeypatch, tree):
    api, subject, _, commits, verified = equivalent_merge_api(monkeypatch)
    subject["head_tree"] = tree
    for commit in commits.values():
        commit["tree"]["sha"] = tree
    with pytest.raises(p.Refused, match="origin-source"):
        p.historical(api, subject, 12, 1, 13, 14)
    assert verified == []


@pytest.mark.parametrize("revision", [None, True, {}, [], "short"])
def test_historical_equivalent_merge_requires_full_origin_identity(
    monkeypatch, revision
):
    api, subject, origin, _, verified = equivalent_merge_api(monkeypatch)
    origin["workflow_sha"] = revision
    with pytest.raises(p.Refused, match="origin-workflow-sha"):
        p.historical(api, subject, 12, 1, 13, 14)
    assert verified == []


def test_historical_current_merge_keeps_existing_acceptance(monkeypatch):
    api, subject, origin, _, _, verified = historical_api(monkeypatch)
    origin["workflow_sha"] = subject["merge_commit_sha"]
    result = p.historical(api, subject, 12, 1, 13, 14)
    assert result["workflow_sha"] == subject["merge_commit_sha"]
    assert verified[0][2] == subject["merge_commit_sha"]


def test_historical_equivalent_merge_keeps_source_mapping_guard(monkeypatch):
    api, subject, _, _, _ = equivalent_merge_api(monkeypatch)
    api.contents = lambda *args: b"changed"
    with pytest.raises(p.Refused, match="live-source-mapping"):
        p.historical(api, subject, 12, 1, 13, 14)


def test_historical_equivalent_merge_keeps_workflow_byte_guard(monkeypatch):
    api, subject, _, _, verified = equivalent_merge_api(monkeypatch)
    api.contents = lambda path, revision: revision.encode()
    with pytest.raises(p.Refused, match="origin-workflow-bytes"):
        p.historical(api, subject, 12, 1, 13, 14)
    assert verified == []


def test_historical_equivalent_merge_keeps_attestation_guard(monkeypatch):
    verify_origin = p.verify_origin
    calls = []

    def reject(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 1)

    api, subject, origin, _, _ = equivalent_merge_api(monkeypatch)
    monkeypatch.setattr(p, "verify_origin", verify_origin)
    monkeypatch.setattr(p.subprocess, "run", reject)
    with pytest.raises(p.Refused, match="origin-signature"):
        p.historical(api, subject, 12, 1, 13, 14)
    assert len(calls) == 1
    command = calls[0]
    assert command[command.index("--source-digest") + 1] == origin["workflow_sha"]
    assert command[command.index("--signer-digest") + 1] == origin["workflow_sha"]


def test_other_pr_grant_does_not_transfer(monkeypatch):
    api, c, req, _ = fake_live(monkeypatch)
    req["pull_request"] = 782
    c["body"] = p.HEADER + "\n" + p.canonical(req).decode()
    with pytest.raises(p.Refused, match="approval-missing"):
        p.decide(api, {}, *packet(), "c" * 40, NOW)


def test_storage_redirect_never_receives_token(monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "test-token")
    seen = []

    class Response:
        def __init__(self, status):
            self.status = status

        def getheader(self, name, default):
            return "https://safe.blob.core.windows.net/artifact?signature=test"

        def read(self, limit):
            return b"zip bytes"

    class Connection:
        def __init__(self, host, **kwargs):
            self.host = host

        def request(self, method, target, headers):
            seen.append((self.host, headers))

        def getresponse(self):
            return Response(302 if self.host == "api.github.com" else 200)

        def close(self):
            pass

    monkeypatch.setattr(p.http.client, "HTTPSConnection", Connection)
    assert (
        p.GitHub().get(
            "/repos/nold-ai/specfact-cli/actions/artifacts/13/zip", archive=True
        )
        == b"zip bytes"
    )
    assert seen[0][1]["Authorization"] == "Bearer test-token"
    assert "Authorization" not in seen[1][1]


@pytest.mark.parametrize(
    "url",
    [
        "http://safe.blob.core.windows.net/a",
        "https://attacker.example/a",
        "https://safe.blob.core.windows.net.attacker.example/a",
        "https://token@safe.blob.core.windows.net/a",
    ],
)
def test_storage_redirect_rejects_untrusted_destinations(monkeypatch, url):
    monkeypatch.setenv("GH_TOKEN", "test-token")

    class Response:
        status = 302

        def getheader(self, *args):
            return url

    class Connection:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            return Response()

        def close(self):
            pass

    monkeypatch.setattr(p.http.client, "HTTPSConnection", Connection)
    with pytest.raises(p.Refused, match="archive-redirect"):
        p.GitHub().get("/repos/x/y/artifact", archive=True)


def test_unwritable_output_has_stable_cli_refusal(tmp_path):
    path = tmp_path / "native"
    path.write_text('{"verdict":"passed","gate_decision":"pass"}')
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            str(SCRIPT),
            "decide",
            "--event",
            str(path),
            "--report",
            str(path),
            "--plan",
            str(path),
            "--junit",
            str(path),
            "--policy-revision",
            "c" * 40,
            "--output",
            str(tmp_path / "missing" / "output"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert result.stdout == "Refused\n"
    assert result.stderr == ""


@pytest.mark.parametrize(
    "alias", ["report", "plan", "junit", "event", "symlink", "hardlink"]
)
def test_refused_decision_never_overwrites_an_input_alias(tmp_path, alias):
    paths = {name: tmp_path / name for name in ("event", "report", "plan", "junit")}
    for name, path in paths.items():
        path.write_bytes(b"original immutable " + name.encode())
    original = {name: path.read_bytes() for name, path in paths.items()}
    if alias in paths:
        output = paths[alias]
    else:
        output = tmp_path / "decision"
        if alias == "symlink":
            output.symlink_to(paths["report"])
        else:
            import os

            os.link(paths["report"], output)
    arguments = [
        sys.executable,
        "-I",
        "-S",
        str(SCRIPT),
        "decide",
        "--policy-revision",
        "c" * 40,
        "--output",
        str(output),
    ]
    for name, path in paths.items():
        arguments.extend(["--" + name, str(path)])
    result = subprocess.run(
        arguments, capture_output=True, text=True, check=False, env={}
    )
    assert result.returncode == 1
    assert {name: path.read_bytes() for name, path in paths.items()} == original


def test_historical_approved_attempt_survives_later_rerun(monkeypatch):
    api, subject, _, run, _, _ = historical_api(monkeypatch)
    original = api.obj
    paths = []

    def obj(path):
        paths.append(path)
        if path == f"/repos/{p.REPO}/actions/runs/12":
            return {**run, "run_attempt": 2}
        return original(path)

    api.obj = obj
    result = p.historical(api, subject, 12, 1, 13, 14)
    assert result["run_attempt"] == 1
    assert f"/repos/{p.REPO}/actions/runs/12/attempts/1" in paths
    assert f"/repos/{p.REPO}/actions/runs/12/attempts/1/jobs?per_page=100" in paths
    assert f"/repos/{p.REPO}/actions/runs/12" not in paths


@pytest.mark.parametrize("attempt", [0, -1, True, "1", None])
def test_historical_rejects_invalid_approved_attempt(monkeypatch, attempt):
    api, subject, _, _, _, _ = historical_api(monkeypatch)
    with pytest.raises(p.Refused, match="run-attempt"):
        p.historical(api, subject, 12, attempt, 13, 14)


@pytest.mark.parametrize("returned_attempt", [2, True, "1", None])
def test_historical_rejects_substituted_attempt_response(monkeypatch, returned_attempt):
    api, subject, _, run, _, _ = historical_api(monkeypatch)
    run["run_attempt"] = returned_attempt
    with pytest.raises(p.Refused, match="run-attempt"):
        p.historical(api, subject, 12, 1, 13, 14)


def test_historical_rejects_old_artifact_for_new_attempt(monkeypatch):
    api, subject, _, run, _, _ = historical_api(monkeypatch)
    run["run_attempt"] = 2
    with pytest.raises(p.Refused, match="artifact-association"):
        p.historical(api, subject, 12, 2, 13, 14)


def test_decision_uses_explicitly_approved_attempt(monkeypatch):
    api, _, req, _ = fake_live(monkeypatch)
    original = p.historical
    observed = []

    def historical(*args):
        observed.append(args[3])
        return original(*args)

    monkeypatch.setattr(p, "historical", historical)
    assert (
        p.decide(api, {}, *packet(), "c" * 40, NOW)["outcome"]
        == "HumanApprovedLateCycle"
    )
    assert observed == [req["run_attempt"]]


def test_request_cli_binds_explicit_attempt(monkeypatch, tmp_path):
    api, _, _, _ = fake_live(monkeypatch)
    monkeypatch.setattr(p, "GitHub", lambda: api)
    original = p.historical
    attempts = []

    def historical(*args):
        attempts.append(args[3])
        return original(*args)

    monkeypatch.setattr(p, "historical", historical)
    event = tmp_path / "event.json"
    event.write_text("{}")
    output = tmp_path / "approval.txt"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT),
            "request",
            "--event",
            str(event),
            "--policy-revision",
            "c" * 40,
            "--output",
            str(output),
            "--run-id",
            "12",
            "--run-attempt",
            "1",
            "--artifact-id",
            "13",
            "--origin-artifact-id",
            "14",
            "--signer",
            "owner",
            "--expires-at",
            "2026-10-22T12:00:00Z",
        ],
    )
    assert p.main() == 0
    assert attempts == [1]
    assert json.loads(output.read_text().splitlines()[1])["run_attempt"] == 1


def test_request_cli_requires_attempt(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            str(SCRIPT),
            "request",
            "--event",
            str(tmp_path / "event"),
            "--policy-revision",
            "c" * 40,
            "--output",
            str(tmp_path / "output"),
            "--run-id",
            "12",
            "--artifact-id",
            "13",
            "--origin-artifact-id",
            "14",
            "--signer",
            "owner",
            "--expires-at",
            "2026-10-22T12:00:00Z",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "--run-attempt" in result.stderr
