"""Finite external-input regressions. Synthetic/local facts grant no native authority."""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from xml.etree import ElementTree as ET

R2 = "22b2fa7bd763b18ada1bfd1a9ea482a624f34cca"
OLD_R = "4ae6175a4d337296d0347e73b66c9da1f0e43f7f"
C = "9b5ad1e78430cc0b061cb16de42f73de96f4f312"
TREE = "fd6a43314d221ee03f6bf476c737487a71aa3677"
OLD_TREE = "baeb88acf0d2a5015810ad12dbfccfa7fdf9a21e"
RAW = "e4fb60ffd26867bb0bab3b92353ff40cfce196011d27aae3fbd5dd14946223fa"
BASE = "/repos/nold-ai/specfact-cli"
URL = "https://github.com/nold-ai/specfact-cli.git"
TARGET = OWNED = PREPARE = OPTIONS = DATA = None


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def data(name):
    return (DATA / name).read_bytes()


def put(path, raw):
    path.write_bytes(raw)
    path.chmod(0o600)


def accepted(test, error_type, operation):
    try:
        return operation()
    except error_type as error:
        test.fail(f"Intended refreshed input was refused: {type(error).__name__}: {error}")




class Junit(unittest.TestCase):
    def parse(self, raw):
        with OWNED.owned_account() as account:
            put(account.root.path / "requirements-proof.xml", raw)
            member = TARGET._read_owned(account, TARGET._SourceRole.JUNIT)
            facts = TARGET._junit_original15(account, member)
            self.assertFalse(account.live_complete)
            return facts

    def test_all_twenty_one_assertions_accept_only_as_parser_facts(self):
        facts = accepted(self, TARGET._OriginalProofError,
                         lambda: self.parse(data("synthetic-native21.xml")))
        cases = json.loads(data("cases.json"))
        self.assertEqual(facts.failures, 21)
        self.assertEqual(facts.selectors, tuple(case["selector"] for case in cases))
        self.assertEqual((facts.errors, facts.skips, facts.passes), (0, 0, 0))

    def test_bad_selector_order_location_marker_properties_and_outcomes_refuse(self):
        def missing(root):
            suite = root.find("testsuite")
            suite.remove(suite.findall("testcase")[-1])
        def duplicate(root):
            suite = root.find("testsuite")
            suite.append(copy.deepcopy(suite.find("testcase")))
        def reorder(root):
            suite = root.find("testsuite")
            cases = suite.findall("testcase")
            suite.remove(cases[0])
            suite.append(cases[0])
        def wrong_location(root):
            failure = root.find(".//failure")
            failure.text = failure.text.rsplit("\n", 1)[0] + "\ntests/wrong.py:1: AssertionError"
        def wrong_assertion(root):
            failure = root.find(".//failure")
            case = json.loads(data("cases.json"))[0]
            failure.text = failure.text.replace(case["markers"][0], "assert wrong_helper")
        def outcome(root, kind):
            case = root.find(".//testcase")
            case.remove(case.find("failure"))
            if kind != "pass":
                ET.SubElement(case, kind).text = "Synthetic setup/skip, not intended RED"
        mutations = [missing, duplicate, reorder, wrong_location, wrong_assertion]
        mutations.extend(lambda root, k=k: outcome(root, k) for k in ("pass", "error", "skipped"))
        def unknown_selector(root):
            root.find(".//property").set("value", "tests/unknown.py::test_unknown")
        def wrong_python(root):
            next(p for p in root.iter("property") if p.get("name") == "specfact.python").set("value", "3.12.13")
        def duplicate_property(root):
            group = root.find(".//properties")
            group.append(copy.deepcopy(group[0]))
        mutations.extend((unknown_selector, wrong_python, duplicate_property))
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                root = ET.fromstring(data("synthetic-native21.xml"))
                mutate(root)
                raw = ET.tostring(root, encoding="utf-8", xml_declaration=True)
                with self.assertRaises(TARGET._OriginalProofError):
                    self.parse(raw)
        for raw in (b"<testsuites>", b'<!DOCTYPE testsuites [<!ENTITY x "x">]><testsuites/>'):
            with self.subTest(raw=raw), self.assertRaises(TARGET._OriginalProofError):
                self.parse(raw)


class Planning(unittest.TestCase):
    def populate(self, account):
        for name in ("plan.json", "planning-report.json", "planning-summary.md"):
            put(account.root.path / name, data(name))

    def test_complete_current_planner_products_accept(self):
        with OWNED.owned_account() as account:
            self.populate(account)
            accepted(self, TARGET._OriginalProofError,
                     lambda: TARGET._check_products(account, TARGET._OriginalStage.PLANNER))
            self.assertEqual(account.products.plan.data, data("plan.json"))
            self.assertEqual(account.products.planning_report.data, data("planning-report.json"))
            self.assertFalse(account.live_complete)

    def test_extra_field_or_old_plan_cannot_replace_current_products(self):
        for name in ("plan.json", "planning-report.json"):
            with self.subTest(name=name), OWNED.owned_account() as account:
                self.populate(account)
                value = json.loads(data(name))
                value["Synthetic-unreviewed-extra"] = True
                put(account.root.path / name, json.dumps(value).encode())
                with self.assertRaises(TARGET._OriginalProofError):
                    TARGET._check_products(account, TARGET._OriginalStage.PLANNER)


class Products(unittest.TestCase):
    populate = Planning.populate

    def through_executor(self, account):
        self.populate(account)
        put(account.root.path / "requirements-proof.xml", data("synthetic-native21.xml"))
        TARGET._check_products(account, TARGET._OriginalStage.PLANNER)
        TARGET._check_products(account, TARGET._OriginalStage.EXECUTOR)

    def report(self, bound=False):
        value = json.loads(data("local-red-report.json" if bound else "local-red-unbound-report.json"))
        value["execution_proof"]["junit_digest"] = "sha256:" + digest(data("synthetic-native21.xml"))
        if bound:
            value["execution_proof"]["toolchain_identity"] = {
                "runner": "pytest", "python": "3.12.15", "pytest": "9.1.1"}
        return value

    def write_report(self, account, value):
        put(account.root.path / "local-red-report.json",
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode())

    def test_current_reconciliation_and_four_binding_additions_accept_as_synthetic_products(self):
        with OWNED.owned_account() as account:
            def operation():
                self.through_executor(account)
                self.write_report(account, self.report())
                put(account.root.path / "local-red-summary.md", b"Synthetic product fixture, no native authority\n")
                TARGET._check_products(account, TARGET._OriginalStage.RECONCILER)
                self.write_report(account, self.report(bound=True))
                TARGET._check_products(account, TARGET._OriginalStage.BINDER)
            accepted(self, TARGET._OriginalProofError, operation)
            proof = json.loads(account.products.bound_report.data)["execution_proof"]
            self.assertEqual((proof["source_ref"], proof["source_tree"], proof["merge_base"]), (R2, TREE, C))
            self.assertEqual(set(proof["test_file_digests"]),
                             {row["path"] for row in json.loads(data("sources.json")) if row["path"].startswith("tests/")})
            self.assertFalse(account.live_complete)

    def test_old_source_or_modified_binding_addition_refuses(self):
        for stage in ("RECONCILER", "BINDER"):
            with self.subTest(stage=stage), OWNED.owned_account() as account:
                accepted(self, TARGET._OriginalProofError, lambda: self.through_executor(account))
                put(account.root.path / "local-red-summary.md", b"Synthetic fixture\n")
                if stage == "BINDER":
                    self.write_report(account, self.report())
                    TARGET._check_products(account, TARGET._OriginalStage.RECONCILER)
                value = self.report(bound=stage == "BINDER")
                value["execution_proof"]["source_tree" if stage == "BINDER" else "source_ref"] = OLD_TREE if stage == "BINDER" else OLD_R
                self.write_report(account, value)
                with self.assertRaises(TARGET._OriginalProofError):
                    TARGET._check_products(account, getattr(TARGET._OriginalStage, stage))


class Sources(unittest.TestCase):
    def fixture(self, account, number):
        rows = json.loads(data("sources.json"))[-2:]
        relative = rows[number]["path"]
        source = account.root.path / relative
        source.parent.mkdir(parents=True, exist_ok=True)
        put(source, data("selected-" + str(number) + ".py"))
        account.source_roots = (account.root.path,) * 4
        try:
            role = TARGET._SourceRole("source-" + str(33 + number))
        except ValueError:
            self.fail("Existing fixed-source reader has no role for new selected proof input")
        return source, role

    def test_both_new_selected_files_are_read_and_hash_bound(self):
        for number in (0, 1):
            with self.subTest(number=number), OWNED.owned_account() as account:
                source, role = self.fixture(account, number)
                member = accepted(self, TARGET._OwnedReadError,
                                  lambda: TARGET._read_owned(account, role))
                self.assertEqual(member.data, source.read_bytes())
                self.assertEqual(member.sha256, digest(data("selected-" + str(number) + ".py")))
                self.assertGreater(account.read_bytes, 0)
                self.assertFalse(account.live_complete)

    def test_one_byte_new_selected_input_corruption_refuses(self):
        for number in (0, 1):
            with self.subTest(number=number), OWNED.owned_account() as account:
                source, role = self.fixture(account, number)
                source.write_bytes(source.read_bytes() + b"x")
                with self.assertRaises(TARGET._OwnedReadError):
                    TARGET._read_owned(account, role)
                self.assertTrue(account.stopped)



class Preparation(unittest.TestCase):
    def setUp(self):
        self.fixture = PREPARE.RealGitSyntheticAPI("test_actual_objects_sources_and_minimal_history")
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.account = self.fixture.account
        self.r2 = json.loads(data("r2-api.json"))
        self.calls = []
        def get(path, *, archive=False):
            self.assertFalse(archive)
            self.calls.append(path)
            routes = {BASE: self.fixture.repo, BASE + "/git/commits/" + C: self.fixture.c,
                      BASE + "/git/commits/" + OLD_R: self.fixture.r,
                      BASE + "/git/commits/" + R2: self.r2}
            return json.dumps(routes[path]).encode()
        self.fixture.api = SimpleNamespace(GitHub=lambda: SimpleNamespace(get=get))

    def prepare(self):
        prepared = accepted(self, TARGET._OriginalRPreparationError,
                            lambda: TARGET._prepare_original_r(self.account, self.fixture.api))
        self.assertEqual((prepared.commit, prepared.parent, prepared.tree, prepared.parent_tree),
                         (R2, OLD_R, TREE, OLD_TREE))
        return prepared

    def test_real_objects_two_commit_chain_and_twelve_subject_bytes(self):
        prepared = self.prepare()
        self.assertEqual(self.fixture.git(prepared.root, "rev-list", "--reverse", C + ".." + R2),
                         (OLD_R + "\n" + R2 + "\n").encode())
        self.assertEqual(self.fixture.git(prepared.root, "merge-base", C, R2), (C + "\n").encode())
        self.assertEqual((prepared.root / ".git/shallow").read_bytes(), (C + "\n").encode())
        self.assertEqual(digest(self.fixture.git(prepared.root, "cat-file", "commit", R2)), RAW)
        sources = tuple((item["path"], item["sha256"]) for item in json.loads(data("sources.json")))
        self.assertEqual(tuple(prepared.sources), sources)
        for path, sha256 in sources:
            self.assertEqual(digest((prepared.root / path).read_bytes()), sha256)
        self.assertEqual(self.calls, [BASE, BASE + "/git/commits/" + C, BASE + "/git/commits/" + R2])
        fetches = [argv for argv in self.fixture.git_calls if "fetch" in argv]
        self.assertEqual(len(fetches), 1)
        self.assertIn("--depth=3", fetches[0])
        self.assertEqual(self.fixture.git(prepared.root, "status", "--porcelain", "--untracked-files=no"), b"")
        self.assertTrue(self.account.preparation.complete)
        self.assertFalse(self.account.stopped)

    def test_c_as_r2_immediate_parent_is_refused_before_fetch(self):
        self.r2["parents"] = [{"sha": C}]
        with self.assertRaises(TARGET._OriginalRPreparationError):
            TARGET._prepare_original_r(self.account, self.fixture.api)
        self.assertFalse(any("fetch" in argv for argv in self.fixture.git_calls))
        self.assertTrue(self.account.stopped)

    def test_new_selected_source_corruption_refuses_live_use(self):
        prepared = self.prepare()
        path = prepared.root / "tests/unit/security/test_code_review_dependency_security.py"
        path.write_bytes(path.read_bytes() + b"\n# Synthetic changed selected proof input\n")
        root = self.account.root.path
        tool = SimpleNamespace(python=root / "synthetic/bin/python",
                               site_packages=root / "synthetic/site-packages",
                               core_root=root / "synthetic/core", modules_root=root / "synthetic/modules",
                               uv=root / "synthetic/bin/uv")
        with TARGET.Timer(1200) as timer:
            with self.assertRaises(TARGET._OriginalProofError):
                TARGET._verify_original_r_live(self.account, prepared, tool, timer)
        self.assertTrue(self.account.stopped)

    def test_existing_vectors_keep_c_and_r2_in_distinct_roles(self):
        prepared = self.prepare()
        root = self.account.root.path
        tool = SimpleNamespace(python=root / "synthetic/bin/python",
                               site_packages=root / "synthetic/site-packages",
                               core_root=root / "synthetic/core", modules_root=root / "synthetic/modules",
                               uv=root / "synthetic/bin/uv")
        vectors = TARGET._original_vectors(tool, prepared)
        self.assertEqual(tuple(v.expected_exit for v in vectors), (0, 1, 0, 0))
        self.assertEqual(vectors[0].argv[vectors[0].argv.index(b"--base-ref") + 1], C.encode())
        self.assertEqual(vectors[2].argv[vectors[2].argv.index(b"--source-ref") + 1], R2.encode())
        self.assertEqual({key for key, _ in vectors[0].environment},
                         {b"HOME", b"TMPDIR", b"PATH", b"LC_ALL", b"VIRTUAL_ENV",
                          b"SPECFACT_MODULES_REPO", b"SPECFACT_MODULES_ROOTS", b"GIT_CONFIG_NOSYSTEM"})


def main():
    global TARGET, OWNED, PREPARE, OPTIONS, DATA
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True,
                        help="Original unchanged test fixture directory, not a runtime override")
    parser.add_argument("--policy-helper", type=Path, required=True)
    parser.add_argument("--git-source", type=Path,
                        help="Read-only local repository containing actual R2, no network fallback")
    parser.add_argument("--mode", choices=("junit", "planning", "products", "sources", "preparation"), required=True)
    OPTIONS = parser.parse_args()
    DATA = Path(__file__).resolve().with_name("data")
    TARGET = load(OPTIONS.candidate.resolve(strict=True), "native21_target")
    load(OPTIONS.policy_helper.resolve(strict=True), "late_cycle_admission")
    OWNED = load(OPTIONS.fixtures / "test_remaining_original15.py", "native21_owned_fixture")
    OWNED.TARGET = TARGET
    if OPTIONS.mode == "preparation":
        if OPTIONS.git_source is None:
            parser.error("--git-source is required for preparation")
        if sys.platform != "linux":
            parser.error("preparation requires real Linux; never patch the runtime platform guard")
        PREPARE = load(OPTIONS.fixtures / "test_prepare_original_r.py", "native21_prepare_fixture")
        PREPARE.candidate = TARGET
        PREPARE.options = SimpleNamespace(r_metadata=OPTIONS.fixtures / "original-r-api.json",
                                         fixture_root=OPTIONS.git_source.parent)
        def local_popen(self, argv, *args, **kwargs):
            launch = dict(kwargs)
            if isinstance(launch.get("env"), dict):
                launch["env"] = dict(launch["env"])
            self.launches.append((type(argv), tuple(argv), launch, self.timer_observation()))
            self.git_calls.append(tuple(argv))
            translated = list(argv)
            if "fetch" in translated and URL in translated:
                translated[translated.index(URL)] = OPTIONS.git_source.resolve(strict=True).as_uri()
            process = self.real_popen(translated, *args, **kwargs)
            self.processes[process.pid] = (process, tuple(argv))
            return process
        PREPARE.RealGitSyntheticAPI.local_popen = local_popen
    classes = {"junit": Junit, "planning": Planning, "products": Products,
               "sources": Sources, "preparation": Preparation}
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(classes[OPTIONS.mode])
    return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())

