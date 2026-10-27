from __future__ import annotations

import ast
import contextlib
import hashlib
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import zlib


HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[2]
SOURCE = Path(".github/development/dev786_original_replay")
OPERATOR = HERE.relative_to(REPOSITORY)
BASE = "640549e62fb3ca001499e71d4cf935aa8c0a0192"
BASE_TREE = "2d27c800651b3e1b30d46078594a61937410f4cc"
METHOD_IDS_SHA256 = "047ec5cb32f0a035d76f986974b2b03a806e621ae1bf4634409006fcdd3f7033"
REF = "refs/heads/codex/dev786-linux-qualification-20261027-02"
WORKFLOW = ".github/workflows/dev786-linux-qualification.yml"
META = {
    "source-before", "source-after", "checkout", "tools-before", "tools-after",
    "context", "selection", "result", "cleanup", "files",
}
ACTUAL_METHODS = {
    "test_actual_nonzero_signal_limits_withholding_and_synthetic_edits",
    "test_actual_unsupported_syntax_collector_error_and_owned_timeout",
    "test_fixed_capture_receipts_keep_cumulative_reread_and_refusal_charges",
    "test_real_untraced_gap_pair_preserves_original_clock_and_cleanup",
}
REAL_POPEN = subprocess.Popen
REAL_OPEN = os.open
REAL_STAT = os.stat
REAL_LSTAT = os.lstat
REAL_FSTAT = os.fstat
REAL_FSYNC = os.fsync
REAL_SCANDIR = os.scandir
REAL_IO_OPEN = io.open
REAL_READ = os.read
REAL_MONOTONIC = time.monotonic


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def source_contract(source):
    ids = []
    for path in sorted(source.glob("test_*.py")):
        for node in ast.parse(path.read_bytes()).body:
            if isinstance(node, ast.ClassDef):
                ids.extend(f"{path.stem}.{node.name}.{method.name}" for method in node.body
                           if isinstance(method, ast.FunctionDef) and method.name.startswith("test_"))
    capture = ast.parse((source / "test_capture_handoff.py").read_bytes())
    child = next(ast.literal_eval(node.value) for node in capture.body
                 if isinstance(node, ast.Assign)
                 and any(isinstance(target, ast.Name) and target.id == "CONTROL_CHILD" for target in node.targets))
    replay = ast.parse((source / "replay.py").read_bytes())
    controls = next(node.value for node in replay.body if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == "_CONTROLS" for target in node.targets))
    names = [ast.literal_eval(item.elts[0]) for item in controls.elts]
    marker = next(ast.literal_eval(node.value).decode() for node in replay.body
                  if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == "_NAME" for target in node.targets))
    return sorted(ids), child.encode(), names, marker


def git_read(*arguments, cwd=REPOSITORY):
    return subprocess.run(["/usr/bin/git", *arguments], cwd=cwd, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5).stdout


def put_object(root, kind, raw):
    encoded = kind.encode() + b" " + str(len(raw)).encode() + b"\0" + raw
    sha = hashlib.sha1(encoded).hexdigest()
    path = root / ".git/objects" / sha[:2] / sha[2:]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(zlib.compress(encoded))
    return sha


def put_tree(root, directory):
    entries = []
    for path in directory.iterdir():
        if path.name == ".git":
            continue
        if path.is_dir():
            mode, sha, key = "40000", put_tree(root, path), path.name + "/"
        else:
            mode = "100755" if path.stat().st_mode & 0o111 else "100644"
            sha, key = put_object(root, "blob", path.read_bytes()), path.name
        entries.append((key.encode(), mode.encode() + b" " + os.fsencode(path.name) + b"\0" + bytes.fromhex(sha)))
    return put_object(root, "tree", b"".join(record for _, record in sorted(entries)))


class OwnedRun:
    def __init__(self, owner, case="green"):
        self.owner, self.case = owner, case
        if git_read("rev-parse", BASE + "^{tree}").decode().strip() != BASE_TREE:
            raise AssertionError("The fixture requires the exact immutable POLICY base tree")
        self.root = owner / "checkout"
        self.root.mkdir()
        for record in git_read("ls-tree", "-rz", "--full-tree", BASE).split(b"\0"):
            if not record:
                continue
            header, name = record.split(b"\t", 1)
            mode, kind, sha = header.split()
            if kind != b"blob" or mode not in (b"100644", b"100755"):
                raise AssertionError("The immutable POLICY fixture must have regular files only")
            destination = self.root / os.fsdecode(name)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(git_read("cat-file", "blob", sha.decode()))
            destination.chmod(int(mode, 8) & 0o777)
        for relative in (SOURCE, OPERATOR):
            shutil.copytree(REPOSITORY / relative, self.root / relative, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        workflow = self.root / WORKFLOW
        workflow.write_bytes((REPOSITORY / WORKFLOW).read_bytes())
        self.inputs_path = self.root / OPERATOR / "inputs.json"
        self.inputs = json.loads(self.inputs_path.read_bytes())
        self.ids, self.child, self.controls, self.marker = source_contract(self.root / SOURCE)
        self.tools = owner / "tools"
        self.tools.mkdir()
        self.tool_paths = {}
        for index, name in enumerate(("/usr/bin/python3", "/usr/bin/strace", "/bin/sh")):
            path = self.tools / str(index)
            path.write_bytes(("Synthetic tool bytes for " + name).encode())
            path.chmod(0o700)
            self.tool_paths[name] = path
        git = self.root / ".git"
        (git / "objects/info").mkdir(parents=True)
        (git / "refs").mkdir()
        common = Path(os.fsdecode(git_read("rev-parse", "--git-common-dir")).strip())
        if not common.is_absolute():
            common = REPOSITORY / common
        (git / "objects/info/alternates").write_text(str(common.resolve() / "objects") + "\n")
        (git / "config").write_text("[core]\nrepositoryformatversion = 0\nbare = false\nfilemode = true\n")
        self.tree = put_tree(self.root, self.root)
        commit = (f"tree {self.tree}\nparent {BASE}\nauthor Synthetic <fixture@invalid> 1 +0000\n"
                  "committer Synthetic <fixture@invalid> 1 +0000\n\nSynthetic unit fixture only\n").encode()
        self.sha = put_object(self.root, "commit", commit)
        (git / "HEAD").write_text(self.sha + "\n")
        git_read("read-tree", self.sha, cwd=self.root)
        self.temp = owner / "runner"
        self.temp.mkdir(mode=0o700)
        self.event = owner / "event.json"
        self.event.write_text(json.dumps({"before": "0" * 40, "after": self.sha, "created": True,
                                         "deleted": False, "ref": REF}))
        self.environment = {
            "PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8", "HOME": str(owner),
            "TMPDIR": str(self.temp), "RUNNER_TEMP": str(self.temp),
            "GITHUB_WORKSPACE": str(self.root), "GITHUB_REPOSITORY": "nold-ai/.github",
            "GITHUB_REPOSITORY_ID": "1110267669", "GITHUB_REPOSITORY_OWNER_ID": "225190663",
            "GITHUB_REF": REF, "GITHUB_SHA": self.sha, "GITHUB_EVENT_NAME": "push",
            "GITHUB_EVENT_PATH": str(self.event), "GITHUB_RUN_ID": "123456789",
            "GITHUB_RUN_ATTEMPT": "1", "GITHUB_WORKFLOW": "dev786-linux-qualification",
            "GITHUB_WORKFLOW_REF": f"nold-ai/.github/{WORKFLOW}@{REF}",
            "ImageOS": "ubuntu24", "ImageVersion": "Synthetic-unit-fixture",
        }
        self.launches, self.processes, self.probes, self.signals = [], [], [], []
        self.forbidden_signals = []
        self.directory_reads = {"root-entries": 0, "class-entries": 0}
        self.export_fsync_fault = False
        self.export_fsync_events = []
        self.deadline_offset = 0
        self.evidence = None
        self.private_nodes = {}
        self.private_accesses = []

    def evidence_files(self, tmp):
        root = Path(tmp) / "dev786-capture-tests-synthetic"
        actual = root / "001-actual-controls"
        owned = actual / "owned"
        actual.mkdir(parents=True, mode=0o700)
        for name in ("home", "tmp"):
            if self.case == "missing-" + name:
                continue
            private = actual / name
            if self.case == name + "-wrongtype":
                private.write_bytes(b"SYNTHETIC-PRIVATE-" + name.encode())
                nodes = [private]
            else:
                if self.case == name + "-symlink":
                    private = self.owner / ("private-" + name)
                    (actual / name).symlink_to(private, target_is_directory=True)
                private.mkdir(mode=0o700)
                nested = private / "nested"
                nested.mkdir(mode=0o700)
                nodes = [private, nested, private / "sentinel", nested / "payload"]
                for payload in nodes[2:]:
                    payload.write_bytes(b"SYNTHETIC-PRIVATE-" + name.encode() + b"-" + payload.name.encode())
            for node in nodes:
                attributes = REAL_STAT(node, follow_symlinks=False)
                self.private_nodes[attributes.st_dev, attributes.st_ino] = (
                    str(node), stat.S_ISDIR(attributes.st_mode))
        if self.case not in {"missing-owned-failure", "missing-owned-output-failure"}:
            owned.mkdir(mode=0o700)
        (root / "control_child.py").write_bytes(self.child)
        if self.case in {"missing-owned-failure", "missing-owned-output-failure"}:
            self.partial_files = {
                "stdout": b"" if self.case == "missing-owned-failure" else b"Synthetic partial child output\n",
                "stderr": b"Synthetic child failure before owned creation\n",
            }
            for name, raw in self.partial_files.items():
                (actual / name).write_bytes(raw)
            self.evidence = root
            return root
        if self.case == "partial-control-failure":
            self.partial_files = {
                "stdout": b"",
                "stderr": (b'Traceback (most recent call last):\n'
                           b'  File "Synthetic-before-clock-fixture", line 1, in synthetic_control\n'
                           b'RuntimeError: Synthetic first-clock failure; cleanup unproved\n'),
                "owned/read-gap-before-evidence/commands.jsonl": b'{"argv":["/bin/sh","-c",":"]}\n',
                "owned/read-gap-before-evidence/raw-output.bin": b"Synthetic first-clock partial raw bytes\n",
            }
            for relative, raw in self.partial_files.items():
                destination = actual / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(raw)
            self.evidence = root
            return root
        (actual / "stderr").write_bytes(b"")
        clocks = []
        for name in self.controls:
            case = owned / name
            case.mkdir()
            for filename, raw in {
                "control.sh": b"# Synthetic inert retained script\n", "pid": b"123\n",
                "stderr": b"", "trace.123": b"Synthetic retained trace bytes\n",
                self.marker if name == "withhold-name" else "stdout": b"Synthetic control output\n",
            }.items():
                (case / filename).write_bytes(raw)
        for name in ("read-gap-before", "read-gap-after"):
            directory = owned / (name + "-evidence")
            directory.mkdir()
            manifest = {"control": name, "origin": "Synthetic", "restored": True,
                        "evidence_complete": name == "read-gap-before",
                        "cleanup": {"deleted": True, "shutil_restored": True},
                        "source_counts": {"fixture.py": 1}, "source_blob_counts": {"fixture.py": 1}}
            for filename, raw in {"commands.jsonl": b"{}\n", "raw-output.bin": b"",
                                  "manifest.json": json.dumps(manifest).encode(), "environments.json": b"{}"}.items():
                (directory / filename).write_bytes(raw)
            clocks.append({"name": name, "gap_start": 100, "gap_end": 161,
                           "owner_end_before": 1200, "owner_end_after": 1200,
                           "collection_started_before_gap": None if name == "read-gap-before" else 99,
                           "original_manifest": manifest})
        value = {"state": "CAPTURED", "platform": "linux", "shared_packet_identity": True,
                 "initialization": {}, "qualification": {"cases": [], "book": {}, "clock_cases": clocks}}
        (actual / "stdout").write_text(json.dumps(value))
        self.evidence = root
        target = owned / self.controls[0] / "stderr"
        if self.case == "unknown-attempt-sibling":
            (actual / "unreviewed").write_bytes(b"DO-NOT-EXPORT-FOREIGN-BYTES")
        if self.case == "unknown":
            (owned / self.controls[0] / "unreviewed").write_bytes(b"private")
        elif self.case == "missing":
            target.unlink()
        elif self.case == "symlink":
            target.unlink()
            target.symlink_to(self.owner / "outside")
        elif self.case == "hardlink":
            target.unlink()
            os.link(self.owner / "outside", target)
        elif self.case == "fifo":
            target.unlink()
            os.mkfifo(target)
        elif self.case == "file-cap":
            target.write_bytes(b"x" * (1048576 + 1))
        elif self.case == "trace-count":
            for number in range(17):
                (target.parent / f"trace.{number + 1000}").write_bytes(b"")
        elif self.case == "two-attempts":
            (root / "002-actual-controls").mkdir()
        elif self.case == "two-roots":
            (Path(tmp) / "dev786-capture-tests-other").mkdir()
        elif self.case == "short-gap":
            value["qualification"]["clock_cases"][0]["gap_end"] = 160
            (actual / "stdout").write_text(json.dumps(value))
        elif self.case == "foreign-stderr-path":
            (actual / "stderr").write_text(str(self.owner / "outside"))
        elif self.case == "root-entries":
            for number in range(65):
                (Path(tmp) / f"unrelated-{number}").mkdir()
        elif self.case == "class-entries":
            for number in range(513):
                (root / f"unrelated-{number}").mkdir()
        elif self.case == "clock-combined-cap":
            directory = owned / "read-gap-before-evidence"
            command = b'{"argv":["/bin/sh","-c",":"]}\n'
            count, padding = divmod(1048575, len(command))
            commands = command * (count - 1) + command[:-1] + b" " * padding + b"\n"
            (directory / "commands.jsonl").write_bytes(commands)
            (directory / "raw-output.bin").write_bytes(b"x" * 1048578)
        elif self.case in {"script-cap", "pid-cap", "trace-cap", "clock-cap", "manifest-cap", "environment-cap"}:
            filename, maximum = {
                "script-cap": (target.parent / "control.sh", 4096),
                "pid-cap": (target.parent / "pid", 64),
                "trace-cap": (target.parent / "trace.123", 2097152),
                "clock-cap": (owned / "read-gap-before-evidence/raw-output.bin", 2097152),
                "manifest-cap": (owned / "read-gap-before-evidence/manifest.json", 524288),
                "environment-cap": (owned / "read-gap-before-evidence/environments.json", 65536),
            }[self.case]
            with filename.open("wb") as stream:
                stream.truncate(maximum + 1)
        elif self.case in {"global-files", "global-bytes"}:
            extra = 46 if self.case == "global-files" else 20
            for name in self.controls:
                for number in range(min(extra, 15)):
                    (owned / name / f"trace.{number + 1000}").write_bytes(b"")
                extra -= min(extra, 15)
            if self.case == "global-bytes":
                for path in owned.glob("*/trace.*"):
                    with path.open("wb") as stream:
                        stream.truncate(2097152)
        return root

    def launch(self, arguments, *positional, **options):
        argv = [os.fspath(item) for item in arguments]
        if argv[:7] == ["/usr/bin/python3", "-I", "-S", "-B", "-m", "unittest", "discover"]:
            self.launches.append((argv, options))
            self.evidence_files(options["env"]["TMPDIR"])
            ids = self.ids[:-1] if self.case == "omitted-id" else self.ids
            if self.case == "duplicate-id":
                ids = self.ids[:-1] + self.ids[:1]
            log = "".join(f"{item.rsplit('.', 1)[1]} ({item.rsplit('.', 1)[0]}.{item.rsplit('.', 1)[1]}) ... ok\n" for item in ids)
            log += f"\nRan {len(ids)} tests in 0.001s\n\nOK\n"
            if self.case == "skipped":
                log = log.replace("... ok", "... skipped 'Synthetic'", 1).replace("OK\n", "OK (skipped=1)\n")
            elif self.case in {"failure", "error"}:
                outcome = "FAIL" if self.case == "failure" else "ERROR"
                category = "failures" if self.case == "failure" else "errors"
                log = log.replace("... ok", "... " + outcome, 1).replace("OK\n", f"FAILED ({category}=1)\n")
            elif self.case == "partial-control-failure":
                log = ("Synthetic first-clock fixture failed before complete actual-control evidence\n"
                       "FAILED (errors=1)\n")
            elif self.case in {"missing-owned-failure", "missing-owned-output-failure"}:
                log = "Synthetic child failed before owned creation\nFAILED (errors=1)\n"
            self.suite_log = log.encode()
            code = "import sys,time; sys.stderr.write(" + repr(log) + "); sys.stderr.flush(); "
            if self.case in ("stdout-overflow", "stderr-overflow"):
                stream = "stdout" if self.case.startswith("stdout") else "stderr"
                code += f"sys.{stream}.buffer.write(b'x'*1048577); sys.{stream}.flush(); "
            if self.case == "deadline":
                self.deadline_offset = 601
                code += "time.sleep(3); "
            if self.case == "source-drift":
                with (self.root / SOURCE / "replay.py").open("ab") as stream:
                    stream.write(b"\n")
            if self.case == "tool-drift":
                self.tool_paths["/usr/bin/strace"].write_bytes(b"changed after admission")
            if self.case == "checkout-drift":
                (self.root / "unreviewed-file").write_bytes(b"changed after admission")
            code += "sys.exit(7)" if self.case in {
                "nonzero", "partial-control-failure", "missing-owned-failure", "missing-owned-output-failure",
            } else "sys.exit(0)"
            process = REAL_POPEN([sys.executable, "-I", "-S", "-B", "-c", code], *positional, **options)
            self.processes.append(process)
            if self.case == "outer-interrupt":
                raise KeyboardInterrupt("Synthetic interruption before ownership transfer")
            return process
        if argv[0] in self.tool_paths:
            if argv[0] == "/usr/bin/python3" and argv[1:] in (["--version"], ["-V"]):
                output = "Python 3.11.0\n" if self.case == "wrong-python" else "Python 3.12.0\n"
            elif argv[0] == "/usr/bin/strace" and argv[1:] in (["--version"], ["-V"]):
                output = "strace -- version Synthetic\n"
            elif argv[0] == "/usr/bin/strace" and argv[1:] in (["--help"], ["-h"]):
                output = "Synthetic strace help -ff -v -s -yy -ttt -e -o\n"
            elif argv[0] == "/bin/sh" and argv[1:] == ["--version"]:
                output = "Synthetic shell\n"
            else:
                raise AssertionError(f"An undeclared tool execution was attempted: {argv!r}")
            process = REAL_POPEN([sys.executable, "-I", "-S", "-B", "-c", f"print({output!r}, end='')"],
                                 *positional, **options)
            self.probes.append(process)
            return process
        if Path(argv[0]).name != "git":
            raise AssertionError(f"An undeclared process was attempted: {argv!r}")
        query = argv[1:]
        if query[:1] == ["-C"]:
            if Path(query[1]) != self.root:
                raise AssertionError("Git probes must stay in the private synthetic checkout")
            query = query[2:]
        if not query or query[0] not in {"rev-parse", "ls-tree", "diff", "diff-tree", "status", "ls-files",
                                         "show", "cat-file", "--version", "version", "log", "rev-list"}:
            raise AssertionError(f"Only read-only Git probes are permitted: {argv!r}")
        if "env" in options and "TMPDIR" not in options["env"]:
            options["env"] = {**options["env"], "TMPDIR": str(self.temp)}
        return REAL_POPEN(arguments, *positional, **options)

    def mapped(self, value):
        if isinstance(value, (str, bytes, os.PathLike)):
            return self.tool_paths.get(os.fsdecode(value), value)
        return value

    def invoke(self):
        (self.owner / "outside").write_bytes(b"DO-NOT-EXPORT-FOREIGN-BYTES")
        output = io.StringIO()
        filename = self.root / OPERATOR / "qualify.py"
        spec = importlib.util.spec_from_file_location("_dev786_operator_under_test", filename)
        module = importlib.util.module_from_spec(spec)
        real_killpg = os.killpg
        real_kill = os.kill
        replacement_done = False

        def observe_private(operation, value, dir_fd=None, payload_only=False):
            try:
                attributes = (REAL_FSTAT(value) if isinstance(value, int) else
                              REAL_STAT(value, dir_fd=dir_fd))
            except (OSError, TypeError, ValueError):
                return
            node = self.private_nodes.get((attributes.st_dev, attributes.st_ino))
            if node is not None and not (payload_only and node[1]):
                self.private_accesses.append((operation, node[0]))

        def observed_open(value, *args, **options):
            mapped = self.mapped(value)
            observe_private("os.open", mapped, options.get("dir_fd"), payload_only=True)
            return REAL_OPEN(mapped, *args, **options)

        def observed_io_open(value, *args, **options):
            mapped = self.mapped(value)
            observe_private("io.open", mapped, payload_only=True)
            return REAL_IO_OPEN(mapped, *args, **options)

        def observed_read(fd, size):
            observe_private("os.read", fd)
            return REAL_READ(fd, size)

        def owned_signal(pid, sig):
            self.signals.append((pid, sig))
            if not any(process.pid == pid and (sig == 0 or process.returncode is None) for process in self.processes + self.probes):
                self.forbidden_signals.append(("killpg", pid, sig))
                raise AssertionError("Signaling requires a still-owned unreaped child")
            return real_killpg(pid, sig)

        def owned_pid_signal(pid, sig):
            self.signals.append((pid, sig))
            if not any(process.pid == pid and (sig == 0 or process.returncode is None) for process in self.processes + self.probes):
                self.forbidden_signals.append(("kill", pid, sig))
                raise AssertionError("Signaling requires a still-owned unreaped child")
            return real_kill(pid, sig)

        def observed_fstat(fd):
            nonlocal replacement_done
            observed = REAL_FSTAT(fd)
            if self.case == "unstable" and self.evidence and not replacement_done:
                target = self.evidence / "001-actual-controls/owned" / self.controls[0] / "trace.123"
                current = REAL_STAT(target)
                if (observed.st_dev, observed.st_ino) == (current.st_dev, current.st_ino):
                    replacement = self.owner / "replacement"
                    replacement.write_bytes(b"changed while selected descriptor remained open")
                    os.replace(replacement, target)
                    replacement_done = True
            return observed

        class ObservedEntries:
            def __init__(self, entries):
                self.entries = entries

            def __iter__(self):
                return self

            def __next__(observer):
                entry = next(observer.entries)
                self.directory_reads[self.case] += 1
                return entry

            def __enter__(self):
                self.entries.__enter__()
                return self

            def __exit__(self, *exception):
                return self.entries.__exit__(*exception)

            def close(self):
                return self.entries.close()

        def observed_scandir(value="."):
            observe_private("os.scandir", value)
            entries = REAL_SCANDIR(value)
            if self.case not in self.directory_reads or not self.launches or self.evidence is None:
                return entries
            try:
                watched = (self.launches[0][1]["env"]["TMPDIR"]
                           if self.case == "root-entries" else self.evidence)
                expected = REAL_STAT(watched, follow_symlinks=False)
                observed = REAL_FSTAT(value) if isinstance(value, int) else REAL_STAT(value)
                if (observed.st_dev, observed.st_ino) == (expected.st_dev, expected.st_ino):
                    return ObservedEntries(entries)
                return entries
            except BaseException:
                entries.close()
                raise

        def observed_fsync(fd):
            synced = REAL_FSYNC(fd)
            if not self.export_fsync_fault or len(self.export_fsync_events) >= 2:
                return synced
            control = sorted(self.controls)[1 if self.export_fsync_events else 0]
            filename = "control.sh" if self.export_fsync_events else "trace.123"
            with contextlib.ExitStack() as stack:
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                directory = REAL_OPEN(self.owner, flags)
                stack.callback(os.close, directory)
                try:
                    for part in ("runner", "dev786-linux-qualification-123456789-1", "export",
                                 "actual", "owned", control):
                        directory = REAL_OPEN(part, flags, dir_fd=directory)
                        stack.callback(os.close, directory)
                    expected = REAL_STAT(filename, dir_fd=directory, follow_symlinks=False)
                except FileNotFoundError:
                    return synced
                observed = REAL_FSTAT(fd)
                if (observed.st_dev, observed.st_ino) != (expected.st_dev, expected.st_ino):
                    return synced
                if not all(stat.S_ISREG(item.st_mode) and item.st_nlink == 1
                           for item in (expected, observed)):
                    raise AssertionError("Synthetic fsync target must be an owned single-link regular file")
                source = self.evidence / "001-actual-controls/owned" / control / filename
                if observed.st_size != REAL_STAT(source, follow_symlinks=False).st_size:
                    raise AssertionError("Synthetic fsync fault must follow the complete destination write")
                event = "continued" if self.export_fsync_events else "fault"
                self.export_fsync_events.append((event, observed.st_dev, observed.st_ino, observed.st_size))
                if event == "fault":
                    raise OSError("Synthetic single post-create export fsync failure")
            return synced

        previous = Path.cwd()
        with contextlib.ExitStack() as stack:
            stack.callback(os.chdir, previous)
            os.chdir(self.root)
            stack.enter_context(patch.dict(os.environ, self.environment, clear=True))
            stack.enter_context(patch("tempfile.tempdir", str(self.temp)))
            stack.enter_context(patch.object(sys, "argv", [str(filename)] + (["--help"] if self.case == "cli-option" else [])))
            stack.enter_context(patch("subprocess.Popen", self.launch))
            stack.enter_context(patch("os.open", observed_open))
            stack.enter_context(patch("os.read", observed_read))
            stack.enter_context(patch("os.stat", lambda value, *args, **kw: REAL_STAT(self.mapped(value), *args, **kw)))
            stack.enter_context(patch("os.lstat", lambda value, *args, **kw: REAL_LSTAT(self.mapped(value), *args, **kw)))
            stack.enter_context(patch("os.fstat", observed_fstat))
            stack.enter_context(patch("os.scandir", observed_scandir))
            stack.enter_context(patch("os.fsync", observed_fsync))
            for target in ("builtins.open", "io.open"):
                stack.enter_context(patch(target, observed_io_open))
            stack.enter_context(patch("platform.system", return_value="Linux"))
            stack.enter_context(patch("platform.machine", return_value="x86_64"))
            stack.enter_context(patch("os.uname", return_value=os.uname_result(
                ("Linux", "synthetic", "6.0", "Synthetic unit fixture", "x86_64"))))
            stack.enter_context(patch.object(sys, "platform", "linux"))
            stack.enter_context(patch("time.monotonic", lambda: REAL_MONOTONIC() + self.deadline_offset))
            stack.enter_context(patch("os.killpg", owned_signal))
            stack.enter_context(patch("os.kill", owned_pid_signal))
            stack.enter_context(contextlib.redirect_stdout(output))
            stack.enter_context(patch.dict(sys.modules, {spec.name: module}))
            spec.loader.exec_module(module)
            if tuple(inspect.signature(module.main).parameters):
                raise AssertionError("NEW main must accept no options")
            try:
                code = module.main()
            except SystemExit as stop:
                code = stop.code
        lines = [line for line in output.getvalue().splitlines() if line.strip()]
        if not lines:
            raise AssertionError("NEW main must emit its observable final JSON result")
        return code, json.loads(lines[-1])

    def close(self):
        for process in self.processes + self.probes:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()


def new_main_declared():
    try:
        tree = ast.parse((HERE / "qualify.py").read_bytes())
    except (FileNotFoundError, SyntaxError):
        return False
    return any(isinstance(node, ast.FunctionDef) and node.name == "main" for node in tree.body)


class NewOperatorBaseline(unittest.TestCase):
    def test_new_fixed_main_is_available(self):
        self.assertTrue(new_main_declared(),
                        "NEW Linux qualification operator main() is unavailable; behavior cases have not run")


class OperatorBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for path in (HERE / "inputs.json", REPOSITORY / WORKFLOW,
                     REPOSITORY / SOURCE / "test_capture_handoff.py"):
            if path.is_symlink() or not path.is_file():
                raise AssertionError(f"NEW accepted operator fixture closure is unavailable: {path}")

    def run_case(self, case="green", change=None):
        owner = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="dev786-operator-unit-")))
        run = OwnedRun(owner, case)
        self.addCleanup(run.close)
        if change:
            change(run)
        code, result = run.invoke()
        self.assertEqual(run.private_accesses, [], "Candidate traversed or opened/read excluded private contents")
        if case in {"root-entries", "class-entries"}:
            self.assertGreater(run.directory_reads[case], 0, "The watched real directory must be examined")
            self.assertLessEqual(run.directory_reads[case], 64 if case == "root-entries" else 512,
                                 "Directory discovery exceeded its actual OS entry-visit budget")
        self.assertEqual(run.forbidden_signals, [], "Candidate attempted signaling without an unreaped owned child")
        self.assertIs(type(code), int)
        self.assertEqual(set(result), {"state", "reasons", "export"})
        self.assertIn(result["state"], {"REFUSED", "FAILED", "INCOMPLETE", "QUALIFIED_PENDING_REVIEW"})
        self.assertIsInstance(result["reasons"], list)
        if result["state"] == "QUALIFIED_PENDING_REVIEW":
            self.assertEqual(code, 0)
            self.assertEqual(result["reasons"], [])
        else:
            self.assertNotEqual(code, 0)
            self.assertTrue(result["reasons"])
        return run, result

    def test_complete_selection_clean_launch_and_closed_export(self):
        run, result = self.run_case()
        self.assertEqual(result["state"], "QUALIFIED_PENDING_REVIEW")
        self.assertEqual(len(run.ids), 49)
        self.assertEqual(hashlib.sha256(("\n".join(run.ids) + "\n").encode()).hexdigest(), METHOD_IDS_SHA256)
        self.assertTrue(ACTUAL_METHODS <= {item.rsplit(".", 1)[1] for item in run.ids})
        self.assertEqual(len(run.controls), 12)
        self.assertEqual(run.inputs["version"], 1)
        self.assertEqual(run.inputs["source"], SOURCE.as_posix())
        self.assertEqual(set(run.inputs), {"version", "source", "sources", "policies", "test_ids"})
        self.assertEqual(run.inputs["test_ids"], run.ids)
        self.assertEqual(len(run.inputs["sources"]), 18)
        self.assertEqual(len(run.inputs["policies"]), 10)
        driver = ast.parse((run.root / SOURCE / "preflight.py").read_bytes())
        literals = {target.id: ast.literal_eval(node.value) for node in driver.body
                    if isinstance(node, ast.Assign) for target in node.targets
                    if isinstance(target, ast.Name) and target.id in {"MODULES", "RELEASE", "FIXTURE_HASHES"}}
        self.assertEqual(set(run.inputs["sources"]), {
            "BUNDLE_SPEC.md", "SPEC.md", "build.py", "observation.py", "preflight.py", "replay.py",
            "test_bundle_loading.py", "test_capture_handoff.py", "test_observation.py",
            *("fixtures/" + name for name in literals["FIXTURE_HASHES"]),
        })
        pins = {f".github/scripts/{name}.py": sha for name, sha in literals["MODULES"].items()}
        pins.update({f".github/native-tools/dev786/{name}": sha for name, sha in literals["RELEASE"].items()})
        self.assertEqual({name: record["sha256"] for name, record in run.inputs["policies"].items()}, pins)
        for name, expected in run.inputs["sources"].items():
            self.assertEqual(expected, identity((run.root / SOURCE / name).read_bytes()))
        for name, expected in run.inputs["policies"].items():
            self.assertEqual(expected, identity((run.root / name).read_bytes()))
        self.assertEqual(len(run.launches), 1)
        argv, options = run.launches[0]
        self.assertEqual(argv, ["/usr/bin/python3", "-I", "-S", "-B", "-m", "unittest", "discover",
                                "-s", str(run.root / SOURCE), "-p", "test_*.py", "-v"])
        self.assertEqual(set(options["env"]), {"HOME", "TMPDIR", "PATH", "LC_ALL", "DEV786_PREFLIGHT_INPUTS"})
        self.assertEqual(options["env"]["PATH"], "/usr/bin:/bin")
        self.assertEqual(options["env"]["LC_ALL"], "C.UTF-8")
        self.assertEqual(options["env"]["DEV786_PREFLIGHT_INPUTS"], str(run.root / SOURCE))
        self.assertEqual(options["stdin"], subprocess.DEVNULL)
        self.assertIs(options["close_fds"], True)
        self.assertEqual(tuple(options["pass_fds"]), ())
        self.assertIs(options["start_new_session"], True)
        for directory in (options["cwd"], options["env"]["HOME"], options["env"]["TMPDIR"]):
            self.assertTrue(Path(directory).is_absolute())
            self.assertEqual(Path(directory).stat().st_mode & 0o777, 0o700)
        export = Path(result["export"])
        self.assertTrue(export.is_relative_to(run.owner))
        self.assertEqual({path.stem for path in (export / "meta").iterdir()}, META)
        checkout = json.loads((export / "meta/checkout.json").read_bytes())
        for key, expected in {"head": run.sha, "tree": run.tree, "parent": BASE, "base_tree": BASE_TREE}.items():
            self.assertEqual(checkout[key], expected)
        context = json.loads((export / "meta/context.json").read_bytes())
        self.assertEqual(context, {
            "repository": "nold-ai/.github", "repository_id": "1110267669", "owner_id": "225190663",
            "ref": REF, "sha": run.sha, "workflow_ref": run.environment["GITHUB_WORKFLOW_REF"],
            "run_id": "123456789", "attempt": 1, "event": "push",
            "image_os": "ubuntu24", "image_version": "Synthetic-unit-fixture",
        })
        selection = json.loads((export / "meta/selection.json").read_bytes())
        self.assertEqual(selection, {"test_ids": run.ids, "actual_attempts": 1,
                                     "clock_cases": ["read-gap-before", "read-gap-after"]})
        files = {path.relative_to(export).as_posix(): path for path in export.rglob("*") if path.is_file()}
        for path in export.rglob("*"):
            attributes = path.lstat()
            self.assertTrue(stat.S_ISDIR(attributes.st_mode) or stat.S_ISREG(attributes.st_mode))
            if stat.S_ISREG(attributes.st_mode):
                self.assertEqual(attributes.st_nlink, 1)
        self.assertLessEqual(len(files), 128)
        self.assertLessEqual(sum(path.stat().st_size for path in files.values()), 67108864)
        inventory = json.loads((export / "meta/files.json").read_bytes())
        self.assertEqual(inventory, {name: identity(path.read_bytes()) for name, path in files.items()
                                     if name != "meta/files.json"})
        self.assertEqual((export / "actual/control_child.py").read_bytes(), run.child)
        expected_files = {f"meta/{name}.json" for name in META} | {
            "suite/stdout", "suite/stderr", "actual/control_child.py", "actual/stdout", "actual/stderr",
        }
        for original in (run.evidence / "001-actual-controls/owned").rglob("*"):
            if original.is_file():
                relative = original.relative_to(run.evidence / "001-actual-controls")
                self.assertEqual((export / "actual" / relative).read_bytes(), original.read_bytes())
                expected_files.add("actual/" + relative.as_posix())
        self.assertEqual(set(files), expected_files)
        self.assertEqual((export / "actual/stdout").read_bytes(),
                         (run.evidence / "001-actual-controls/stdout").read_bytes())
        self.assertEqual((export / "actual/stderr").read_bytes(), b"")
        self.assertEqual((export / "suite/stdout").read_bytes(), b"")
        self.assertEqual((export / "suite/stderr").read_bytes(), run.suite_log)
        self.assertEqual(json.loads((export / "meta/result.json").read_bytes()), result)
        self.assertEqual(json.loads((export / "meta/source-before.json").read_bytes()),
                         {"sources": run.inputs["sources"], "policies": run.inputs["policies"]})
        self.assertEqual(json.loads((export / "meta/tools-before.json").read_bytes()),
                         {name: identity(path.read_bytes()) for name, path in run.tool_paths.items()})
        cleanup = json.loads((export / "meta/cleanup.json").read_bytes())
        self.assertIs(cleanup["suite"]["reaped"], True)
        self.assertEqual(cleanup["suite"]["wait"], run.processes[0].returncode)
        self.assertEqual(cleanup["nested_sessions"], "diagnostic-owned")
        for before, after in (("source-before", "source-after"), ("tools-before", "tools-after")):
            self.assertEqual(json.loads((export / f"meta/{before}.json").read_bytes()),
                             json.loads((export / f"meta/{after}.json").read_bytes()))
        self.assertTrue(all(process.returncode == 0 for process in run.processes))
        actual = run.evidence / "001-actual-controls"
        self.assertEqual({path.name for path in actual.iterdir()}, {"home", "tmp", "stdout", "stderr", "owned"})
        for name in ("home", "tmp"):
            attributes = (actual / name).lstat()
            self.assertTrue(stat.S_ISDIR(attributes.st_mode))
            self.assertEqual(attributes.st_mode & 0o777, 0o700)
        for name, path in files.items():
            self.assertFalse(name.startswith(("actual/home/", "actual/tmp/")))
            self.assertNotIn(b"SYNTHETIC-PRIVATE-", path.read_bytes())

    def test_context_and_creation_refuse_before_suite_launch(self):
        run, result = self.run_case("cli-option")
        self.assertEqual(result["state"], "REFUSED")
        self.assertEqual(run.launches, [])
        for key, value in (("GITHUB_REPOSITORY", "foreign/repo"), ("GITHUB_REPOSITORY_ID", "1"),
                           ("GITHUB_REPOSITORY_OWNER_ID", "1"), ("GITHUB_REF", "refs/heads/main"),
                           ("GITHUB_RUN_ATTEMPT", "2"), ("GITHUB_EVENT_NAME", "workflow_dispatch"),
                           ("GITHUB_SHA", "f" * 40), ("GITHUB_WORKFLOW_REF", "foreign/workflow"),
                           ("GH_TOKEN", "Synthetic-not-a-secret")):
            with self.subTest(key=key):
                run, result = self.run_case(change=lambda run: run.environment.__setitem__(key, value))
                self.assertEqual(result["state"], "REFUSED")
                self.assertEqual(run.launches, [])
        for key, value in (("before", "1" * 40), ("created", False), ("deleted", True)):
            with self.subTest(event=key):
                def change(run):
                    event = json.loads(run.event.read_bytes())
                    event[key] = value
                    run.event.write_text(json.dumps(event))
                run, result = self.run_case(change=change)
                self.assertEqual(result["state"], "REFUSED")
                self.assertEqual(run.launches, [])

    def test_source_type_identity_and_checkout_caps_refuse_before_launch(self):
        for case in ("source", "symlink", "gitlink", "operator-cap", "git-cap", "unknown-file",
                     "tool-missing", "wrong-python", "input-path"):
            with self.subTest(case=case):
                def change(run):
                    source = run.root / SOURCE / "replay.py"
                    if case == "source":
                        source.write_bytes(source.read_bytes() + b"\n")
                    elif case == "symlink":
                        source.unlink()
                        source.symlink_to(run.root / SOURCE / "observation.py")
                    elif case == "gitlink":
                        git_read("update-index", "--add", "--cacheinfo", f"160000,{BASE},foreign-submodule", cwd=run.root)
                    elif case == "operator-cap":
                        (run.root / OPERATOR / "qualify.py").write_bytes(
                            (run.root / OPERATOR / "qualify.py").read_bytes() + b"\n#" + b"x" * 131072)
                    elif case == "git-cap":
                        with (run.root / ".git/oversize").open("wb") as stream:
                            stream.truncate(33554433)
                    elif case == "tool-missing":
                        run.tool_paths["/usr/bin/strace"].unlink()
                    elif case == "wrong-python":
                        run.case = case
                    elif case == "input-path":
                        inputs = json.loads(run.inputs_path.read_bytes())
                        inputs["source"] = "../outside"
                        run.inputs_path.write_text(json.dumps(inputs))
                    else:
                        (run.root / "unknown").write_bytes(b"unreviewed")
                run, result = self.run_case(change=change)
                self.assertEqual(result["state"], "REFUSED")
                self.assertEqual(run.launches, [])

    def test_after_launch_source_tool_and_checkout_drift_prevent_success(self):
        for case in ("source-drift", "tool-drift", "checkout-drift"):
            with self.subTest(case=case):
                run, result = self.run_case(case)
                self.assertEqual(len(run.launches), 1)
                self.assertIn(result["state"], {"FAILED", "INCOMPLETE"})

    def test_nonzero_skip_and_missing_method_cannot_be_green(self):
        for case in ("nonzero", "skipped", "omitted-id", "duplicate-id", "failure", "error"):
            with self.subTest(case=case):
                run, result = self.run_case(case)
                self.assertEqual(len(run.launches), 1)
                self.assertEqual(result["state"], "FAILED")
                self.assertTrue(Path(result["export"]).is_dir())
                self.assertTrue((Path(result["export"]) / "suite/stderr").read_bytes())

        run, result = self.run_case("partial-control-failure")
        self.assertEqual(len(run.launches), 1)
        self.assertEqual(run.processes[0].returncode, 7)
        self.assertEqual(result["state"], "INCOMPLETE")
        self.assertTrue(result["export"])
        export = Path(result["export"])
        self.assertTrue(export.is_relative_to(run.owner))
        self.assertTrue(export.is_dir())
        self.assertEqual(export.stat().st_mode & 0o777, 0o700)
        expected = {"suite/stdout": b"", "suite/stderr": run.suite_log,
                    "actual/control_child.py": run.child}
        expected.update({"actual/" + name: raw for name, raw in run.partial_files.items()})
        files = {}
        for path in export.rglob("*"):
            attributes = path.lstat()
            self.assertTrue(stat.S_ISDIR(attributes.st_mode) or stat.S_ISREG(attributes.st_mode))
            if stat.S_ISREG(attributes.st_mode):
                self.assertEqual(attributes.st_nlink, 1)
                files[path.relative_to(export).as_posix()] = path
        self.assertLessEqual(len(files), 128)
        self.assertLessEqual(sum(path.stat().st_size for path in files.values()), 67108864)
        self.assertTrue(set(files) <= set(expected) | {f"meta/{name}.json" for name in META})
        for name, raw in expected.items():
            self.assertIn(name, files)
            self.assertLessEqual(files[name].stat().st_size, 16384 if name == "actual/control_child.py" else 1048576)
            self.assertEqual(files[name].read_bytes(), raw)
        self.assertEqual(set(files) - {f"meta/{name}.json" for name in META}, set(expected))
        self.assertFalse((export / "actual/owned/read-gap-after-evidence").exists())
        for name in run.controls:
            self.assertFalse((export / "actual/owned" / name).exists())
        for name, path in files.items():
            self.assertFalse(name.startswith(("actual/home/", "actual/tmp/")))
            self.assertNotIn(b"SYNTHETIC-PRIVATE-", path.read_bytes())

        for case in ("missing-owned-failure", "missing-owned-output-failure"):
            with self.subTest(case=case):
                run, result = self.run_case(case)
                self.assertEqual(len(run.launches), 1)
                self.assertEqual(run.processes[0].returncode, 7)
                self.assertEqual(result["state"], "INCOMPLETE")
                self.assertTrue(result["export"])
                self.assertFalse((run.evidence / "001-actual-controls/owned").exists())
                export = Path(result["export"])
                self.assertTrue(export.is_relative_to(run.owner))
                expected = {"suite/stdout": b"", "suite/stderr": run.suite_log,
                            "actual/control_child.py": run.child}
                expected.update({"actual/" + name: raw for name, raw in run.partial_files.items()})
                files = {path.relative_to(export).as_posix(): path for path in export.rglob("*") if path.is_file()}
                self.assertEqual(set(files) - {f"meta/{name}.json" for name in META}, set(expected))
                self.assertLessEqual(len(files), 128)
                self.assertLessEqual(sum(path.stat().st_size for path in files.values()), 67108864)
                for name, raw in expected.items():
                    self.assertIn(name, files)
                    self.assertLessEqual(files[name].stat().st_size,
                                         16384 if name == "actual/control_child.py" else 1048576)
                    self.assertEqual(files[name].read_bytes(), raw)
                for name, path in files.items():
                    self.assertFalse(name.startswith(("actual/home/", "actual/tmp/")))
                    self.assertNotIn(b"SYNTHETIC-PRIVATE-", path.read_bytes())
                self.assertEqual(json.loads((export / "meta/result.json").read_bytes()), result)
                self.assertIs(json.loads((export / "meta/selection.json").read_bytes())["evidence_complete"], False)
                self.assertEqual(json.loads((export / "meta/cleanup.json").read_bytes())["nested_sessions"], "unproved")

    def test_output_and_deadline_failures_reap_only_owned_child(self):
        for case in ("stdout-overflow", "stderr-overflow", "deadline"):
            with self.subTest(case=case):
                run, result = self.run_case(case)
                self.assertIn(result["state"], {"FAILED", "INCOMPLETE"})
                self.assertEqual(len(run.processes), 1)
                self.assertIsNotNone(run.processes[0].returncode)
                with self.assertRaises(ChildProcessError):
                    os.waitpid(run.processes[0].pid, os.WNOHANG)
                export = Path(result["export"])
                cleanup = json.loads((export / "meta/cleanup.json").read_bytes())
                self.assertEqual(cleanup["suite"]["pid"], run.processes[0].pid)
                self.assertIs(cleanup["suite"]["reaped"], True)
                for stream in ("stdout", "stderr"):
                    self.assertLessEqual((export / "suite" / stream).stat().st_size, 1048576)
                self.assertTrue(all(pid == run.processes[0].pid for pid, _ in run.signals))

    def test_export_refuses_unsafe_missing_and_excess_members(self):
        for case in ("unknown", "missing", "symlink", "hardlink", "fifo", "file-cap", "trace-count",
                     "two-attempts", "two-roots", "short-gap", "unstable", "root-entries", "class-entries",
                     "script-cap", "pid-cap", "trace-cap", "clock-cap", "manifest-cap", "environment-cap",
                     "global-files", "global-bytes"):
            with self.subTest(case=case):
                run, result = self.run_case(case)
                self.assertEqual(len(run.launches), 1)
                self.assertEqual(result["state"], "INCOMPLETE")
                if result["export"]:
                    for path in Path(result["export"]).rglob("*"):
                        self.assertFalse(path.is_symlink())
                        if path.is_file():
                            self.assertNotIn(b"DO-NOT-EXPORT-FOREIGN-BYTES", path.read_bytes())

        run, result = self.run_case("clock-combined-cap")
        self.assertEqual(len(run.launches), 1)
        self.assertEqual(result["state"], "INCOMPLETE")
        clock = run.evidence / "001-actual-controls/owned/read-gap-before-evidence"
        sizes = [(clock / name).stat().st_size for name in ("commands.jsonl", "raw-output.bin")]
        self.assertEqual(sizes, [1048575, 1048578])
        self.assertTrue(all(size < 2097152 for size in sizes))
        self.assertEqual(sum(sizes), 2097153)
        if result["export"]:
            relative = Path(result["export"]).relative_to(run.owner)
            self.assertNotIn("..", relative.parts)
            retained = 0
            with contextlib.ExitStack() as stack:
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                directory = REAL_OPEN(run.owner, flags)
                stack.callback(os.close, directory)
                for part in relative.parts + ("actual", "owned", "read-gap-before-evidence"):
                    try:
                        directory = REAL_OPEN(part, flags, dir_fd=directory)
                    except FileNotFoundError:
                        directory = None
                        break
                    stack.callback(os.close, directory)
                if directory is not None:
                    for name in ("commands.jsonl", "raw-output.bin"):
                        try:
                            attributes = REAL_STAT(name, dir_fd=directory, follow_symlinks=False)
                        except FileNotFoundError:
                            continue
                        self.assertTrue(stat.S_ISREG(attributes.st_mode))
                        self.assertEqual(attributes.st_nlink, 1)
                        retained += attributes.st_size
            self.assertLessEqual(retained, 2097152, "Failure exports must preserve the combined clock byte cap")

        for case in ("global-files", "global-bytes"):
            with self.subTest(case=case, fault="single-post-create-fsync"):
                run, result = self.run_case(case, change=lambda run: setattr(run, "export_fsync_fault", True))
                self.assertEqual(len(run.launches), 1)
                self.assertEqual(result["state"], "INCOMPLETE")
                self.assertEqual([event[0] for event in run.export_fsync_events], ["fault", "continued"],
                                 "The single real target sync and later export work must both be reached")
                retained = {}
                visited = 0
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

                def visit(directory, parts=()):
                    nonlocal visited
                    with REAL_SCANDIR(directory) as entries:
                        while True:
                            self.assertLess(visited, 320, "Physical export discovery exceeded its entry budget")
                            try:
                                entry = next(entries)
                            except StopIteration:
                                break
                            visited += 1
                            attributes = REAL_STAT(entry.name, dir_fd=directory, follow_symlinks=False)
                            relative = parts + (entry.name,)
                            if stat.S_ISDIR(attributes.st_mode):
                                self.assertLess(len(parts), 3, "Physical export exceeded its fixed directory depth")
                                child = REAL_OPEN(entry.name, flags, dir_fd=directory)
                                try:
                                    visit(child, relative)
                                finally:
                                    os.close(child)
                            else:
                                self.assertTrue(stat.S_ISREG(attributes.st_mode))
                                self.assertEqual(attributes.st_nlink, 1)
                                retained["/".join(relative)] = attributes

                with contextlib.ExitStack() as stack:
                    directory = REAL_OPEN(run.owner, flags)
                    stack.callback(os.close, directory)
                    for part in ("runner", "dev786-linux-qualification-123456789-1", "export"):
                        directory = REAL_OPEN(part, flags, dir_fd=directory)
                        stack.callback(os.close, directory)
                    visit(directory)
                for event, control, filename in zip(run.export_fsync_events, sorted(run.controls),
                                                     ("trace.123", "control.sh")):
                    name = "actual/owned/" + control + "/" + filename
                    self.assertIn(name, retained, "Synced physical evidence must remain observable after main returns")
                    attributes = retained[name]
                    self.assertEqual((attributes.st_dev, attributes.st_ino, attributes.st_size), event[1:])
                self.assertLessEqual(len(retained), 128, "Post-create failures must preserve the physical file cap")
                self.assertLessEqual(sum(item.st_size for item in retained.values()), 67108864,
                                     "Post-create failures must preserve the physical byte cap")

        for case in ("unknown-attempt-sibling", "home-symlink", "tmp-symlink", "home-wrongtype",
                     "tmp-wrongtype", "missing-home", "missing-tmp"):
            with self.subTest(case=case):
                run, result = self.run_case(case)
                self.assertEqual(len(run.launches), 1)
                self.assertEqual(result["state"], "INCOMPLETE")
                if result["export"]:
                    for path in Path(result["export"]).rglob("*"):
                        self.assertFalse(path.is_symlink())
                        if path.is_file():
                            relative = path.relative_to(result["export"]).as_posix()
                            self.assertFalse(relative.startswith(("actual/home/", "actual/tmp/")))
                            raw = path.read_bytes()
                            self.assertNotIn(b"SYNTHETIC-PRIVATE-", raw)
                            self.assertNotIn(b"DO-NOT-EXPORT-FOREIGN-BYTES", raw)

    def test_outer_interruption_cannot_claim_cleanup_or_signal_without_ownership(self):
        run, result = self.run_case("outer-interrupt")
        self.assertEqual(result["state"], "INCOMPLETE")
        self.assertEqual(run.signals, [])
        if result["export"]:
            cleanup = json.loads((Path(result["export"]) / "meta/cleanup.json").read_bytes())
            self.assertIs(cleanup["suite"]["reaped"], False)
        run.close()
        for process in run.processes + run.probes:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    self.assertTrue(stream.closed, "The fixture must close every pipe it owns")

    def test_stderr_paths_do_not_select_foreign_files(self):
        run, result = self.run_case("foreign-stderr-path")
        self.assertIn(result["state"], {"FAILED", "INCOMPLETE"})
        export = Path(result["export"])
        self.assertEqual((export / "actual/stderr").read_text(), str(run.owner / "outside"))
        for path in export.rglob("*"):
            if path.is_file():
                self.assertNotIn(b"DO-NOT-EXPORT-FOREIGN-BYTES", path.read_bytes())


def load_tests(loader, tests, pattern):
    if not new_main_declared():
        return loader.loadTestsFromTestCase(NewOperatorBaseline)
    return loader.loadTestsFromTestCase(OperatorBehaviorTests)


if __name__ == "__main__":
    unittest.main(verbosity=2)
