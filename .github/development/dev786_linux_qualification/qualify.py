import ast
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import stat
import subprocess
import sys
import time


_SOURCE = ".github/development/dev786_original_replay"
_OPERATOR = ".github/development/dev786_linux_qualification"
_WORKFLOW = ".github/workflows/dev786-linux-qualification.yml"
_REF = "refs/heads/codex/dev786-linux-qualification-20261027-02"
_BASE = "640549e62fb3ca001499e71d4cf935aa8c0a0192"
_BASE_TREE = "2d27c800651b3e1b30d46078594a61937410f4cc"
_INPUT_SHA = "050cf23a0679000e74bcf55d70a4dfad414767195a535b47aeb91da92fe030e1"
_ID_SHA = "047ec5cb32f0a035d76f986974b2b03a806e621ae1bf4634409006fcdd3f7033"
_TOOLS = ("/usr/bin/python3", "/usr/bin/strace", "/bin/sh")
_MIB = 1048576
_CLEAN = {"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"}


def _require(condition, reason):
    if not condition:
        raise ValueError(reason)


def _identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"


def _attributes(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_uid, value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


class _Directory:

    def __init__(self, path):
        self.path = Path(path)
        _require(self.path.is_absolute(), "directory is not absolute")
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in self.path.parts[1:]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            self.fd = fd
            self.before = os.fstat(fd)
        except BaseException:
            os.close(fd)
            raise

    def close(self):
        os.close(self.fd)

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()

    def names(self, maximum):
        names = []
        with os.scandir(self.fd) as entries:
            while True:
                _require(len(names) < maximum, "directory entry cap")
                try:
                    entry = next(entries)
                except StopIteration:
                    break
                names.append(entry.name)
        self.stable()
        return sorted(names)

    def stable(self):
        current = os.stat(self.path, follow_symlinks=False)
        descriptor = os.fstat(self.fd)
        _require(stat.S_ISDIR(current.st_mode) and
                 (current.st_dev, current.st_ino) == (self.before.st_dev, self.before.st_ino) ==
                 (descriptor.st_dev, descriptor.st_ino), "directory identity changed")

    def read(self, name, maximum):
        _require(name not in ("", ".", "..") and "/" not in name, "invalid member")
        before = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                 before.st_size <= maximum, "unsafe or over-cap file")
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        try:
            opened = os.fstat(fd)
            _require(_attributes(before) == _attributes(opened), "file changed before read")
            chunks = []
            remaining = before.st_size
            while remaining:
                raw = os.read(fd, min(65536, remaining))
                if not raw:
                    break
                chunks.append(raw)
                remaining -= len(raw)
            data = b"".join(chunks)
            after = os.fstat(fd)
            path_after = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            _require(len(data) == before.st_size and len(data) <= maximum and
                     _attributes(before) == _attributes(after) == _attributes(path_after),
                     "incomplete or changing file")
            self.stable()
            return data
        finally:
            os.close(fd)


def _read(path, maximum):
    with _Directory(Path(path).parent) as directory:
        return directory.read(Path(path).name, maximum)


def _tree_files(root, maximum_files, maximum_bytes, maximum_entries=320, exclude=()):
    files = {}
    count = total = 0

    def visit(path, prefix):
        nonlocal count, total
        with _Directory(path) as directory:
            for name in directory.names(maximum_entries):
                if not prefix and name in exclude:
                    continue
                count += 1
                _require(count <= maximum_entries, "tree directory entry cap")
                relative = prefix + name
                entry = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
                if stat.S_ISDIR(entry.st_mode):
                    visit(path / name, relative + "/")
                else:
                    _require(len(files) < maximum_files, "tree file count cap")
                    raw = directory.read(name, maximum_bytes - total)
                    total += len(raw)
                    files[relative] = (_identity(raw), "100755" if entry.st_mode & 0o111 else "100644",
                                       hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest())
            directory.stable()
    visit(Path(root), "")
    return files


def _owned_anchor(process):
    _require(process.poll() is None, "child already reaped")
    _require(os.getpgid(process.pid) == process.pid, "owned child session changed")


def _finish_child(process, abnormal):
    receipt = {"pid": process.pid, "reaped": False, "wait": None, "signals": []}
    if abnormal:
        for sig in (signal.SIGTERM, signal.SIGKILL):
            if process.poll() is not None:
                break
            _owned_anchor(process)
            os.killpg(process.pid, sig)
            receipt["signals"].append(int(sig))
            end = time.monotonic() + 5
            while time.monotonic() < end:
                if process.poll() is not None:
                    break
                time.sleep(0.01)
            if process.returncode is not None:
                break
    receipt["wait"] = process.wait(timeout=5)
    receipt["reaped"] = True
    return receipt


def _command(argv, cwd, environment, seconds, maximum, owner_deadline):
    end = min(time.monotonic() + seconds, owner_deadline)
    process = None
    output = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    problem = None
    cleanup = {"reaped": False, "wait": None}
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   close_fds=True, pass_fds=(), start_new_session=True)
        for name in output:
            stream = getattr(process, name)
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            _require(time.monotonic() < end, "command deadline")
            for key, unused in selector.select(min(0.05, max(0, end - time.monotonic()))):
                raw = os.read(key.fileobj.fileno(), 65536)
                if not raw:
                    selector.unregister(key.fileobj)
                    continue
                target = output[key.data]
                available = maximum - len(target)
                target.extend(raw[:available])
                _require(len(raw) <= available, "command output overflow; retained prefix is incomplete")
        while process.poll() is None:
            _require(time.monotonic() < end, "command deadline")
            time.sleep(0.01)
    except BaseException as error:
        problem = type(error).__name__ + ": " + str(error)
    finally:
        selector.close()
        if process is not None:
            try:
                cleanup = _finish_child(process, problem is not None)
            except BaseException as error:
                problem = (problem or "") + "; cleanup unproved: " + type(error).__name__
            for name in output:
                stream = getattr(process, name)
                if stream is not None:
                    stream.close()
    return {"argv": argv, "exit": cleanup.get("wait"), "problem": problem,
            "cleanup": cleanup, **{name: bytes(raw) for name, raw in output.items()}}


def _context():
    environment = dict(os.environ)
    allowed = set(_CLEAN) | {"HOME", "TMPDIR", "RUNNER_TEMP", "GITHUB_WORKSPACE",
        "GITHUB_REPOSITORY", "GITHUB_REPOSITORY_ID", "GITHUB_REPOSITORY_OWNER_ID", "GITHUB_REF",
        "GITHUB_SHA", "GITHUB_EVENT_NAME", "GITHUB_EVENT_PATH", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
        "GITHUB_WORKFLOW", "GITHUB_WORKFLOW_REF", "ImageOS", "ImageVersion"}
    _require(set(environment) == allowed, "operator environment is not the closed context")
    fixed = {**_CLEAN, "GITHUB_REPOSITORY": "nold-ai/.github", "GITHUB_REPOSITORY_ID": "1110267669",
        "GITHUB_REPOSITORY_OWNER_ID": "225190663", "GITHUB_REF": _REF, "GITHUB_EVENT_NAME": "push",
        "GITHUB_RUN_ATTEMPT": "1", "GITHUB_WORKFLOW": "dev786-linux-qualification",
        "GITHUB_WORKFLOW_REF": "nold-ai/.github/" + _WORKFLOW + "@" + _REF, "ImageOS": "ubuntu24"}
    _require(all(environment.get(key) == value for key, value in fixed.items()), "wrong run context")
    _require(re.fullmatch(r"[0-9a-f]{40}", environment["GITHUB_SHA"]) and
             re.fullmatch(r"[1-9][0-9]{0,19}", environment["GITHUB_RUN_ID"]), "invalid run identity")
    _require(platform.system() == "Linux" and platform.machine() == "x86_64", "unsupported host")
    _require(0 < len(environment["ImageVersion"]) <= 256 and
             not any(ord(char) < 32 for char in environment["ImageVersion"]), "invalid image label")
    for key in ("HOME", "TMPDIR", "RUNNER_TEMP", "GITHUB_WORKSPACE", "GITHUB_EVENT_PATH"):
        _require(Path(environment[key]).is_absolute(), "nonabsolute context path")
    event = json.loads(_read(Path(environment["GITHUB_EVENT_PATH"]), 65536))
    _require(event.get("before") == "0" * 40 and event.get("after") == environment["GITHUB_SHA"] and
             event.get("created") is True and event.get("deleted") is False and event.get("ref") == _REF,
             "not the one branch creation")
    context = {"repository": environment["GITHUB_REPOSITORY"], "repository_id": environment["GITHUB_REPOSITORY_ID"],
        "owner_id": environment["GITHUB_REPOSITORY_OWNER_ID"], "ref": _REF, "sha": environment["GITHUB_SHA"],
        "workflow_ref": environment["GITHUB_WORKFLOW_REF"], "run_id": environment["GITHUB_RUN_ID"],
        "attempt": 1, "event": "push", "image_os": environment["ImageOS"], "image_version": environment["ImageVersion"]}
    return environment, context


def _git(root, arguments, deadline):
    result = _command(["/usr/bin/git", *arguments], root,
                      {**_CLEAN, "GIT_OPTIONAL_LOCKS": "0", "GIT_CONFIG_NOSYSTEM": "1",
                       "GIT_CONFIG_GLOBAL": "/dev/null"}, 5, 2 * _MIB, deadline)
    _require(result["problem"] is None and result["exit"] == 0 and not result["stderr"], "Git query failed")
    return result["stdout"]


def _git_tree(raw):
    value = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        header, name = record.split(b"\t", 1)
        mode, kind, sha = header.decode().split()
        name = name.decode("utf-8")
        _require(kind == "blob" and mode in ("100644", "100755") and
                 name not in value and not name.startswith("/") and
                 all(part not in ("", ".", "..") for part in name.split("/")), "unsafe Git tree")
        value[name] = (mode, sha)
    return value


def _checkout(root, sha, inputs, deadline):
    _require(Path.cwd() == root and Path(__file__).absolute() == root / _OPERATOR / "qualify.py",
             "operator is outside exact workspace")
    head = _git(root, ["rev-parse", "HEAD"], deadline).decode().strip()
    tree = _git(root, ["rev-parse", "HEAD^{tree}"], deadline).decode().strip()
    parent = _git(root, ["rev-parse", "HEAD^@"], deadline).decode().strip()
    base_tree = _git(root, ["rev-parse", _BASE + "^{tree}"], deadline).decode().strip()
    _require(head == sha and parent == _BASE and base_tree == _BASE_TREE, "wrong candidate ancestry")
    base = _git_tree(_git(root, ["ls-tree", "-rz", "--full-tree", _BASE], deadline))
    tracked = _git_tree(_git(root, ["ls-tree", "-rz", "--full-tree", "HEAD"], deadline))
    additions = {f"{_SOURCE}/{name}" for name in inputs["sources"]} | {
        f"{_OPERATOR}/{name}" for name in ("SPEC.md", "test_qualify.py", "inputs.json", "qualify.py")} | {_WORKFLOW}
    _require(set(tracked) == set(base) | additions and not (set(base) & additions) and
             all(tracked[name] == value for name, value in base.items()), "unreviewed checkout delta")
    files = _tree_files(root, 64, 2 * _MIB, exclude=(".git",))
    _require(set(files) == set(tracked) and
             all((record[1], record[2]) == tracked[name] for name, record in files.items()),
             "checkout differs from candidate tree")
    _require(sum(files[name][0]["bytes"] for name in additions if name not in
                 {f"{_SOURCE}/{item}" for item in inputs["sources"]}) <= 131072, "operator aggregate cap")
    index = _git(root, ["ls-files", "--stage", "-z"], deadline)
    staged = {}
    for record in index.split(b"\0"):
        if record:
            header, name = record.split(b"\t", 1)
            mode, object_id, stage = header.decode().split()
            _require(stage == "0" and name.decode() not in staged, "unmerged or duplicate index")
            staged[name.decode()] = (mode, object_id)
    _require(staged == tracked, "index differs from HEAD")
    _require(not _git(root, ["status", "--porcelain=v1", "--untracked-files=all"], deadline), "dirty checkout")
    git_directory = Path(_git(root, ["rev-parse", "--absolute-git-dir"], deadline).decode().strip())
    _require(git_directory == root / ".git", "unexpected Git storage")
    git_files = _tree_files(git_directory, 128, 32 * _MIB, 320)
    return {"head": head, "tree": tree, "parent": parent, "base_tree": base_tree,
            "files": {name: value[0] for name, value in files.items()},
            "index": _identity(index), "git_storage_bytes": sum(value[0]["bytes"] for value in git_files.values())}


def _source(root):
    raw = _read(root / _OPERATOR / "inputs.json", 65536)
    _require(_identity(raw)["sha256"] == _INPUT_SHA, "changed input closure")
    inputs = json.loads(raw)
    _require(set(inputs) == {"version", "source", "sources", "policies", "test_ids"} and
             inputs["version"] == 1 and inputs["source"] == _SOURCE and
             len(inputs["sources"]) == 18 and len(inputs["policies"]) == 10, "invalid input schema")
    snapshot = {"sources": {}, "policies": {}}
    source_bytes = {}
    for group, prefix in (("sources", root / _SOURCE), ("policies", root)):
        for name, expected in inputs[group].items():
            _require(not name.startswith("/") and all(part not in ("", ".", "..") for part in name.split("/")),
                     "input path escaped closure")
            data = _read(prefix / name, 2 * _MIB)
            _require(_identity(data) == expected, "source or policy changed")
            snapshot[group][name] = expected
            if group == "sources":
                source_bytes[name] = data
    ids = []
    for name, data in source_bytes.items():
        if name.startswith("test_") and name.endswith(".py"):
            for node in ast.parse(data).body:
                if isinstance(node, ast.ClassDef):
                    ids.extend(f"{name[:-3]}.{node.name}.{item.name}" for item in node.body
                               if isinstance(item, ast.FunctionDef) and item.name.startswith("test_"))
    ids.sort()
    _require(ids == inputs["test_ids"] and len(ids) == 49 and len(set(ids)) == 49 and
             hashlib.sha256(("\n".join(ids) + "\n").encode()).hexdigest() == _ID_SHA, "wrong test selection")
    capture = ast.parse(source_bytes["test_capture_handoff.py"])
    replay = ast.parse(source_bytes["replay.py"])

    def assigned(tree, name):
        return next(node.value for node in tree.body if isinstance(node, ast.Assign) and
                    any(isinstance(target, ast.Name) and target.id == name for target in node.targets))
    child = ast.literal_eval(assigned(capture, "CONTROL_CHILD")).encode()
    controls = [ast.literal_eval(item.elts[0]) for item in assigned(replay, "_CONTROLS").elts]
    marker = ast.literal_eval(assigned(replay, "_NAME")).decode()
    _require(len(child) <= 16384 and len(controls) == len(set(controls)) == 12 and
             all(re.fullmatch(r"[a-z0-9-]{1,64}", name) for name in controls) and
             re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", marker), "invalid inert evidence membership")
    return inputs, snapshot, (ids, child, controls, marker)


def _tools():
    identities, opened = {}, {}
    for path in _TOOLS:
        fd = os.open(path, os.O_RDONLY)
        try:
            before = os.fstat(fd)
            _require(stat.S_ISREG(before.st_mode) and before.st_size <= 64 * _MIB and
                     before.st_mode & 0o111, "missing or unsupported system tool")
            digest = hashlib.sha256()
            size = 0
            while True:
                raw = os.read(fd, 65536)
                if not raw:
                    break
                size += len(raw)
                _require(size <= 64 * _MIB, "system tool cap")
                digest.update(raw)
            after = os.fstat(fd)
            _require(_attributes(before) == _attributes(after) == _attributes(os.stat(path)) and
                     size == before.st_size, "system tool changed during fingerprint")
            canonical = os.path.realpath(path)
            if os.path.isdir("/proc/self/fd"):
                canonical = os.readlink(f"/proc/self/fd/{fd}")
            identities[path] = {"bytes": size, "sha256": digest.hexdigest()}
            opened[path] = {"opened_path": canonical, "metadata": list(_attributes(before))}
        finally:
            os.close(fd)
    return identities, opened


def _probes(cwd, environment, deadline):
    receipts = []
    for argv in (["/usr/bin/python3", "--version"], ["/usr/bin/strace", "--version"],
                 ["/usr/bin/strace", "--help"], ["/bin/sh", "--version"], ["/usr/bin/git", "--version"]):
        result = _command(argv, cwd, environment, 5, 65536, deadline)
        _require(result["problem"] is None and result["cleanup"]["reaped"], "probe incomplete")
        _require(argv[0] == "/bin/sh" or result["exit"] == 0, "required probe failed")
        if argv[0] == "/usr/bin/python3":
            _require(re.fullmatch(rb"Python 3\.12\.[^\r\n]+\r?\n?", result["stdout"] + result["stderr"]),
                     "existing Python is not 3.12")
        receipts.append({key: value for key, value in result.items() if key not in ("stdout", "stderr")})
        receipts[-1].update({name: {**_identity(result[name]), "base64": base64.b64encode(result[name]).decode()}
                             for name in ("stdout", "stderr")})
    return receipts


class _Export:
    def __init__(self, path, deadline):
        self.path, self.deadline = path, deadline
        self.path.mkdir(mode=0o700)
        self.files = {}
        self.reserved_files = 0
        self.reserved_bytes = 0
        self.directories = set()

    def put(self, name, raw, maximum=65536):
        _require(time.monotonic() < self.deadline, "evidence deadline")
        _require(name not in self.files and len(raw) <= maximum and self.reserved_files < 128 and
                 self.reserved_bytes + len(raw) <= 64 * _MIB, "export cap")
        destination = self.path / name
        relative = Path(name)
        _require(not relative.is_absolute() and all(part not in ("", ".", "..") for part in relative.parts),
                 "invalid export name")
        self.reserved_files += 1
        self.reserved_bytes += len(raw)
        for parent in reversed(list(relative.parents)[:-1]):
            if parent.as_posix() not in self.directories:
                (self.path / parent).mkdir(mode=0o700)
                self.directories.add(parent.as_posix())
        _require(len(self.directories) + self.reserved_files <= 320, "export directory entry cap")
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            view = memoryview(raw)
            while view:
                count = os.write(fd, view)
                _require(count > 0, "short export write")
                view = view[count:]
            os.fsync(fd)
        finally:
            os.close(fd)
        _require(_read(destination, maximum) == raw, "export hash-copy mismatch")
        self.files[name] = _identity(raw)


def _evidence(export, tmp, contract, reasons):
    ids, child, controls, marker = contract
    collected = {}
    complete = True

    def missing(reason):
        nonlocal complete
        complete = False
        reasons.append(reason)

    def copy(directory, name, destination, cap):
        try:
            raw = directory.read(name, cap)
            export.put(destination, raw, cap)
            collected[destination] = raw
            return raw
        except (OSError, ValueError) as error:
            missing(destination + ": " + str(error))
            return None

    try:
        with _Directory(tmp) as directory:
            roots = [name for name in directory.names(64)
                     if re.fullmatch(r"dev786-capture-tests-[A-Za-z0-9_-]{1,32}", name)]
        _require(len(roots) == 1, "not exactly one actual test root")
        root = tmp / roots[0]
        with _Directory(root) as directory:
            attempts = [name for name in directory.names(512) if re.fullmatch(r"[0-9]{3}-actual-controls", name)]
            _require(len(attempts) == 1, "not exactly one actual control attempt")
            actual_child = copy(directory, "control_child.py", "actual/control_child.py", 16384)
            _require(actual_child == child, "control child differs from source literal")
        actual = root / attempts[0]
        with _Directory(actual) as directory:
            stdout = copy(directory, "stdout", "actual/stdout", _MIB)
            stderr = copy(directory, "stderr", "actual/stderr", _MIB)
            names = set(directory.names(6))
            required = {"home", "tmp", "stdout", "stderr", "owned"}
            _require(names <= required, "unknown actual member")
            if names != required:
                missing("actual membership incomplete")
            for name in ("home", "tmp"):
                if name in names:
                    entry = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
                    _require(stat.S_ISDIR(entry.st_mode), "unsafe actual private directory")
        allowed = set(controls) | {"read-gap-before-evidence", "read-gap-after-evidence"}
        with _Directory(actual / "owned") as directory:
            actual_names = set(directory.names(32))
            if actual_names != allowed:
                missing("actual owned membership incomplete or unknown")
        for name in sorted(actual_names & allowed):
            with _Directory(actual / "owned" / name) as directory:
                if name in controls:
                    names = set(directory.names(32))
                    output = marker if name == "withhold-name" else "stdout"
                    required = {"control.sh", "pid", "stderr", output}
                    traces = {item for item in names if re.fullmatch(r"trace\.[1-9][0-9]{0,9}", item)}
                    _require(names <= required | traces and len(traces) <= 16, "unknown control member or trace cap")
                    if not required <= names or not traces:
                        missing("control membership incomplete: " + name)
                    caps = {"control.sh": 4096, "pid": 64, "stderr": _MIB, output: _MIB}
                    for item in sorted(names):
                        copy(directory, item, "actual/owned/" + name + "/" + item, caps.get(item, 2 * _MIB))
                else:
                    names = set(directory.names(5))
                    caps = {"commands.jsonl": 2 * _MIB, "raw-output.bin": 2 * _MIB,
                            "manifest.json": 524288, "environments.json": 65536}
                    _require(names <= set(caps), "unknown clock evidence member")
                    if names != set(caps):
                        missing("clock evidence incomplete: " + name)
                    combined = 0
                    for item in sorted(names):
                        destination = "actual/owned/" + name + "/" + item
                        if item in ("commands.jsonl", "raw-output.bin"):
                            cap = min(caps[item], 2 * _MIB - combined)
                            try:
                                raw = directory.read(item, cap)
                                combined += len(raw)
                                export.put(destination, raw, cap)
                                collected[destination] = raw
                            except (OSError, ValueError) as error:
                                missing(destination + ": " + str(error))
                        else:
                            copy(directory, item, destination, caps[item])
        _require(stdout is not None and stderr == b"", "actual control output incomplete or stderr nonempty")
        value = json.loads(stdout)
        _require(value.get("state") == "CAPTURED" and value.get("platform") == "linux" and
                 value.get("shared_packet_identity") is True, "actual control packet incomplete")
        clocks = value["qualification"]["clock_cases"]
        _require(len(clocks) == 2 and {item["name"] for item in clocks} ==
                 {"read-gap-before", "read-gap-after"}, "real clock pair missing")
        for clock in clocks:
            _require(all(type(clock[key]) in (int, float) and math.isfinite(clock[key]) for key in
                         ("gap_start", "gap_end", "owner_end_before", "owner_end_after")) and
                     clock["gap_end"] - clock["gap_start"] >= 61 and
                     clock["owner_end_before"] == clock["owner_end_after"], "clock gap or owner renewal")
            manifest = clock["original_manifest"]
            _require(manifest["restored"] is True and manifest["cleanup"]["deleted"] is True and
                     manifest["cleanup"]["shutil_restored"] is True and
                     manifest["evidence_complete"] is (clock["name"] == "read-gap-before") and
                     bool(manifest["source_counts"]) and manifest["source_counts"] == manifest["source_blob_counts"],
                     "clock cleanup or complete read unproved")
            start = clock["collection_started_before_gap"]
            _require(start is None if clock["name"] == "read-gap-before" else
                     type(start) in (int, float) and math.isfinite(start) and start <= clock["gap_start"],
                     "clock collection origin changed")
            retained = json.loads(collected["actual/owned/" + clock["name"] + "-evidence/manifest.json"])
            _require(retained == manifest, "clock manifest differs from packet")
    except (OSError, ValueError, KeyError, TypeError, StopIteration) as error:
        missing("actual evidence: " + str(error))
    return ({"test_ids": ids, "actual_attempts": 1,
             "clock_cases": ["read-gap-before", "read-gap-after"]} if complete else
            {"test_ids": ids, "evidence_complete": False}), complete


def _suite_ok(result, ids):
    if result["problem"] is not None or result["exit"] != 0:
        return False
    text = result["stderr"].decode("utf-8", "strict")
    observed = re.findall(r"^test_[^\n ]+ \(([^()\n]+)\) \.\.\. ok$", text, re.MULTILINE)
    return (sorted(observed) == ids and len(observed) == len(set(observed)) == 49 and
            len(re.findall(r"^Ran 49 tests in [0-9.]+s$", text, re.MULTILINE)) == 1 and
            re.search(r"\nOK\n\Z", text) is not None and
            not re.search(r"(?:skipped|FAILED|ERROR|FAIL:|ERROR:)", text))


def main():
    result = {"state": "REFUSED", "reasons": [], "export": None}
    export = None
    launched = False
    try:
        _require(len(sys.argv) == 1, "this operator accepts no arguments")
        started = time.monotonic()
        environment, context = _context()
        root = Path(environment["GITHUB_WORKSPACE"])
        inputs, source_before, contract = _source(root)
        checkout_before = _checkout(root, context["sha"], inputs, started + 30)
        tools_before, tool_paths_before = _tools()
        owner = Path(environment["RUNNER_TEMP"]) / ("dev786-linux-qualification-" + context["run_id"] + "-1")
        owner.mkdir(mode=0o700)
        for name in ("home", "tmp", "work"):
            (owner / name).mkdir(mode=0o700)
        child_environment = {**_CLEAN, "HOME": str(owner / "home"), "TMPDIR": str(owner / "tmp"),
                             "DEV786_PREFLIGHT_INPUTS": str(root / _SOURCE)}
        probes = _probes(owner / "work", {**_CLEAN, "HOME": str(owner / "home"), "TMPDIR": str(owner / "tmp")},
                         min(started + 30, time.monotonic() + 30))
        checkout = {**checkout_before, "tool_paths_before": tool_paths_before, "probes": probes,
                    "host": {"kernel": list(os.uname()), "architecture": platform.machine(),
                             "image_os": context["image_os"], "image_version": context["image_version"]}}
        _require(len(_json(checkout)) <= 65536, "probe and checkout metadata cap")
        launched = True
        suite = _command(["/usr/bin/python3", "-I", "-S", "-B", "-m", "unittest", "discover",
                          "-s", str(root / _SOURCE), "-p", "test_*.py", "-v"], owner / "work",
                         child_environment, 600, _MIB, started + 840 - 90 - 15)
        result["state"] = "QUALIFIED_PENDING_REVIEW" if _suite_ok(suite, contract[0]) else "FAILED"
        if result["state"] == "FAILED":
            result["reasons"].append("suite did not produce every reviewed test ID with zero failures, errors and skips")
        if suite["problem"] is not None:
            result["state"] = "INCOMPLETE"
            result["reasons"].append(suite["problem"])
        if not suite["cleanup"]["reaped"]:
            result["state"] = "INCOMPLETE"
            result["reasons"].append("suite ownership or reaping unproved")
        export = _Export(owner / "export", min(time.monotonic() + 90, started + 840))
        result["export"] = str(export.path)
        export.put("suite/stdout", suite["stdout"], _MIB)
        export.put("suite/stderr", suite["stderr"], _MIB)
        selection, complete = _evidence(export, owner / "tmp", contract, result["reasons"])
        if not complete:
            result["state"] = "INCOMPLETE"
        snapshots = {"source-before": source_before, "tools-before": tools_before}
        try:
            unused, source_after, unused_contract = _source(root)
            tools_after, tool_paths_after = _tools()
            checkout_after = _checkout(root, context["sha"], inputs, export.deadline)
            checkout["tool_paths_after"] = tool_paths_after
            checkout["post_checkout"] = _identity(_json(checkout_after))
            snapshots.update({"source-after": source_after, "tools-after": tools_after})
            _require(source_after == source_before and tools_after == tools_before and
                     tool_paths_after == tool_paths_before and checkout_after == checkout_before, "source, tools or checkout drift")
        except (OSError, ValueError) as error:
            result["state"] = "INCOMPLETE"
            result["reasons"].append(str(error))
        cleanup = {"suite": suite["cleanup"], "nested_sessions": "diagnostic-owned" if
                   complete and suite["problem"] is None else "unproved"}
        for name, value in {**snapshots, "checkout": checkout, "context": context,
                            "selection": selection, "cleanup": cleanup}.items():
            export.put("meta/" + name + ".json", _json(value))
    except BaseException as error:
        result["state"] = "INCOMPLETE" if launched else "REFUSED"
        result["reasons"].append(type(error).__name__ + ": " + str(error))
    if export is not None:
        try:
            export.put("meta/result.json", _json(result))
            export.put("meta/files.json", _json(export.files), 131072)
        except BaseException as error:
            result = {"state": "INCOMPLETE", "reasons": result["reasons"] +
                      ["export finalization: " + type(error).__name__ + ": " + str(error)], "export": None}
    print(_json(result).decode(), end="")
    return 0 if result["state"] == "QUALIFIED_PENDING_REVIEW" else 1


if __name__ == "__main__":
    raise SystemExit(main())
