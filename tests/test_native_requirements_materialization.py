from __future__ import annotations

import hashlib
import io
import json
import os
import re
import subprocess
import tarfile
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from test_native_tool_release import (
    DIRECTORY, INDEX_GET, INDEX_PATH,
    file_response, load, release as release, tool_endpoint,
)


C = "9b5ad1e78430cc0b061cb16de42f73de96f4f312"
CT = "24112d8c9983333f9059283965230348f718b74c"
M = "69f075819be5e1ceca1446b026b0417f19e584ca"
MT = "5d0b8e66c6cd467e6b1ad9d582e24c66b907e205"


def tar_bytes(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, data, kind in entries:
            member = tarfile.TarInfo(name)
            member.mode = 0o755 if name.endswith(("/uv", "/gh", "/python3.12")) else 0o644
            if kind in {"file", "setuid", "setgid"}:
                if kind == "setuid":
                    member.mode |= 0o4000
                elif kind == "setgid":
                    member.mode |= 0o2000
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            else:
                member.type = {"symlink": tarfile.SYMTYPE, "hardlink": tarfile.LNKTYPE, "fifo": tarfile.FIFOTYPE}[kind]
                member.linkname = data.decode()
                archive.addfile(member)
    return stream.getvalue()


def pin_descriptor(fixture):
    raw = json.dumps(fixture.descriptor).encode()
    fixture.release.raw["runtime.json"] = raw
    fixture.release.routes[tool_endpoint("runtime.json")] = file_response(DIRECTORY + "/runtime.json", raw)
    digest = hashlib.sha256(raw).hexdigest()
    fixture.release.selection = replace(fixture.release.selection, runtime_descriptor_sha256=digest)
    fixture.release.index["runtime_descriptor_sha256"] = digest
    fixture.release.routes[INDEX_GET] = file_response(INDEX_PATH, json.dumps(fixture.release.index).encode())


def replace_archive(fixture, role, entries=None, raw=None):
    if raw is None:
        raw = tar_bytes(entries)
    asset = fixture.descriptor["assets"][role]
    asset["size"] = len(raw)
    asset["sha256"] = hashlib.sha256(raw).hexdigest()
    fixture.release.routes[f"/repos/{asset['repository']}/releases/assets/{asset['asset_id']}"] = raw
    pin_descriptor(fixture)


def expected_inventory(raw):
    pins = {}
    for content in (raw["locked.txt"], raw["build-locked.txt"]):
        for name, version in re.findall(rb"(?m)^([A-Za-z0-9_.-]+)==([^\s;\\]+)", content):
            pins[name.decode().lower().replace("_", "-")] = version.decode()
    return tuple(sorted(pins.items()))


def synthetic_install_report(raw):
    allowed = {}
    for content in (raw["locked.txt"], raw["build-locked.txt"]):
        for block in re.split(rb"(?m)(?=^[A-Za-z0-9_.-]+==)", content):
            pin = re.match(rb"([A-Za-z0-9_.-]+)==([^\s;\\]+)", block)
            if pin:
                name = re.sub(r"[-_.]+", "-", pin[1].decode()).lower()
                key = (name, pin[2].decode())
                hashes = re.findall(rb"--hash=sha256:([a-f0-9]{64})", block)
                allowed.setdefault(key, []).extend(value.decode() for value in hashes)
    alternate = next(key for key in sorted(allowed) if len(set(allowed[key])) > 1
                     and key[0] not in {"commentjson", "lark-parser"})
    records = []
    for (name, version), hashes in sorted(allowed.items()):
        digest = hashes[1] if (name, version) == alternate else hashes[0]
        stem = name.replace("-", "_") + "-" + version
        filename = stem + (".tar.gz" if name in {"commentjson", "lark-parser"} else "-py3-none-any.whl")
        records.append({
            "download_info": {"url": "https://files.pythonhosted.org/packages/aa/bb/" + filename,
                              "archive_info": {"hashes": {"sha256": digest}}},
            "is_direct": False, "is_yanked": False, "requested": True,
            "metadata": {"metadata_version": "2.4", "name": name, "version": version,
                         "summary": "Synthetic external-process contract data"},
        })
    assert len(records) == 57
    return {"version": "1", "pip_version": "26.2.1", "install": records,
            "environment": {"implementation_name": "cpython", "implementation_version": "3.12.15",
                            "os_name": "posix", "platform_machine": "x86_64",
                            "platform_release": "6.8.0-synthetic", "platform_system": "Linux",
                            "platform_version": "Synthetic contract fixture",
                            "python_full_version": "3.12.15", "python_version": "3.12",
                            "platform_python_implementation": "CPython", "sys_platform": "linux"}}, alternate, allowed[alternate][0]


@pytest.fixture
def native(release, monkeypatch, tmp_path):
    materialization = load("native_requirements_materialization", monkeypatch)
    descriptor = json.loads(release.raw["runtime.json"])
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o700)
    fixture = SimpleNamespace(release=release, module=materialization, descriptor=descriptor,
                              workspace=workspace, calls=[], failure=None, inventory=expected_inventory(release.raw))
    assert len(fixture.inventory) == 57
    for role in ("uv", "python", "gh"):
        asset = descriptor["assets"][role]
        payload = ("fixture-" + role).encode()
        asset["binary_sha256"] = hashlib.sha256(payload).hexdigest()
        entries = [(asset["binary"], payload, "file")]
        if role == "python":
            entries.append(("python/bin/python3", b"python3.12", "symlink"))
        replace_archive(fixture, role, entries)
    return fixture


def enter(fixture):
    return fixture.module.materialize_native_tool(fixture.release.selection, fixture.workspace)


def assert_clean(fixture):
    assert list(fixture.workspace.iterdir()) == []


@pytest.mark.parametrize("change", ["unknown", "duplicate", "boolean_version", "platform", "repository", "asset_id", "binary_path", "uppercase_hash", "url", "missing", "tag", "asset_name", "binary_identity"])
def test_selected_descriptor_is_closed_and_role_bound_before_execution(native, monkeypatch, change):
    descriptor = native.descriptor
    if change == "unknown":
        descriptor["commands"] = ["arbitrary"]
    elif change == "boolean_version":
        descriptor["schema_version"] = True
    elif change == "platform":
        descriptor["platform"] = "darwin-arm64"
    elif change == "repository":
        descriptor["assets"]["python"]["repository"] = "foreign/python"
    elif change == "asset_id":
        descriptor["assets"]["uv"]["asset_id"] = True
    elif change == "binary_path":
        descriptor["assets"]["gh"]["binary"] = "../../gh"
    elif change == "uppercase_hash":
        descriptor["assets"]["uv"]["sha256"] = "A" * 64
    elif change == "url":
        descriptor["assets"]["python"]["url"] = "https://evil.example/python"
    elif change == "missing":
        del descriptor["assets"]["gh"]
    elif change == "tag":
        descriptor["assets"]["python"]["tag"] = "20261020"
    elif change == "asset_name":
        descriptor["assets"]["gh"]["name"] = "gh_2.101.0_darwin_arm64.tar.gz"
    elif change == "binary_identity":
        descriptor["assets"]["python"]["binary"] = "python/bin/python3.11"
    pin_descriptor(native)
    if change == "duplicate":
        raw = native.release.raw["runtime.json"][:-1] + b',"schema_version":1}'
        native.release.routes[tool_endpoint("runtime.json")] = file_response(DIRECTORY + "/runtime.json", raw)
        digest = hashlib.sha256(raw).hexdigest()
        native.release.selection = replace(native.release.selection, runtime_descriptor_sha256=digest)
        native.release.index["runtime_descriptor_sha256"] = digest
        native.release.routes[INDEX_GET] = file_response(INDEX_PATH, json.dumps(native.release.index).encode())
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(ValueError):
        with enter(native):
            pytest.fail("invalid descriptor yielded a native environment")
    assert not calls
    assert_clean(native)


@pytest.mark.parametrize("change", ["hash", "short", "long", "binary_hash"])
def test_asset_bytes_and_binary_digest_refuse_before_any_execution(native, monkeypatch, change):
    asset = native.descriptor["assets"]["uv"]
    endpoint = f"/repos/{asset['repository']}/releases/assets/{asset['asset_id']}"
    raw = native.release.routes[endpoint]
    if change == "binary_hash":
        asset["binary_sha256"] = "0" * 64
        pin_descriptor(native)
    elif change == "hash":
        native.release.routes[endpoint] = raw[:-1] + bytes([raw[-1] ^ 1])
    elif change == "short":
        native.release.routes[endpoint] = raw[:-1]
    else:
        native.release.routes[endpoint] = raw + b"x"
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(ValueError):
        with enter(native):
            pytest.fail("unchecked asset yielded an executable")
    assert not calls
    assert_clean(native)


@pytest.mark.parametrize("entries", [
    [("../escape", b"x", "file")], [("/absolute", b"x", "file")],
    [("same", b"a", "file"), ("same", b"b", "file")],
    [("fifo", b"", "fifo")], [("link", b"target", "hardlink")],
    [("privileged", b"x", "setuid")], [("privileged", b"x", "setgid")],
    [("link", b"../../outside", "symlink")], [("link", b"missing", "symlink")],
    [("a", b"b", "symlink"), ("b", b"a", "symlink")],
    [("parent", b"real", "symlink"), ("real/member", b"x", "file"), ("parent/injected", b"x", "file")],
    [("x" * 1025, b"x", "file")],
])
def test_runtime_archive_graph_refuses_unsafe_members_before_execution(native, monkeypatch, entries):
    binary = native.descriptor["assets"]["python"]["binary"]
    replace_archive(native, "python", [(binary, b"fixture-python", "file")] + entries)
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(ValueError):
        with enter(native):
            pytest.fail("unsafe archive yielded a native environment")
    assert not calls
    assert_clean(native)


@pytest.mark.parametrize("raw", [b"not an archive", b"\x1f\x8btruncated"])
def test_malformed_but_selected_archive_refuses_without_execution(native, monkeypatch, raw):
    replace_archive(native, "python", raw=raw)
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(ValueError):
        with enter(native):
            pytest.fail("malformed archive yielded")
    assert not calls
    assert_clean(native)


@pytest.mark.parametrize("kind", ["member", "total", "count"])
def test_runtime_expansion_caps_refuse_before_execution(native, monkeypatch, kind):
    binary = native.descriptor["assets"]["python"]["binary"]
    entries = [(binary, b"fixture-python", "file")]
    if kind == "member":
        entries.append(("large", b"x" * (64 * 1024 * 1024 + 1), "file"))
    elif kind == "total":
        entries.extend((f"large-{i}", b"x" * (44 * 1024 * 1024), "file") for i in range(3))
    else:
        entries.extend((f"file-{i}", b"", "file") for i in range(10000))
    replace_archive(native, "python", entries)
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(ValueError):
        with enter(native):
            pytest.fail("over-limit archive yielded")
    assert not calls
    assert_clean(native)


@pytest.mark.parametrize("kind", ["symlink", "file", "missing"])
def test_workspace_parent_is_checked_without_touching_foreign_paths(native, tmp_path, kind):
    sentinel = tmp_path / "sentinel"
    sentinel.mkdir()
    (sentinel / "keep").write_bytes(b"foreign")
    if kind == "symlink":
        native.workspace.rmdir()
        native.workspace.symlink_to(sentinel, target_is_directory=True)
    elif kind == "file":
        native.workspace.rmdir()
        native.workspace.write_bytes(b"foreign")
    else:
        native.workspace.rmdir()
    with pytest.raises(ValueError):
        with enter(native):
            pytest.fail("unsafe workspace parent accepted")
    assert (sentinel / "keep").read_bytes() == b"foreign"


@pytest.mark.parametrize("field", ["runtime.json", "locked.txt"])
def test_release_substitution_cannot_reach_installer(native, monkeypatch, field):
    native.release.routes[tool_endpoint(field)] = file_response(DIRECTORY + "/" + field, b"substituted")
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(ValueError):
        with enter(native):
            pytest.fail("substitution accepted")
    assert not calls
    assert_clean(native)


@pytest.fixture(autouse=True)
def no_unmocked_processes(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("unmocked process creation is forbidden in contract tests")

    monkeypatch.setattr(subprocess, "Popen", forbidden)


def git_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


@pytest.fixture
def process_native(native, monkeypatch):
    fixture_lock = json.dumps({"repository": "nold-ai/specfact-cli-modules", "commit": M, "tree": MT}).encode()
    native.sources = {
        "core": {"ci/module-fixture.lock.json": fixture_lock, "src/specfact_cli/__init__.py": b"fixture-core\n"},
        "modules": {"packages/specfact-requirements/src/specfact_requirements/__init__.py": b"fixture-modules\n"},
    }
    native.source_fault = None
    native.source_links = {"core": set(), "modules": set()}
    native.source_executables = {"core": set(), "modules": set()}
    native.git_archive_snapshots = []
    native.probe_fault = None
    native.install_fault = None
    native.report_fault = None
    native.report, native.alternate_artifact, native.first_artifact_hash = synthetic_install_report(native.release.raw)
    native.report_paths = []
    native.installed_python = None
    native.venv_python = None
    native.private_roots = set()
    native.fetches = []
    native.probes = []
    native.installs = []
    native.mirror_files = []
    native.uv_policy_snapshots = []
    native.repositories = {}
    native.source_archives = {}
    for repository, identity, commit, tree in (
        ("nold-ai/specfact-cli", 1085706003, C, CT),
        ("nold-ai/specfact-cli-modules", 1162937710, M, MT),
    ):
        native.release.routes[f"/repos/{repository}"] = {
            "id": identity, "full_name": repository, "name": repository.split("/")[1],
            "owner": {"login": "nold-ai", "id": 225190663, "type": "Organization"},
            "default_branch": "main",
        }
        native.release.routes[f"/repos/{repository}/git/commits/{commit}"] = {
            "sha": commit, "tree": {"sha": tree}, "parents": [],
        }

    def output(args, raw, kwargs, stderr=b""):
        text = kwargs.get("text") or kwargs.get("universal_newlines") or kwargs.get("encoding") or kwargs.get("errors")
        encoding = kwargs.get("encoding") or "utf-8"
        errors = kwargs.get("errors") or "strict"

        def stream_result(stream, data):
            sink = kwargs.get(stream)
            if kwargs.get("capture_output") or sink == subprocess.PIPE:
                return data.decode(encoding, errors) if text else data
            if sink is not None and sink != subprocess.DEVNULL:
                if isinstance(sink, int):
                    os.write(sink, data)
                else:
                    sink.write(data.decode(encoding, errors) if isinstance(sink, io.TextIOBase) else data)
                    sink.flush()
            return None

        stdout = stream_result("stdout", raw + stderr if kwargs.get("stderr") == subprocess.STDOUT else raw)
        error = None if kwargs.get("stderr") == subprocess.STDOUT else stream_result("stderr", stderr)
        return subprocess.CompletedProcess(args, 0, stdout, error)

    def execute(args, **kwargs):
        assert isinstance(args, (list, tuple)) and all(isinstance(arg, (str, os.PathLike)) for arg in args)
        args = [str(arg) for arg in args]
        assert not kwargs.get("shell", False)
        assert 0 < kwargs.get("timeout", 0) <= 300
        env = kwargs.get("env")
        assert isinstance(env, dict), "every child requires an explicit isolated environment"
        assert not any(key in env for key in ("GH_TOKEN", "GITHUB_TOKEN", "PYTHONPATH", "PYTHONHOME", "PIP_CONFIG_FILE", "UV_PYTHON_CACHE_DIR", "HTTP_PROXY", "HTTPS_PROXY", "LD_LIBRARY_PATH"))
        assert all("poison" not in value for value in env.values())
        native.calls.append((args, dict(kwargs)))
        if Path(args[0]).name == "uname":
            return output(args, b"Linux x86_64\n", kwargs)
        if Path(args[0]).name == "git":
            if "--version" in args:
                return output(args, b"git version 2.50.1\n", kwargs)
            assert env.get("GIT_CONFIG_NOSYSTEM") == "1"
            assert env.get("GIT_CONFIG_GLOBAL") == os.devnull
            assert env.get("GIT_NO_REPLACE_OBJECTS") == "1"
            assert env.get("GIT_TERMINAL_PROMPT") == "0"
            assert "GIT_CONFIG_COUNT" not in env and "GIT_ALTERNATE_OBJECT_DIRECTORIES" not in env
            if "init" in args:
                assert "--bare" in args
                directory = Path(args[-1])
                directory.mkdir(parents=True, exist_ok=True)
                native.repositories[str(directory)] = None
                return output(args, b"", kwargs)
            cwd = str(Path(args[args.index("-C") + 1])) if "-C" in args else str(kwargs.get("cwd", ""))
            if "fetch" in args:
                assert "--no-tags" in args and any(arg in {"--depth=1", "--depth"} for arg in args)
                assert not any(arg in {"main", "dev", "--recurse-submodules"} for arg in args)
                remote = next(arg for arg in args if arg.startswith("https://github.com/"))
                role = "modules" if "specfact-cli-modules" in remote else "core"
                assert remote in {"https://github.com/nold-ai/specfact-cli.git", "https://github.com/nold-ai/specfact-cli-modules.git"}
                commit = M if role == "modules" else C
                assert commit in args
                native.repositories[cwd] = role
                native.fetches.append((remote, commit))
                if native.source_fault == "fetch_timeout":
                    raise subprocess.TimeoutExpired(args, kwargs["timeout"])
                return output(args, b"", kwargs)
            role = native.repositories.get(cwd)
            assert role in native.sources, f"unknown private source repository {cwd}"
            commit, tree = (C, CT) if role == "core" else (M, MT)
            sources = native.sources[role]
            if "fsck" in args:
                assert "--strict" in args
                if native.source_fault == "fsck":
                    raise subprocess.CalledProcessError(1, args, stderr=b"corrupt object")
                return output(args, b"", kwargs)
            if "rev-parse" in args:
                value = tree if any("tree" in arg for arg in args) else commit
                if native.source_fault == "tree" and value == tree:
                    value = "0" * 40
                return output(args, (value + "\n").encode(), kwargs)
            if "ls-tree" in args:
                records = []
                for name, raw in sorted(sources.items()):
                    mode = ("120000" if name in native.source_links[role] else
                            "100755" if name in native.source_executables[role] else "100644")
                    if native.source_fault == "mode":
                        mode = "100755"
                    records.append(f"{mode} blob {git_blob(raw)}\t{name}\0".encode())
                return output(args, b"".join(records), kwargs)
            if "cat-file" in args or "show" in args:
                needle = args[-1]
                for name, raw in sources.items():
                    if needle in {git_blob(raw), commit + ":" + name}:
                        return output(args, raw, kwargs)
                pytest.fail(f"unexpected blob read {args}")
            if "archive" in args:
                entries = [(name, raw, "symlink" if name in native.source_links[role] else "file")
                           for name, raw in sources.items()]
                if native.source_fault == "member":
                    entries.pop()
                if native.source_fault == "bytes":
                    name, raw, kind = entries[-1]
                    entries[-1] = (name, raw + b"changed", kind)
                mask = 0o0002
                for index, arg in enumerate(args[:args.index("archive")]):
                    if arg == "-c" and args[index + 1].startswith("tar.umask="):
                        mask = int(args[index + 1].split("=", 1)[1], 8)
                stream = io.BytesIO()
                modes = []
                with tarfile.open(fileobj=stream, mode="w") as archive:
                    for name, data, kind in entries:
                        member = tarfile.TarInfo(name)
                        member.mode = (0o777 if name in native.source_executables[role] else 0o666) & ~mask
                        if kind == "symlink":
                            member.type = tarfile.SYMTYPE
                            member.linkname = data.decode()
                            member.mode = 0o777
                            archive.addfile(member)
                        else:
                            member.size = len(data)
                            archive.addfile(member, io.BytesIO(data))
                        modes.append((name, member.mode))
                native.git_archive_snapshots.append((tuple(args), role, mask, tuple(modes)))
                raw = stream.getvalue()
                if "--output" in args:
                    Path(args[args.index("--output") + 1]).write_bytes(raw)
                    raw = b""
                elif any(arg.startswith("--output=") for arg in args):
                    Path(next(arg.split("=", 1)[1] for arg in args if arg.startswith("--output="))).write_bytes(raw)
                    raw = b""
                return output(args, raw, kwargs)
            pytest.fail(f"unexpected Git operation {args}")
        cwd = Path(kwargs.get("cwd", native.workspace))
        assert cwd.is_relative_to(native.workspace)
        if Path(args[0]).name == "uv":
            native.uv_policy_snapshots.append((tuple(args), env.get("UV_PYTHON_DOWNLOADS")))
            assert "--no-config" in args
            if "python" in args and "install" in args:
                if env.get("UV_PYTHON_DOWNLOADS") == "never" and native.installed_python is None:
                    message = b'Python downloads are not allowed (`python-downloads = "never"`). Change to `python-downloads = "manual"` to allow explicit installs.\n'
                    result = output(args, b"", kwargs, message)
                    result.returncode = 1
                    if kwargs.get("check"):
                        raise subprocess.CalledProcessError(1, args, output=result.stdout, stderr=result.stderr)
                    return result
                assert env.get("UV_PYTHON_DOWNLOADS") == "manual"
                assert "--no-python-downloads" not in args
                assert "--offline" in args and "--no-bin" in args and "--no-compile-bytecode" in args
                assert "cpython-3.12.15-linux-x86_64-gnu" in args
                install = Path(args[args.index("--install-dir") + 1])
                mirror = args[args.index("--mirror") + 1]
                assert mirror.startswith("file://")
                from urllib.parse import unquote, urlsplit
                mirror_root = Path(unquote(urlsplit(mirror).path))
                files = list(mirror_root.rglob("*.tar.gz"))
                assert len(files) == 1
                assert files[0].name == native.descriptor["assets"]["python"]["name"]
                assert files[0].parent.name == "20261021"
                assert hashlib.sha256(files[0].read_bytes()).hexdigest() == native.descriptor["assets"]["python"]["sha256"]
                native.mirror_files.append(files[0])
                if native.install_fault == "mirror":
                    files[0].unlink()
                    raise subprocess.CalledProcessError(1, args, stderr=b"offline mirror unavailable")
                if native.install_fault == "timeout":
                    raise subprocess.TimeoutExpired(args, kwargs["timeout"])
                binary = install / "cpython-3.12.15-linux-x86_64-gnu/bin/python3.12"
                binary.parent.mkdir(parents=True)
                binary.write_bytes(b"fixture-python")
                binary.chmod(0o755)
                native.installed_python = binary
                return output(args, b"", kwargs)
            if "venv" in args:
                assert "--seed" not in args and "--python" in args
                assert args[args.index("--python") + 1] == str(native.installed_python)
                assert "--no-python-downloads" in args or env.get("UV_PYTHON_DOWNLOADS") == "never"
                directory = Path(args[-1])
                binary = directory / "bin/python"
                binary.parent.mkdir(parents=True)
                binary.symlink_to(native.installed_python)
                (directory / "lib/python3.12/site-packages").mkdir(parents=True)
                native.venv_python = binary
                return output(args, b"", kwargs)
            if "pip" in args and "install" in args:
                assert all(flag in args for flag in ("--require-hashes", "--no-deps", "--python", "-r"))
                assert "--only-binary=:all:" in args or ("--only-binary" in args and ":all:" in args)
                lock = Path(args[args.index("-r") + 1])
                assert lock.is_relative_to(native.workspace)
                assert lock.read_bytes() == native.release.raw["build-locked.txt"]
                native.installs.append(("build", args, lock.read_bytes()))
                return output(args, b"", kwargs)
            if "--version" in args:
                return output(args, b"uv 0.13.5\n", kwargs)
            pytest.fail(f"unexpected uv invocation {args}")
        if Path(args[0]).name == "gh":
            assert "--version" in args
            return output(args, b"gh version 2.101.0\n", kwargs)
        assert Path(args[0]) in {native.installed_python, native.venv_python}
        if "pip" in args and "install" in args:
            assert args[1:4] == ["-I", "-m", "pip"]
            assert all(flag in args for flag in ("--isolated", "--require-hashes", "--no-deps", "--no-build-isolation", "--only-binary=:all:", "--no-binary=commentjson,lark-parser", "--no-cache-dir", "--index-url", "--force-reinstall", "--report", "-r"))
            assert args[args.index("--index-url") + 1] == "https://pypi.org/simple"
            assert "--upgrade" not in args and "--extra-index-url" not in args
            locks = [Path(args[index + 1]) for index, arg in enumerate(args) if arg == "-r"]
            assert len(locks) == 2 and locks[0] != locks[1]
            assert all(lock.is_relative_to(native.workspace) for lock in locks)
            assert [lock.read_bytes() for lock in locks] == [native.release.raw["locked.txt"], native.release.raw["build-locked.txt"]]
            native.installs.append(("runtime", args, locks[0].read_bytes()))
            assert "--dry-run" not in args
            report_path = Path(args[args.index("--report") + 1])
            assert report_path.is_relative_to(native.workspace) and report_path.parent.is_dir()
            assert not report_path.exists(), "report must originate from this mocked final pip invocation"
            native.report_paths.append(report_path)
            if native.install_fault == "sdist":
                raise subprocess.CalledProcessError(1, args, stderr=b"unexpected source distribution")
            if native.install_fault == "install":
                raise subprocess.CalledProcessError(1, args, stderr=b"build failed")
            report = json.loads(json.dumps(native.report))
            record = report["install"][0]
            fault = native.report_fault
            if fault == "wrong_hash":
                record["download_info"]["archive_info"]["hashes"]["sha256"] = "0" * 64
            elif fault == "uppercase_hash":
                record["download_info"]["archive_info"]["hashes"]["sha256"] = record["download_info"]["archive_info"]["hashes"]["sha256"].upper()
            elif fault == "missing_package":
                report["install"].pop()
            elif fault == "extra_package":
                extra = json.loads(json.dumps(record))
                extra["metadata"]["name"] = "unexpected-package"
                extra["download_info"]["url"] = "https://files.pythonhosted.org/packages/unexpected_package-1.0-py3-none-any.whl"
                extra["metadata"]["version"] = "1.0"
                report["install"].append(extra)
            elif fault == "duplicate_package":
                report["install"].append(json.loads(json.dumps(record)))
            elif fault == "wrong_version":
                record["metadata"]["version"] = "999.0"
                record["download_info"]["url"] = "https://files.pythonhosted.org/packages/annotated_doc-999.0-py3-none-any.whl"
            elif fault in {"wrong_host", "credentials", "port", "fragment", "unexpected_sdist"}:
                url = record["download_info"]["url"]
                if fault == "wrong_host":
                    url = url.replace("files.pythonhosted.org", "foreign.example")
                elif fault == "credentials":
                    url = url.replace("https://", "https://user:password@")
                elif fault == "port":
                    url = url.replace("files.pythonhosted.org", "files.pythonhosted.org:443")
                elif fault == "fragment":
                    url += "#artifact"
                else:
                    url = url.removesuffix("-py3-none-any.whl") + ".tar.gz"
                record["download_info"]["url"] = url
            elif fault == "direct":
                record["is_direct"] = True
            elif fault == "directory":
                record["download_info"]["dir_info"] = {"editable": False}
            elif fault == "vcs":
                record["download_info"]["vcs_info"] = {"vcs": "git", "commit_id": C}
            elif fault == "extras":
                record["requested_extras"] = ["unexpected"]
            elif fault == "report_version":
                report["version"] = 1
            elif fault == "pip_version":
                report["pip_version"] = "26.2.0"
            elif fault == "boolean_field":
                record["is_direct"] = 0
            raw = json.dumps(report).encode()
            if fault == "malformed":
                raw = b"{"
            elif fault == "empty":
                raw = b""
            elif fault == "oversize":
                report["environment"]["synthetic_padding"] = "x" * (4 * 1024 * 1024)
                raw = json.dumps(report).encode()
            elif fault == "duplicate_key":
                raw = raw[:-1] + b',"version":"1"}'
            elif fault == "nested_duplicate_key":
                digest = record["download_info"]["archive_info"]["hashes"]["sha256"]
                raw = raw.replace(('"sha256": "' + digest + '"').encode(),
                                  ('"sha256": "' + digest + '", "sha256": "' + digest + '"').encode(), 1)
            if fault == "nonregular":
                report_path.mkdir()
            elif fault == "symlink":
                target = report_path.with_name("external-report.json")
                target.write_bytes(raw)
                report_path.symlink_to(target)
            elif fault != "missing":
                report_path.write_bytes(raw)
            return output(args, b"Successfully installed frozen inputs\n", kwargs, b"Synthetic backend build log\n")
        assert "-I" in args and "-c" in args
        executable = Path(args[0])
        prefix = executable.parent.parent
        site = prefix / "lib/python3.12/site-packages"
        inventory = list(native.inventory)
        if native.probe_fault == "inventory":
            inventory.append(("unexpected-package", "1.0"))
        elif native.probe_fault == "setuptools":
            inventory = [(name, "84.0.0" if name == "setuptools" else version) for name, version in inventory]
        result = {
            "executable": str(executable), "prefix": str(prefix), "version": "3.12.15",
            "site_packages": str(site), "platform": "linux", "machine": "x86_64",
            "case_sensitive": True,
            "inventory": [{"name": name, "version": version} for name, version in inventory],
        }
        if native.probe_fault == "python":
            result["executable"] = "/ambient/python"
        if native.probe_fault == "version":
            result["version"] = "3.12.13"
        if native.probe_fault == "case_sensitive":
            result["case_sensitive"] = False
        native.probes.append(executable)
        return output(args, json.dumps(result).encode(), kwargs)

    monkeypatch.setattr(subprocess, "run", execute)
    for name in ("PYTHONPATH", "PYTHONHOME", "PIP_CONFIG_FILE", "UV_PYTHON_CACHE_DIR", "UV_PYTHON_INSTALL_DIR", "GIT_CONFIG_COUNT", "GIT_DIR", "GIT_WORK_TREE", "HTTPS_PROXY"):
        monkeypatch.setenv(name, "/poison/ambient")
    return native


def test_owned_native_paths_inventory_and_lifetime(process_native):
    fixture = process_native
    with enter(fixture) as tool:
        assert type(tool) is fixture.module.NativeTool
        assert tool.selection == fixture.release.selection
        assert tool.manifest_sha256 == fixture.release.selection.manifest_sha256
        assert tool.runtime_descriptor_sha256 == fixture.release.selection.runtime_descriptor_sha256
        assert tool.inventory == fixture.inventory
        paths = (tool.python, tool.site_packages, tool.core_root, tool.modules_root, tool.uv, tool.gh)
        assert all(path.exists() and path.is_relative_to(fixture.workspace) for path in paths)
        assert tool.python == fixture.venv_python
        assert (tool.core_root / "ci/module-fixture.lock.json").read_bytes() == fixture.sources["core"]["ci/module-fixture.lock.json"]
        assert (tool.modules_root / "packages/specfact-requirements/src/specfact_requirements/__init__.py").read_bytes() == fixture.sources["modules"]["packages/specfact-requirements/src/specfact_requirements/__init__.py"]
        owned = next(iter(fixture.workspace.iterdir()))
        assert owned.stat().st_mode & 0o777 == 0o700
        with pytest.raises(FrozenInstanceError):
            tool.python = Path("/ambient/python")
        assert isinstance(tool.diagnostic_identity, tuple) and tool.diagnostic_identity
        assert all(isinstance(record, tuple) and len(record) == 2 for record in tool.diagnostic_identity)
        assert len(fixture.fetches) == 2 and len(fixture.installs) == 2
        assert fixture.probes and fixture.mirror_files
    assert all(not path.exists() for path in paths)
    assert_clean(fixture)


def test_caller_exception_cleans_all_sources_and_installs(process_native):
    class CallerFailure(Exception):
        pass

    with pytest.raises(CallerFailure, match="caller failed"):
        with enter(process_native) as tool:
            assert tool.python.exists() and tool.core_root.exists()
            raise CallerFailure("caller failed")
    assert_clean(process_native)


@pytest.mark.parametrize("fault", ["fsck", "tree", "member", "mode", "bytes", "symlink", "casefold", "oversize", "fetch_timeout"])
def test_exact_git_source_failures_refuse_and_cleanup(process_native, fault):
    process_native.source_fault = fault
    sources = process_native.sources["core"]
    if fault == "casefold":
        sources.update({"Case": b"a", "case": b"b"})
    elif fault == "symlink":
        sources.update({"source-link": b"target", "target": b"ordinary target\n"})
        process_native.source_links["core"].add("source-link")
    elif fault == "oversize":
        sources["oversize"] = b"x" * (16 * 1024 * 1024 + 1)
    with pytest.raises(ValueError):
        with enter(process_native):
            pytest.fail("unbound Git source yielded")
    assert_clean(process_native)


@pytest.mark.parametrize("fault", ["python", "version", "inventory", "setuptools", "case_sensitive"])
def test_installed_interpreter_and_exact_57_distribution_inventory_are_verified(process_native, fault):
    process_native.probe_fault = fault
    with pytest.raises(ValueError):
        with enter(process_native):
            pytest.fail("unverified interpreter or package graph yielded")
    assert_clean(process_native)


@pytest.mark.parametrize("fault", ["mirror", "timeout", "sdist", "install"])
def test_installer_failure_has_no_fallback_and_cleans_owned_root(process_native, fault):
    process_native.install_fault = fault
    with pytest.raises(ValueError):
        with enter(process_native):
            pytest.fail("failed installer yielded")
    assert_clean(process_native)
    assert sum("python" in args and "install" in args for args, _ in process_native.calls) <= 1


def test_retry_and_nested_callers_have_disjoint_private_roots(process_native):
    fixture = process_native
    fixture.install_fault = "timeout"
    with pytest.raises(ValueError):
        with enter(fixture):
            pytest.fail("timeout yielded")
    assert_clean(fixture)
    fixture.install_fault = None
    with enter(fixture) as first:
        first_root = next(iter(fixture.workspace.iterdir()))
        with enter(fixture) as second:
            roots = list(fixture.workspace.iterdir())
            assert len(roots) == 2 and first.python != second.python
            assert first.python.exists() and second.python.exists()
        assert first_root.exists() and first.python.exists()
    assert_clean(fixture)


def test_runtime_member_larger_than_old_16mib_bound_is_accepted(process_native):
    fixture = process_native
    asset = fixture.descriptor["assets"]["uv"]
    payload = b"u" * (16 * 1024 * 1024 + 1)
    asset["binary_sha256"] = hashlib.sha256(payload).hexdigest()
    replace_archive(fixture, "uv", [(asset["binary"], payload, "file")])
    with enter(fixture) as tool:
        assert hashlib.sha256(tool.uv.read_bytes()).hexdigest() == asset["binary_sha256"]
    assert_clean(fixture)


def test_linux_runtime_exact_case_names_and_contained_relative_links_accept(process_native):
    fixture = process_native
    binary = fixture.descriptor["assets"]["python"]["binary"]
    replace_archive(fixture, "python", [
        (binary, b"fixture-python", "file"),
        ("python/bin/python3", b"python3.12", "symlink"),
        ("python/share/terminfo/2/2621A", b"upper", "file"),
        ("python/share/terminfo/2/2621a", b"lower", "file"),
    ])
    with enter(fixture) as tool:
        assert tool.python.exists()
    assert_clean(fixture)


@pytest.mark.parametrize("role", ["core", "modules"])
@pytest.mark.parametrize("fault", ["repository_id", "boolean_id", "commit_sha", "tree_sha"])
def test_source_api_identity_is_independent_of_correct_git_objects(process_native, role, fault):
    repository, commit = ("nold-ai/specfact-cli", C) if role == "core" else ("nold-ai/specfact-cli-modules", M)
    repository_record = process_native.release.routes[f"/repos/{repository}"]
    commit_record = process_native.release.routes[f"/repos/{repository}/git/commits/{commit}"]
    if fault == "repository_id":
        repository_record["id"] += 1
    elif fault == "boolean_id":
        repository_record["id"] = True
    elif fault == "commit_sha":
        commit_record["sha"] = "0" * 40
    else:
        commit_record["tree"]["sha"] = "0" * 40
    with pytest.raises(ValueError):
        with enter(process_native):
            pytest.fail("unauthenticated source identity yielded NativeTool")
    assert_clean(process_native)


@pytest.mark.parametrize("field,value", [
    ("repository", "foreign/specfact-cli-modules"), ("commit", "0" * 40), ("tree", "0" * 40),
])
def test_coherent_core_fixture_lock_must_semantically_bind_modules(process_native, field, value):
    sources = process_native.sources["core"]
    name = "ci/module-fixture.lock.json"
    fixture_lock = json.loads(sources[name])
    fixture_lock[field] = value
    sources[name] = json.dumps(fixture_lock).encode()
    with pytest.raises(ValueError):
        with enter(process_native):
            pytest.fail("unbound fixture-lock yielded NativeTool")
    assert_clean(process_native)


def test_final_install_receipt_preserves_reported_alternate_hash(process_native):
    fixture = process_native
    name, version = fixture.alternate_artifact
    reported = next(record["download_info"]["archive_info"]["hashes"]["sha256"]
                    for record in fixture.report["install"] if record["metadata"]["name"] == name)
    assert reported != fixture.first_artifact_hash
    with enter(fixture) as tool:
        assert len(fixture.report_paths) == 1
        report_path = fixture.report_paths[0]
        raw = report_path.read_bytes()
        diagnostics = dict(tool.diagnostic_identity)
        assert diagnostics["install_report_path"] == str(report_path)
        assert diagnostics["install_report_sha256"] == hashlib.sha256(raw).hexdigest()
        artifacts = {key: value for key, value in diagnostics.items() if key.startswith("artifact.")}
        assert artifacts == {"artifact." + record["metadata"]["name"]:
                             record["metadata"]["version"] + ":" + record["download_info"]["archive_info"]["hashes"]["sha256"]
                             for record in fixture.report["install"]}
        assert artifacts["artifact." + name] == version + ":" + reported
        assert len(fixture.installs) == 2
    assert not report_path.exists()
    assert_clean(fixture)


@pytest.mark.parametrize("fault", [
    "missing", "empty", "malformed", "oversize", "nonregular", "symlink",
    "duplicate_key", "nested_duplicate_key", "wrong_hash", "uppercase_hash",
    "missing_package", "extra_package", "duplicate_package", "wrong_version",
    "wrong_host", "credentials", "port", "fragment", "unexpected_sdist",
    "direct", "directory", "vcs", "extras", "report_version", "pip_version", "boolean_field",
])
def test_final_install_receipt_refuses_incomplete_or_foreign_evidence(process_native, fault):
    process_native.report_fault = fault
    with pytest.raises(ValueError):
        with enter(process_native):
            pytest.fail("invalid final pip artifact receipt yielded NativeTool")
    assert len(process_native.report_paths) == 1
    assert_clean(process_native)


def test_explicit_offline_managed_install_alone_uses_manual_download_policy(process_native):
    fixture = process_native
    with enter(fixture) as tool:
        assert tool.python.exists()
        snapshots = tuple(fixture.uv_policy_snapshots)
        installs = [(args, policy) for args, policy in snapshots if "python" in args and "install" in args]
        assert len(installs) == 1
        args, policy = installs[0]
        assert policy == "manual"
        assert "--offline" in args and "--no-config" in args
        assert args[args.index("--mirror") + 1].startswith("file://")
        assert args[-1] == "cpython-3.12.15-linux-x86_64-gnu"
        assert sum(policy == "manual" for _, policy in snapshots) == 1
        others = [(args, policy) for args, policy in snapshots if not ("python" in args and "install" in args)]
        assert others and all(policy == "never" for _, policy in others)
        assert any("venv" in args for args, _ in others)
        assert any("pip" in args and "install" in args for args, _ in others)
        assert len(fixture.mirror_files) == 1
    assert_clean(fixture)


def test_git_source_archive_pins_mask_and_preserves_exact_regular_modes(process_native):
    fixture = process_native
    executable = "scripts/source-tool"
    for role in ("core", "modules"):
        fixture.sources[role][executable] = b"#!/bin/sh\nexit 0\n"
        fixture.source_executables[role].add(executable)
    with enter(fixture) as tool:
        snapshots = tuple(fixture.git_archive_snapshots)
        assert len(snapshots) == 2
        assert {role for _, role, _, _ in snapshots} == {"core", "modules"}
        for args, role, mask, modes in snapshots:
            assert any(arg == "-c" and args[index + 1] == "tar.umask=0022"
                       for index, arg in enumerate(args[:args.index("archive")]))
            assert mask == 0o0022
            expected = {name: 0o755 if name in fixture.source_executables[role] else 0o644
                        for name in fixture.sources[role]}
            assert dict(modes) == expected
            assert set(expected.values()) == {0o644, 0o755}
            source_root = tool.core_root if role == "core" else tool.modules_root
            for name, data in fixture.sources[role].items():
                path = source_root / name
                assert path.read_bytes() == data
                assert path.stat().st_mode & 0o777 == expected[name]
    assert_clean(fixture)
