from __future__ import annotations

import gzip
import hashlib
import http.client
import io
import json
import os
import posixpath
import re
import resource
import shutil
import signal
import stat
import subprocess
import tarfile
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote, urlsplit

import native_requirements_bootstrap as bootstrap
from late_cycle_admission import GitHub
from native_requirements_acquisition import ProtectedSelection, ToolRelease, acquire_tool_release


_MIB = 1024 * 1024
_ARCHIVE_LIMIT = 64 * _MIB
_EXPANDED_LIMIT = 128 * _MIB
_TAR_LIMIT = 160 * _MIB
_SOURCE_MEMBER_LIMIT = 16 * _MIB
_METADATA_LIMIT = 4 * _MIB
_MEMBER_COUNT = 10000


@dataclass(frozen=True, slots=True)
class NativeTool:
    python: Path
    site_packages: Path
    core_root: Path
    modules_root: Path
    uv: Path
    gh: Path
    selection: ProtectedSelection
    manifest_sha256: str
    runtime_descriptor_sha256: str
    inventory: tuple[tuple[str, str], ...]
    diagnostic_identity: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class _Asset:
    repository: str
    tag: str
    asset_id: int
    name: str
    size: int
    sha256: str
    binary: str
    binary_sha256: str
    version: str


@dataclass(frozen=True, slots=True)
class _Archive:
    data: bytes
    members: dict[str, tarfile.TarInfo]


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(f"native materialization rejected: {reason}")


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _hex(value: object, length: int = 64) -> str:
    _require(type(value) is str and re.fullmatch(r"[0-9a-f]{%d}" % length, value) is not None,
             "invalid digest")
    return value


def _pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        _require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def _object(raw: bytes) -> dict[str, object]:
    _require(0 < len(raw) <= _METADATA_LIMIT, "JSON size")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                       parse_constant=lambda _: _require(False, "nonfinite JSON"))
    _require(type(value) is dict, "JSON object required")
    return value


def _path(value: object) -> str:
    _require(type(value) is str and 0 < len(value.encode("utf-8")) <= 1024,
             "invalid member path")
    _require(not any(c in value for c in "\\\x00\r\n") and not value.startswith("/"),
             "unsafe member path")
    _require(all(part not in {"", ".", ".."} for part in value.split("/")),
             "noncanonical member path")
    return value


def _asset(role: str, value: object) -> _Asset:
    fields = {"repository", "tag", "asset_id", "name", "size", "sha256", "binary", "binary_sha256"}
    _require(type(value) is dict and set(value) == fields, "asset fields")
    repository = {"uv": "astral-sh/uv", "python": "astral-sh/python-build-standalone", "gh": "cli/cli"}[role]
    _require(value["repository"] == repository, "asset repository")
    _require(type(value["asset_id"]) is int and value["asset_id"] > 0, "asset ID")
    _require(type(value["size"]) is int and 0 < value["size"] <= _ARCHIVE_LIMIT, "asset size")
    name, binary, tag = _path(value["name"]), _path(value["binary"]), value["tag"]
    _require("/" not in name and type(tag) is str, "asset name or tag")
    if role == "python":
        match = re.fullmatch(r"cpython-(3\.\d+\.\d+)\+(\d{8})-x86_64-unknown-linux-gnu-install_only_stripped\.tar\.gz", name)
        _require(match is not None and match[2] == tag, "Python release identity")
        version = match[1]
        _require(binary == "python/bin/python" + version.rsplit(".", 1)[0], "Python binary identity")
    elif role == "uv":
        _require(re.fullmatch(r"\d+\.\d+\.\d+", tag) is not None, "UV version")
        version = tag
        _require(name == "uv-x86_64-unknown-linux-gnu.tar.gz"
                 and binary == "uv-x86_64-unknown-linux-gnu/uv", "UV platform identity")
    else:
        _require(re.fullmatch(r"v\d+\.\d+\.\d+", tag) is not None, "GH version")
        version = tag[1:]
        _require(name == f"gh_{version}_linux_amd64.tar.gz"
                 and binary == f"gh_{version}_linux_amd64/bin/gh", "GH platform identity")
    return _Asset(repository, tag, value["asset_id"], name, value["size"],
                  _hex(value["sha256"]), binary, _hex(value["binary_sha256"]), version)


def _descriptor(raw: bytes) -> dict[str, _Asset]:
    value = _object(raw)
    _require(set(value) == {"schema_version", "platform", "assets"}, "descriptor fields")
    _require(type(value["schema_version"]) is int and value["schema_version"] == 1,
             "descriptor version")
    _require(value["platform"] == "linux-x86_64-gnu", "descriptor platform")
    assets = value["assets"]
    _require(type(assets) is dict and set(assets) == {"uv", "python", "gh"}, "descriptor roles")
    return {role: _asset(role, assets[role]) for role in ("uv", "python", "gh")}


def _tar_bytes(raw: bytes) -> bytes:
    if raw.startswith(b"\x1f\x8b"):
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
            data = stream.read(_TAR_LIMIT + 1)
    else:
        data = raw
    _require(len(data) <= _TAR_LIMIT, "expanded tar envelope")
    return data


def _link_graph(members: dict[str, tarfile.TarInfo]) -> None:
    directories = set()
    for name in members:
        parent = posixpath.dirname(name)
        while parent:
            _require(parent not in members or members[parent].isdir(), "non-directory archive parent")
            directories.add(parent)
            parent = posixpath.dirname(parent)
    for name, member in members.items():
        if not member.issym():
            continue
        seen = {name}
        target = name
        while target in members and members[target].issym():
            link = members[target].linkname
            _require(link and not link.startswith("/") and not any(c in link for c in "\\\x00\r\n"),
                     "unsafe symlink")
            target = posixpath.normpath(posixpath.join(posixpath.dirname(target), link))
            _require(target not in {".", ".."} and not target.startswith("../"), "escaping symlink")
            _require(target not in seen, "cyclic symlink")
            seen.add(target)
        _require(target in members or target in directories, "dangling symlink")
        parent = posixpath.dirname(target)
        while parent:
            _require(parent not in members or members[parent].isdir(), "symlink target parent")
            parent = posixpath.dirname(parent)


def _archive(raw: bytes, *, source: bool) -> _Archive:
    data = _tar_bytes(raw)
    members: dict[str, tarfile.TarInfo] = {}
    folded: set[str] = set()
    expanded = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        for member in archive:
            _require(len(members) < _MEMBER_COUNT, "archive member count")
            name = _path(member.name.rstrip("/") if member.isdir() else member.name)
            _require(name not in members, "duplicate archive member")
            if source:
                _require(name.casefold() not in folded, "source case collision")
                folded.add(name.casefold())
            _require(not member.mode & 0o6000 and member.sparse is None
                     and not any(key.startswith("GNU.sparse") for key in member.pax_headers),
                     "privileged or sparse archive member")
            _require(member.isfile() or member.isdir() or (member.issym() and not source),
                     "unsupported archive member")
            if member.isfile():
                limit = _SOURCE_MEMBER_LIMIT if source else _ARCHIVE_LIMIT
                _require(0 <= member.size <= limit, "archive member size")
                expanded += member.size
                _require(expanded <= _EXPANDED_LIMIT, "archive expanded total")
            else:
                _require(member.size == 0, "nonregular member data")
            members[name] = member
    _link_graph(members)
    return _Archive(data, members)


def _member_bytes(archive: _Archive, name: str) -> bytes:
    member = archive.members.get(name)
    _require(member is not None and member.isfile(), "missing regular binary or source")
    with tarfile.open(fileobj=io.BytesIO(archive.data), mode="r:") as opened:
        stream = opened.extractfile(member)
        _require(stream is not None, "missing archive data")
        with stream:
            raw = stream.read(member.size + 1)
    _require(len(raw) == member.size, "archive data length")
    return raw


def _runtime_archives(api: GitHub, assets: dict[str, _Asset]) -> tuple[dict[str, bytes], dict[str, bytes]]:
    archives: dict[str, bytes] = {}
    binaries: dict[str, bytes] = {}
    for role, asset in assets.items():
        raw = api.release_asset(asset.repository, asset.asset_id, max_bytes=asset.size)
        _require(len(raw) == asset.size and _digest(raw) == asset.sha256, "asset bytes")
        parsed = _archive(raw, source=False)
        binary = _member_bytes(parsed, asset.binary)
        _require(parsed.members[asset.binary].mode & 0o111 != 0, "binary not executable")
        _require(_digest(binary) == asset.binary_sha256, "binary digest")
        archives[role], binaries[role] = raw, binary
    return archives, binaries


def _write(path: Path, raw: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)


def _read(path: Path, limit: int, *, nonempty: bool = False) -> bytes:
    before = path.lstat()
    _require(stat.S_ISREG(before.st_mode) and int(nonempty) <= before.st_size <= limit,
             "owned file type or size")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        _require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), "owned file replaced")
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    _require(len(raw) <= limit and len(raw) == opened.st_size == after.st_size
             and (opened.st_mtime_ns, opened.st_ctime_ns) == (after.st_mtime_ns, after.st_ctime_ns),
             "owned file changed")
    return raw


@contextmanager
def _private_root(workspace: Path) -> Iterator[Path]:
    descriptor = None
    root = None
    try:
        _require(isinstance(workspace, Path), "workspace path")
        before = workspace.lstat()
        _require(stat.S_ISDIR(before.st_mode), "workspace must be nonsymlink directory")
        descriptor = os.open(workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        opened = os.fstat(descriptor)
        _require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), "workspace replaced")
        parent = workspace.resolve(strict=True)
        root = Path(tempfile.mkdtemp(prefix="native-tool-", dir=parent))
        current = parent.stat()
        _require((current.st_dev, current.st_ino) == (opened.st_dev, opened.st_ino), "workspace moved")
        root.chmod(0o700)
    except (OSError, RuntimeError, ValueError):
        if root is not None:
            shutil.rmtree(root)
        if descriptor is not None:
            os.close(descriptor)
        raise ValueError("native materialization rejected: unsafe workspace") from None
    try:
        yield root
    finally:
        try:
            shutil.rmtree(root)
        finally:
            os.close(descriptor)


def _environment(root: Path) -> dict[str, str]:
    for name in ("home", "tmp", "cache", "config", "bin", "logs", "empty-hooks", "empty-template"):
        (root / name).mkdir(mode=0o700)
    return {
        "PATH": f"{root / 'bin'}:/usr/bin:/bin", "HOME": str(root / "home"),
        "TMPDIR": str(root / "tmp"), "TMP": str(root / "tmp"), "TEMP": str(root / "tmp"),
        "XDG_CACHE_HOME": str(root / "cache"), "XDG_CONFIG_HOME": str(root / "config"),
        "UV_CACHE_DIR": str(root / "cache" / "uv"), "UV_PYTHON_DOWNLOADS": "never",
        "UV_PYTHON_INSTALL_DIR": str(root / "python"), "UV_NO_PROGRESS": "1",
        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1", "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_SYSTEM": os.devnull, "GIT_ATTR_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0",
        "GIT_ALLOW_PROTOCOL": "https", "GIT_PROTOCOL_FROM_USER": "0",
    }


def _resource_limits() -> tuple[tuple[int, int], ...]:
    limits = []
    for key, cap in ((resource.RLIMIT_FSIZE, 256 * _MIB),
                     (resource.RLIMIT_AS, 2 * 1024 * _MIB),
                     (resource.RLIMIT_NPROC, 128), (resource.RLIMIT_CPU, 240),
                     (resource.RLIMIT_CORE, 0)):
        _, hard = resource.getrlimit(key)
        limits.append((key, cap if hard == resource.RLIM_INFINITY else min(cap, hard)))
    return tuple(limits)


def _kill_group(marker: Path) -> None:
    raw = _read(marker, 32)
    if raw:
        _require(re.fullmatch(rb"[1-9][0-9]*", raw) is not None, "invalid child group")
        group = int(raw)
        _require(group != os.getpgrp(), "unsafe child group")
        try:
            os.killpg(group, signal.SIGKILL)
        except ProcessLookupError:
            pass


class _Commands:
    def __init__(self, root: Path, env: dict[str, str]) -> None:
        self.root, self.env = root, env
        self.records: list[tuple[str, str]] = []
        self.sequence = 0

    def run(
        self, args: list[str], *, limit: int = _METADATA_LIMIT, explicit_python_install: bool = False
    ) -> bytes:
        self.sequence += 1
        stem = self.root / "logs" / f"{self.sequence:05d}"
        stdout, stderr = stem.with_suffix(".stdout"), stem.with_suffix(".stderr")
        marker = stem.with_suffix(".pgid")
        limits = _resource_limits()
        env = self.env | {"UV_PYTHON_DOWNLOADS": "manual" if explicit_python_install else "never"}
        record = {"argv": args, "cwd": str(self.root), "env": env,
                  "stdout": str(stdout), "stderr": str(stderr), "timeout_seconds": 300,
                  "resource_limits": dict(limits), "exit_code": None}
        # The child writes its new session ID before exec so timeout cleanup also
        # reaches descendants; subprocess.run itself only waits for the direct child.
        with marker.open("xb") as group_file:
            def setup_child() -> None:
                os.write(group_file.fileno(), str(os.getpid()).encode("ascii"))
                for key, maximum in limits:
                    resource.setrlimit(key, (maximum, maximum))

            try:
                with stdout.open("xb") as output, stderr.open("xb") as errors:
                    result = subprocess.run(args, cwd=self.root, env=env, stdin=subprocess.DEVNULL,
                                            stdout=output, stderr=errors, shell=False, timeout=300,
                                            check=False, preexec_fn=setup_child, start_new_session=True,
                                            pass_fds=(group_file.fileno(),))
                record["exit_code"] = result.returncode
                _require(type(result.returncode) is int and result.returncode == 0, "child exit")
                return _read(stdout, limit)
            except BaseException as error:
                record["failure_type"] = type(error).__name__
                raise
            finally:
                _kill_group(marker)
                _write(stem.with_suffix(".json"), json.dumps(record, sort_keys=True).encode())
                self.records.append((f"process.{self.sequence}", str(stem.with_suffix(".json"))))
                _read(stderr, _METADATA_LIMIT)


def _normalized_name(value: object) -> str:
    _require(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", value) is not None,
             "distribution name")
    return re.sub(r"[-_.]+", "-", value).lower()


def _lock_union(release: ToolRelease) -> dict[str, tuple[str, frozenset[str]]]:
    pins: dict[str, tuple[str, frozenset[str]]] = {}
    for raw in (release.locked, release.build_locked):
        text = raw.decode("utf-8").replace("\\\n", " ")
        for line in text.splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([^\s;]+)\s+((?:--hash=sha256:[a-f0-9]{64}\s*)+)", line)
            _require(match is not None, "unexpected frozen lock syntax")
            name, version = _normalized_name(match[1]), match[2]
            hashes = frozenset(re.findall(r"--hash=sha256:([a-f0-9]{64})", match[3]))
            if name in pins:
                _require(pins[name][0] == version, "conflicting frozen versions")
                hashes = hashes | pins[name][1]
            pins[name] = (version, hashes)
    _require(len(pins) == 57, "frozen inventory size")
    return pins


_PROBE = '''import importlib.metadata, json, os, platform, sys, sysconfig, tempfile
from pathlib import Path
with tempfile.TemporaryDirectory(prefix="case-probe-", dir=os.getcwd()) as directory:
    upper, lower = Path(directory) / "Case", Path(directory) / "case"
    with upper.open("xb") as stream:
        stream.write(b"upper")
    try:
        with lower.open("xb") as stream:
            stream.write(b"lower")
    except FileExistsError:
        sensitive = False
    else:
        sensitive = upper.read_bytes() == b"upper" and lower.read_bytes() == b"lower"
print(json.dumps({"executable": sys.executable, "prefix": sys.prefix,
    "version": platform.python_version(), "site_packages": sysconfig.get_path("purelib"),
    "platform": sys.platform, "machine": platform.machine(), "case_sensitive": sensitive,
    "inventory": [{"name": d.metadata["Name"], "version": d.version}
                  for d in importlib.metadata.distributions()]}))
'''


def _executable(path: Path, root: Path, expected: str) -> None:
    resolved = path.resolve(strict=True)
    _require(resolved.is_relative_to(root) and resolved.stat().st_mode & 0o111 != 0,
             "executable outside owned root or not executable")
    _require(_digest(_read(resolved, _ARCHIVE_LIMIT, nonempty=True)) == expected,
             "installed binary digest")


def _probe(commands: _Commands, python: Path, asset: _Asset, *, final: bool) -> tuple[Path, tuple[tuple[str, str], ...]]:
    _executable(python, commands.root, asset.binary_sha256)
    value = _object(commands.run([str(python), "-I", "-c", _PROBE]))
    prefix = python.parent.parent
    site = prefix / "lib" / ("python" + asset.version.rsplit(".", 1)[0]) / "site-packages"
    expected = {"executable": str(python), "prefix": str(prefix), "version": asset.version,
                "site_packages": str(site), "platform": "linux", "machine": "x86_64",
                "case_sensitive": True}
    _require(set(value) == set(expected) | {"inventory"}, "interpreter diagnostic fields")
    for key, required in expected.items():
        _require(type(value[key]) is type(required) and value[key] == required,
                 "interpreter diagnostic identity")
    _require(prefix.resolve(strict=True).is_relative_to(commands.root), "interpreter prefix")
    if final:
        _require(site.is_dir() and not site.is_symlink()
                 and site.resolve(strict=True).is_relative_to(prefix), "site packages path")
    records = value["inventory"]
    _require(type(records) is list and len(records) <= 200, "interpreter inventory")
    inventory: dict[str, str] = {}
    for record in records:
        _require(type(record) is dict and set(record) == {"name", "version"}, "inventory record")
        name = _normalized_name(record["name"])
        _require(name not in inventory and type(record["version"]) is str, "inventory duplicate or version")
        inventory[name] = record["version"]
    return site, tuple(sorted(inventory.items()))


def _tool_inputs(root: Path, release: ToolRelease) -> Path:
    directory = root / "inputs"
    directory.mkdir(mode=0o700)
    captured = {"tool-files.json": release.manifest, "requirements.in": release.requirements,
                "locked.txt": release.locked, "build-requirements.in": release.build_requirements,
                "build-locked.txt": release.build_locked}
    for name, raw in captured.items():
        _write(directory / name, raw)
    bootstrap.verify_tool_files(directory, release.selection.manifest_sha256)
    _write(root / "runtime.json", release.runtime_descriptor)
    return directory


def _install_python(commands: _Commands, uv: Path, asset: _Asset, archive: bytes) -> Path:
    root = commands.root
    mirror = root / "mirror"
    _write(mirror / asset.tag / asset.name, archive)
    request = f"cpython-{asset.version}-linux-x86_64-gnu"
    commands.run([str(uv), "--no-config", "--offline", "python", "install", "--no-bin",
                  "--no-compile-bytecode", "--install-dir", str(root / "python"),
                  "--mirror", mirror.as_uri(), request], explicit_python_install=True)
    python = root / "python" / request / "bin" / ("python" + asset.version.rsplit(".", 1)[0])
    _require(not python.is_symlink(), "managed interpreter is not regular")
    _probe(commands, python, asset, final=False)
    venv = root / "venv"
    commands.run([str(uv), "--no-config", "--offline", "venv", "--no-python-downloads",
                  "--python", str(python), str(venv)])
    venv_python = venv / "bin" / "python"
    _require(venv_python.resolve(strict=True) == python.resolve(strict=True), "venv interpreter identity")
    return venv_python


def _install_packages(commands: _Commands, uv: Path, python: Path, inputs: Path) -> Path:
    commands.run([str(uv), "--no-config", "pip", "install", "--python", str(python),
                  "--require-hashes", "--no-deps", "--only-binary=:all:",
                  "--index-url", "https://pypi.org/simple", "-r", str(inputs / "build-locked.txt")])
    report = commands.root / "install-report.json"
    commands.run([str(python), "-I", "-m", "pip", "--isolated", "install", "--require-hashes",
                  "--no-deps", "--no-build-isolation", "--only-binary=:all:",
                  "--no-binary=commentjson,lark-parser", "--no-cache-dir", "--disable-pip-version-check",
                  "--index-url", "https://pypi.org/simple", "--force-reinstall", "--report", str(report),
                  "--verbose", "-r", str(inputs / "locked.txt"), "-r", str(inputs / "build-locked.txt")])
    return report


def _artifact_url(value: object, name: str, version: str) -> None:
    _require(type(value) is str and len(value) <= 8192, "artifact URL")
    url = urlsplit(value)
    _require(url.scheme == "https" and url.netloc == "files.pythonhosted.org"
             and not url.fragment and not url.query and url.path.startswith("/packages/"),
             "artifact source")
    filename = unquote(url.path.rsplit("/", 1)[-1])
    _path(filename)
    _require("/" not in filename, "artifact filename")
    if name in {"commentjson", "lark-parser"}:
        _require((name, version) in {("commentjson", "0.9.0"), ("lark-parser", "0.7.8")}
                 and filename.endswith(".tar.gz"), "source artifact allowance")
        stem = filename[:-7]
        artifact_name, separator, artifact_version = stem.rpartition("-")
        _require(bool(separator) and _normalized_name(artifact_name) == name and artifact_version == version,
                 "source artifact identity")
    else:
        _require(filename.endswith(".whl"), "unexpected source artifact")
        parts = filename[:-4].split("-")
        _require(len(parts) in {5, 6} and _normalized_name(parts[0]) == name and parts[1] == version,
                 "wheel artifact identity")


def _report(path: Path, pins: dict[str, tuple[str, frozenset[str]]],
            inventory: tuple[tuple[str, str], ...]) -> list[tuple[str, str]]:
    raw = _read(path, _METADATA_LIMIT, nonempty=True)
    report = _object(raw)
    _require(report.get("version") == "1" and report.get("pip_version") == pins["pip"][0], "pip report version")
    records = report.get("install")
    _require(type(records) is list and len(records) == len(pins), "pip report coverage")
    found: dict[str, str] = {}
    diagnostics = [("install_report_path", str(path)), ("install_report_sha256", _digest(raw))]
    for record in records:
        _require(type(record) is dict, "pip record")
        for field in ("is_direct", "is_yanked", "requested"):
            _require(type(record.get(field)) is bool, "pip record boolean")
        _require(not record["is_direct"] and not record["is_yanked"] and "requested_extras" not in record,
                 "pip direct, yanked or extras")
        metadata, download = record.get("metadata"), record.get("download_info")
        _require(type(metadata) is dict and type(download) is dict, "pip metadata")
        name = _normalized_name(metadata.get("name"))
        version = metadata.get("version")
        _require(type(version) is str and name in pins and name not in found
                 and version == pins[name][0], "pip distribution identity")
        _require("dir_info" not in download and "vcs_info" not in download, "pip nonarchive source")
        _artifact_url(download.get("url"), name, version)
        archive = download.get("archive_info")
        _require(type(archive) is dict and type(archive.get("hashes")) is dict, "pip archive hashes")
        digest = _hex(archive["hashes"].get("sha256"))
        _require(digest in pins[name][1], "pip artifact hash")
        found[name] = version
        diagnostics.append(("artifact." + name, version + ":" + digest))
    _require(tuple(sorted(found.items())) == inventory, "pip report inventory mismatch")
    return diagnostics


def _source_api(api: GitHub, repository: str, identity: int, commit: str, tree: str) -> None:
    scope = bootstrap.red_scope()
    record = api.obj(f"/repos/{repository}")
    expected = {"id": identity, "name": repository.split("/")[1], "full_name": repository}
    for key, value in expected.items():
        _require(type(record.get(key)) is type(value) and record[key] == value, "source repository identity")
    owner = record.get("owner")
    _require(type(owner) is dict, "source repository owner")
    for key, value in {"login": scope.owner, "id": scope.owner_id, "type": "Organization"}.items():
        _require(type(owner.get(key)) is type(value) and owner[key] == value, "source owner identity")
    record = api.obj(f"/repos/{repository}/git/commits/{commit}")
    _require(record.get("sha") == commit and type(record.get("tree")) is dict
             and record["tree"].get("sha") == tree, "source API commit or tree")


def _git_args(git: Path, root: Path) -> list[str]:
    options = {"credential.helper": "", "core.hooksPath": str(root / "empty-hooks"),
               "init.templateDir": str(root / "empty-template"), "core.attributesFile": os.devnull,
               "core.fsmonitor": "false", "protocol.allow": "never", "protocol.https.allow": "always",
               "http.sslVerify": "true", "submodule.recurse": "false", "fetch.fsckObjects": "true",
               "transfer.fsckObjects": "true", "gc.auto": "0", "maintenance.auto": "false",
               "tar.umask": "0022"}
    args = [str(git)]
    for key, value in options.items():
        args.extend(["-c", f"{key}={value}"])
    return args


def _repository_usage(directory: Path) -> tuple[int, int]:
    count = total = 0
    for parent, dirs, files in os.walk(directory, followlinks=False):
        for name in (*dirs, *files):
            path = Path(parent) / name
            metadata = path.lstat()
            _require(stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode), "Git storage kind")
            count += 1
            if stat.S_ISREG(metadata.st_mode):
                total += metadata.st_size
            _require(count <= 20000 and total <= 256 * _MIB, "Git storage post-fetch aggregate")
    return count, total


def _tree_entries(raw: bytes) -> dict[str, tuple[str, str]]:
    _require(raw.endswith(b"\0"), "Git tree terminator")
    records = raw[:-1].split(b"\0")
    _require(len(records) <= _MEMBER_COUNT, "Git tree count")
    entries: dict[str, tuple[str, str]] = {}
    folded = set()
    for record in records:
        match = re.fullmatch(rb"(100644|100755) blob ([a-f0-9]{40})\t(.+)", record)
        _require(match is not None, "Git tree mode or object")
        name = _path(match[3].decode("utf-8"))
        _require(name not in entries and name.casefold() not in folded, "Git tree collision")
        _require(name.rsplit("/", 1)[-1] != ".gitattributes", "source export attributes")
        entries[name] = (match[1].decode("ascii"), match[2].decode("ascii"))
        folded.add(name.casefold())
    return entries


def _source_archive(commands: _Commands, args: list[str], commit: str,
                    entries: dict[str, tuple[str, str]], output: Path) -> _Archive:
    commands.run(args + ["archive", "--format=tar", "--output", str(output), commit])
    archive = _archive(_read(output, _TAR_LIMIT, nonempty=True), source=True)
    regular = {name for name, member in archive.members.items() if member.isfile()}
    _require(regular == set(entries), "Git archive membership")
    parents = set()
    for name in entries:
        parent = posixpath.dirname(name)
        while parent:
            parents.add(parent)
            parent = posixpath.dirname(parent)
    _require(all(member.isfile() or name in parents for name, member in archive.members.items()),
             "Git archive directory membership")
    for name, (mode, blob) in entries.items():
        member = archive.members[name]
        _require(member.mode & 0o777 == int(mode[-3:], 8), "Git archive mode")
        raw = commands.run(args + ["cat-file", "blob", blob], limit=_SOURCE_MEMBER_LIMIT)
        _require(raw == _member_bytes(archive, name), "Git archive blob bytes")
    return archive


def _source(commands: _Commands, api: GitHub, git: Path, role: str,
            repository: str, identity: int, commit: str, tree: str) -> tuple[Path, list[tuple[str, str]]]:
    _source_api(api, repository, identity, commit, tree)
    bare = commands.root / (role + ".git")
    base = _git_args(git, commands.root)
    commands.run(base + ["init", "--bare", str(bare)])
    args = base + ["-C", str(bare)]
    commands.run(args + ["fetch", "--depth=1", "--no-tags", "--no-recurse-submodules",
                         "--no-auto-maintenance", "https://github.com/" + repository + ".git", commit])
    count, total = _repository_usage(bare)
    commands.run(args + ["fsck", "--strict", "--no-reflogs"])
    _require(commands.run(args + ["rev-parse", "--verify", commit + "^{commit}"]).strip() == commit.encode(),
             "Git commit identity")
    _require(commands.run(args + ["rev-parse", "--verify", commit + "^{tree}"]).strip() == tree.encode(),
             "Git tree identity")
    entries = _tree_entries(commands.run(args + ["ls-tree", "-rz", "--full-tree", commit], limit=12 * _MIB))
    archive = _source_archive(commands, args, commit, entries, commands.root / (role + ".tar"))
    if role == "core":
        lock = _object(_member_bytes(archive, "ci/module-fixture.lock.json"))
        scope = bootstrap.red_scope()
        _require(lock == {"repository": scope.module_repository, "commit": scope.module_commit,
                          "tree": scope.module_tree}, "core module fixture binding")
    directory = commands.root / role
    directory.mkdir(mode=0o700)
    for name, (mode, _) in entries.items():
        _write(directory / name, _member_bytes(archive, name), int(mode[-3:], 8))
    return directory, [(role + ".commit", commit), (role + ".tree", tree),
                       (role + ".git_file_count", str(count)), (role + ".git_bytes", str(total)),
                       (role + ".archive_sha256", _digest(archive.data))]


def _prepare(root: Path, release: ToolRelease, assets: dict[str, _Asset], api: GitHub) -> NativeTool:
    inputs = _tool_inputs(root, release)
    pins = _lock_union(release)
    archives, binaries = _runtime_archives(api, assets)
    commands = _Commands(root, _environment(root))
    _require(commands.run(["/usr/bin/uname", "-sm"], limit=256).strip() == b"Linux x86_64", "host platform")
    uv, gh = root / "bin" / "uv", root / "bin" / "gh"
    _write(uv, binaries["uv"], 0o700)
    _write(gh, binaries["gh"], 0o700)
    _executable(uv, root, assets["uv"].binary_sha256)
    _executable(gh, root, assets["gh"].binary_sha256)
    _require(commands.run([str(uv), "--no-config", "--version"], limit=4096).decode().split()[:2]
             == ["uv", assets["uv"].version], "UV version identity")
    _require(commands.run([str(gh), "--version"], limit=4096).decode().split()[:3]
             == ["gh", "version", assets["gh"].version], "GH version identity")
    python = _install_python(commands, uv, assets["python"], archives["python"])
    report = _install_packages(commands, uv, python, inputs)
    site, inventory = _probe(commands, python, assets["python"], final=True)
    _require(inventory == tuple(sorted((name, pin[0]) for name, pin in pins.items())), "final frozen inventory")
    diagnostics = _report(report, pins, inventory)
    git_name = shutil.which("git", path="/usr/bin:/bin")
    _require(git_name is not None, "protected host Git unavailable")
    git = Path(git_name).resolve(strict=True)
    git_digest = _digest(_read(git, _ARCHIVE_LIMIT, nonempty=True))
    git_version = commands.run([str(git), "--version"], limit=4096).decode().strip()
    _require(re.fullmatch(r"git version \d+\.\d+[^\r\n]*", git_version) is not None, "host Git version")
    diagnostics += [("git_path", str(git)), ("git_sha256", git_digest), ("git_version", git_version),
                    ("limits", "per-file=268435456;address-space=2147483648;processes=128;cpu-seconds=240;wall-seconds=300;post-fetch-total=268435456;post-fetch-count=20000;no-atomic-total-quota")]
    scope = bootstrap.red_scope()
    core, core_records = _source(commands, api, git, "core", scope.repository, scope.repository_id,
                                 scope.proof_base, scope.proof_base_tree)
    modules, module_records = _source(commands, api, git, "modules", scope.module_repository,
                                       scope.module_repository_id, scope.module_commit, scope.module_tree)
    diagnostics += core_records + module_records + commands.records
    for role, asset in assets.items():
        diagnostics += [(role + ".archive_sha256", asset.sha256), (role + ".binary_sha256", asset.binary_sha256)]
    diagnostics += [("manifest_sha256", release.selection.manifest_sha256),
                    ("runtime_descriptor_sha256", release.selection.runtime_descriptor_sha256)]
    return NativeTool(python, site, core, modules, uv, gh, release.selection,
                      release.selection.manifest_sha256, release.selection.runtime_descriptor_sha256,
                      inventory, tuple(diagnostics))


@contextmanager
def materialize_native_tool(expected_selection: ProtectedSelection, workspace: Path) -> Iterator[NativeTool]:
    """Own fresh checked bytes, private native paths and their complete caller lifetime."""
    with _private_root(workspace) as root:
        try:
            release = acquire_tool_release(now=datetime.now(UTC), expected_selection=expected_selection)
            assets = _descriptor(release.runtime_descriptor)
            tool = _prepare(root, release, assets, GitHub())
        except (ValueError, TypeError, KeyError, OSError, RuntimeError, OverflowError,
                RecursionError, tarfile.TarError, EOFError, subprocess.SubprocessError,
                http.client.HTTPException):
            raise ValueError("native materialization rejected: setup failed") from None
        yield tool
