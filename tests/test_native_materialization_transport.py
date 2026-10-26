from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
REVISION = "2" * 40
TOOL = ".github/native-tools/dev786/locked.txt"


def load_module(name, monkeypatch):
    spec = importlib.util.spec_from_file_location(name, ROOT / f".github/scripts/{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module


def contents(path, raw):
    return {
        "type": "file", "encoding": "base64", "path": path,
        "name": path.rsplit("/", 1)[-1], "size": len(raw),
        "content": base64.encodebytes(raw).decode("ascii"),
        "sha": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(),
    }


@pytest.fixture
def wire(monkeypatch):
    module = load_module("late_cycle_admission", monkeypatch)
    monkeypatch.setenv("GH_TOKEN", "fixture-token")
    monkeypatch.setenv("GITHUB_API_URL", "https://api.github.com")
    routes, requests, reads, closed = {}, [], [], []

    class Connection:
        def __init__(self, host, timeout):
            assert 0 < timeout <= 60
            self.host = host

        def request(self, method, target, headers):
            assert method == "GET"
            self.key = (self.host, target)
            requests.append((self.host, target, dict(headers)))
            assert self.key in routes, f"unexpected network request {self.key}"

        def getresponse(self):
            reply = routes[self.key]
            if isinstance(reply, Exception):
                raise reply
            status, body, headers = reply

            def read(limit):
                reads.append(limit)
                assert 0 < limit <= 64 * 1024 * 1024 + 1
                return body[:limit]

            return SimpleNamespace(status=status, read=read, getheader=lambda key, default=None: headers.get(key, default))

        def close(self):
            closed.append(self.host)

    monkeypatch.setattr(module.http.client, "HTTPSConnection", Connection)
    return SimpleNamespace(module=module, api=module.GitHub(), routes=routes, requests=requests, reads=reads, closed=closed)


def blob_route(wire, raw, path=TOOL):
    value = contents(path, raw)
    key = ("api.github.com", f"/repos/nold-ai/.github/contents/{path}?ref={REVISION}")
    wire.routes[key] = (200, json.dumps(value).encode(), {})
    return key, value


@pytest.mark.parametrize("wrapped", [True, False])
def test_real_65303_byte_lock_is_bound_to_exact_git_blob(wire, wrapped):
    raw = (ROOT / TOOL).read_bytes()
    assert len(raw) == 65303
    key, value = blob_route(wire, raw)
    if not wrapped:
        value["content"] = base64.b64encode(raw).decode()
        wire.routes[key] = (200, json.dumps(value).encode(), {})
    assert wire.api.immutable_contents("nold-ai/.github", TOOL, REVISION, max_bytes=131072) == raw
    assert wire.requests[0][2]["Authorization"] == "Bearer fixture-token"
    assert len(wire.closed) == 1


@pytest.mark.parametrize("size,limit,accept", [(16384, 16384, True), (16385, 16384, False), (131072, 131072, True), (131073, 131072, False)])
def test_decoded_content_bounds_are_per_request(wire, size, limit, accept):
    raw = b"x" * size
    blob_route(wire, raw)
    if accept:
        assert wire.api.immutable_contents("nold-ai/.github", TOOL, REVISION, max_bytes=limit) == raw
    else:
        with pytest.raises(ValueError):
            wire.api.immutable_contents("nold-ai/.github", TOOL, REVISION, max_bytes=limit)


@pytest.mark.parametrize("field,value", [
    ("type", "symlink"), ("path", "other"), ("name", "other"),
    ("encoding", "none"), ("size", True), ("size", 2),
    ("sha", "0" * 40), ("content", "Zh=="), ("content", "Zg==!"),
])
def test_content_metadata_and_canonical_encoding_are_checked_together(wire, field, value):
    key, response = blob_route(wire, b"f")
    response[field] = value
    wire.routes[key] = (200, json.dumps(response).encode(), {})
    with pytest.raises(ValueError):
        wire.api.immutable_contents("nold-ai/.github", TOOL, REVISION, max_bytes=16384)


@pytest.mark.parametrize("repository,path,revision,limit", [
    ("nold-ai/.github/../other", TOOL, REVISION, 16384),
    ("nold-ai/.github", "../outside", REVISION, 16384),
    ("nold-ai/.github", TOOL + "?ref=main", REVISION, 16384),
    ("nold-ai/.github", TOOL, "main", 16384),
    ("nold-ai/.github", TOOL, REVISION, True),
    ("nold-ai/.github", TOOL, REVISION, 131073),
])
def test_unsafe_content_requests_refuse_before_network(wire, repository, path, revision, limit):
    with pytest.raises(ValueError):
        wire.api.immutable_contents(repository, path, revision, max_bytes=limit)
    assert not wire.requests


def test_oversize_encoding_refuses_before_decoder(wire, monkeypatch):
    key, response = blob_route(wire, b"f")
    response["content"] = "A" * 174768
    wire.routes[key] = (200, json.dumps(response).encode(), {})
    decoder = wire.module.base64.b64decode

    def decode(value, *args, **kwargs):
        assert len(value) <= 174764, "oversized allocation reached base64 decoder"
        return decoder(value, *args, **kwargs)

    monkeypatch.setattr(wire.module.base64, "b64decode", decode)
    with pytest.raises(ValueError):
        wire.api.immutable_contents("nold-ai/.github", TOOL, REVISION, max_bytes=131072)


ASSET = "/repos/astral-sh/uv/releases/assets/664336023"


@pytest.mark.parametrize("hops", [0, 1, 2])
def test_release_binary_200_and_redirects_strip_credentials(wire, hops):
    body = b"\x1f\x8bfixture-public-binary"
    key = ("api.github.com", ASSET)
    for hop in range(hops):
        target = f"/asset/{hop}?signature=fixture"
        wire.routes[key] = (302, b"", {"Location": "https://release-assets.githubusercontent.com" + target})
        key = ("release-assets.githubusercontent.com", target)
    wire.routes[key] = (200, body, {"Content-Length": str(len(body)), "Content-Type": "application/octet-stream"})
    assert wire.api.release_asset("astral-sh/uv", 664336023, max_bytes=len(body)) == body
    assert wire.requests[0][2]["Accept"] == "application/octet-stream"
    assert wire.requests[0][2]["Authorization"] == "Bearer fixture-token"
    assert all("Authorization" not in headers and "Cookie" not in headers for _, _, headers in wire.requests[1:])
    assert len(wire.closed) == hops + 1


@pytest.mark.parametrize("location", [
    "http://release-assets.githubusercontent.com/file",
    "https://evil.example/file", "https://release-assets.githubusercontent.com.evil.example/file",
    "https://a.blob.core.windows.net/file", "https://user@release-assets.githubusercontent.com/file",
    "https://release-assets.githubusercontent.com:443/file", "https://release-assets.githubusercontent.com/file#fragment",
])
def test_release_redirect_host_is_exact_and_https_only(wire, location):
    wire.routes[("api.github.com", ASSET)] = (302, b"", {"Location": location})
    with pytest.raises(ValueError):
        wire.api.release_asset("astral-sh/uv", 664336023, max_bytes=100)
    assert len(wire.requests) == 1 and len(wire.closed) == 1


def test_third_redirect_refuses_without_fourth_request(wire):
    wire.routes[("api.github.com", ASSET)] = (302, b"", {"Location": "https://release-assets.githubusercontent.com/a"})
    wire.routes[("release-assets.githubusercontent.com", "/a")] = (302, b"", {"Location": "https://release-assets.githubusercontent.com/b"})
    wire.routes[("release-assets.githubusercontent.com", "/b")] = (302, b"", {"Location": "https://release-assets.githubusercontent.com/c"})
    with pytest.raises(ValueError):
        wire.api.release_asset("astral-sh/uv", 664336023, max_bytes=100)
    assert len(wire.requests) == 3 and len(wire.closed) == 3


@pytest.mark.parametrize("reply", [(200, b"x" * 101, {}), (403, b"denied", {}), TimeoutError("fixture timeout")])
def test_release_size_status_and_timeout_refuse_and_close(wire, reply):
    wire.routes[("api.github.com", ASSET)] = reply
    with pytest.raises(ValueError):
        wire.api.release_asset("astral-sh/uv", 664336023, max_bytes=100)
    assert len(wire.closed) == 1


@pytest.mark.parametrize("repository,asset_id,limit", [
    ("evil/uv", 1, 100), ("astral-sh/uv", True, 100), ("astral-sh/uv", 0, 100),
    ("astral-sh/uv", "1/../../other", 100), ("astral-sh/uv", 1, 67108865), ("astral-sh/uv", 1, True),
])
def test_release_request_role_and_numeric_bounds_precede_network(wire, repository, asset_id, limit):
    with pytest.raises(ValueError):
        wire.api.release_asset(repository, asset_id, max_bytes=limit)
    assert not wire.requests
