from __future__ import annotations

import hashlib
import json
from types import MappingProxyType

import pytest

from test_native_tool_release import DIRECTORY, MANIFEST, ROOT, load


INPUTS = ("build-locked.txt", "build-requirements.in", "locked.txt", "requirements.in")
SMALL_DIGESTS = (
    ("build-locked.txt", "392e074d6bf987b9c6c5960c33febfbabd94c801964bf05c8db9b3accd239357"),
    ("build-requirements.in", "3e6282d5bd7c90793cbbb56f16885d7cd4751d4bbae604ea4a036cd41f8fd398"),
    ("locked.txt", "02a21ea4342d51cac354ee7822388bca868caaaf7879ac4cc82295621d19e0ea"),
    ("requirements.in", "69b25c9a4470fea9dc2be160419d5828b222eae49575ae6346632ae07fc8a79f"),
)
SMALL_MANIFEST_SHA256 = "91922348a4c23b61eb9987673fc27bfb871eea60a442173daa4addc343e4fec7"


@pytest.fixture
def verifier(monkeypatch):
    return load("native_requirements_bootstrap", monkeypatch).verify_tool_bytes


@pytest.fixture
def captured():
    files = {
        "requirements.in": b"example==1\n",
        "locked.txt": b"example==1 --hash=sha256:fixture\n",
        "build-requirements.in": b"backend==2\n",
        "build-locked.txt": b"backend==2 --hash=sha256:fixture\n",
    }
    files["tool-files.json"] = json.dumps(
        {"schema_version": 1, "files": dict(SMALL_DIGESTS)}, sort_keys=True, separators=(",", ":")
    ).encode()
    return files


def repin(files, manifest):
    files["tool-files.json"] = json.dumps(manifest).encode()
    return hashlib.sha256(files["tool-files.json"]).hexdigest()


def test_small_captured_bytes_verify_against_independent_literal_pin(verifier, captured):
    before = dict(captured)
    assert verifier(MappingProxyType(captured), SMALL_MANIFEST_SHA256) == SMALL_DIGESTS
    assert captured == before


def test_exact_prepared_release_bytes_verify_without_descriptor(verifier):
    files = {name: (ROOT / DIRECTORY / name).read_bytes() for name in (*INPUTS, "tool-files.json")}
    assert len(files["locked.txt"]) == 65303
    expected = tuple(sorted(json.loads(files["tool-files.json"])["files"].items()))
    assert verifier(MappingProxyType(files), MANIFEST) == expected


@pytest.mark.parametrize("name", INPUTS)
def test_every_changed_input_refuses_under_unchanged_authenticated_manifest(verifier, captured, name):
    captured[name] += b"changed"
    with pytest.raises(ValueError):
        verifier(captured, SMALL_MANIFEST_SHA256)


@pytest.mark.parametrize("name", INPUTS)
def test_empty_input_refuses_even_when_manifest_and_hash_are_consistent(verifier, captured, name):
    captured[name] = b""
    manifest = json.loads(captured["tool-files.json"])
    manifest["files"][name] = hashlib.sha256(b"").hexdigest()
    expected = repin(captured, manifest)
    with pytest.raises(ValueError):
        verifier(captured, expected)


@pytest.mark.parametrize("fault", ["missing_input", "missing_manifest", "extra", "path", "case", "nonstring"])
def test_exact_canonical_capture_names_are_required(verifier, captured, fault):
    if fault == "missing_input":
        del captured["locked.txt"]
    elif fault == "missing_manifest":
        del captured["tool-files.json"]
    elif fault == "extra":
        captured["runtime.json"] = b"{}"
    else:
        name = {"path": "./locked.txt", "case": "Locked.txt", "nonstring": 1}[fault]
        captured[name] = captured.pop("locked.txt")
    with pytest.raises(ValueError):
        verifier(captured, SMALL_MANIFEST_SHA256)


@pytest.mark.parametrize("name", ["tool-files.json", "locked.txt"])
@pytest.mark.parametrize("kind", ["bytearray", "memoryview", "text", "none", "subclass"])
def test_capture_values_require_exact_immutable_bytes(verifier, captured, name, kind):
    class BytesSubclass(bytes):
        pass

    raw = captured[name]
    captured[name] = {
        "bytearray": bytearray(raw), "memoryview": memoryview(raw), "text": raw.decode(),
        "none": None, "subclass": BytesSubclass(raw),
    }[kind]
    with pytest.raises(ValueError):
        verifier(captured, SMALL_MANIFEST_SHA256)


@pytest.mark.parametrize("value", [None, [], b"not a mapping"])
def test_capture_requires_mapping(verifier, value):
    with pytest.raises(ValueError):
        verifier(value, SMALL_MANIFEST_SHA256)


@pytest.mark.parametrize("digest", ["0" * 64, "A" * 64, "a" * 63, None, True])
def test_manifest_pin_must_be_exact_lowercase_sha256_and_match(verifier, captured, digest):
    with pytest.raises(ValueError):
        verifier(captured, digest)


@pytest.mark.parametrize("name,limit", [("tool-files.json", 16384), ("locked.txt", 4194304)])
def test_inclusive_byte_limits_accept_exact_bound(verifier, captured, name, limit):
    manifest = json.loads(captured["tool-files.json"])
    if name == "locked.txt":
        captured[name] = b"x" * limit
        manifest["files"][name] = hashlib.sha256(captured[name]).hexdigest()
    digest = repin(captured, manifest)
    if name == "tool-files.json":
        captured[name] += b" " * (limit - len(captured[name]))
        digest = hashlib.sha256(captured[name]).hexdigest()
    expected = tuple(sorted(manifest["files"].items()))
    assert verifier(captured, digest) == expected


@pytest.mark.parametrize("name,limit", [("tool-files.json", 16384), ("locked.txt", 4194304)])
def test_oversized_bytes_refuse_even_with_matching_hashes(verifier, captured, name, limit):
    manifest = json.loads(captured["tool-files.json"])
    if name == "locked.txt":
        captured[name] = b"x" * (limit + 1)
        manifest["files"][name] = hashlib.sha256(captured[name]).hexdigest()
    digest = repin(captured, manifest)
    if name == "tool-files.json":
        captured[name] += b" " * (limit + 1 - len(captured[name]))
        digest = hashlib.sha256(captured[name]).hexdigest()
    with pytest.raises(ValueError):
        verifier(captured, digest)


@pytest.mark.parametrize("fault", [
    "unknown", "missing", "boolean_version", "wrong_version", "root_array", "files_array",
    "missing_name", "extra_name", "path_name", "case_name", "uppercase_digest", "digest_type", "wrong_digest",
])
def test_authenticated_manifest_is_closed_and_strict(verifier, captured, fault):
    manifest = json.loads(captured["tool-files.json"])
    if fault == "unknown":
        manifest["commands"] = []
    elif fault == "missing":
        del manifest["schema_version"]
    elif fault in {"boolean_version", "wrong_version"}:
        manifest["schema_version"] = True if fault == "boolean_version" else 2
    elif fault == "root_array":
        manifest = []
    elif fault == "files_array":
        manifest["files"] = []
    elif fault == "missing_name":
        del manifest["files"]["locked.txt"]
    elif fault == "extra_name":
        manifest["files"]["runtime.json"] = "0" * 64
    elif fault in {"path_name", "case_name"}:
        name = "./locked.txt" if fault == "path_name" else "Locked.txt"
        manifest["files"][name] = manifest["files"].pop("locked.txt")
    else:
        manifest["files"]["locked.txt"] = {"uppercase_digest": "A" * 64, "digest_type": True, "wrong_digest": "0" * 64}[fault]
    digest = repin(captured, manifest)
    with pytest.raises(ValueError):
        verifier(captured, digest)


@pytest.mark.parametrize("fault", ["duplicate_root", "duplicate_file", "invalid_json", "invalid_utf8"])
def test_authenticated_json_rejects_duplicates_and_malformed_bytes(verifier, captured, fault):
    raw = captured["tool-files.json"]
    if fault == "duplicate_root":
        raw = raw[:-1] + b',"schema_version":1}'
    elif fault == "duplicate_file":
        raw = raw.replace(b'"files":{', b'"files":{"locked.txt":"' + SMALL_DIGESTS[2][1].encode() + b'",', 1)
    else:
        raw = b"{" if fault == "invalid_json" else b"\xff"
    captured["tool-files.json"] = raw
    with pytest.raises(ValueError):
        verifier(captured, hashlib.sha256(raw).hexdigest())
