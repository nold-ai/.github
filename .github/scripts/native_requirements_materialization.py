from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from native_requirements_acquisition import ProtectedSelection


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


@contextmanager
def materialize_native_tool(
    expected_selection: ProtectedSelection, workspace: Path
) -> Iterator[NativeTool]:
    """Own fresh checked bytes, private native paths and their complete caller lifetime."""
    raise NotImplementedError
