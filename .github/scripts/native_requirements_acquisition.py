from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime

import native_requirements_bootstrap as bootstrap


@dataclass(frozen=True, slots=True)
class ProtectedSelection:
    index_commit: str
    policy_commit: str
    manifest_sha256: str
    runtime_descriptor_sha256: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class AcquiredRed:
    selection: ProtectedSelection
    context: bootstrap.AuthorizedRedContext


def _github():
    raise NotImplementedError


def acquire_red_context(*, runtime: Mapping[str, str], now: datetime) -> AcquiredRed:
    """Select protected policy and acquire the fresh fixed RED context."""
    raise NotImplementedError
