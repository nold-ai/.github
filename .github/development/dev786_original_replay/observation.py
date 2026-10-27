"""Pure, finite inspection of the first observation unit's sealed packets."""

from __future__ import annotations

import hashlib
import re
from collections import deque
from dataclasses import dataclass, fields, replace
from enum import Enum
from typing import Generic, Literal, TypeVar


class Origin(Enum):
    """A provenance label is data, not authentication of a run."""

    ORIGINAL_ROW = "OriginalRow"
    ACTUAL_CONTROL = "ActualControl"
    SYNTHETIC = "Synthetic"


@dataclass(frozen=True, slots=True)
class TaskKey:
    stage: str
    tid: int
    birth_generation: int


@dataclass(frozen=True, slots=True)
class ImageKey:
    task: TaskKey
    generation: int


@dataclass(frozen=True, slots=True)
class RawRef:
    """Half-open byte range including newline; physical lines start at one."""

    member: MemberId
    byte_start: int
    byte_stop: int
    physical_line: int


@dataclass(frozen=True, slots=True)
class MemberId:
    value: str


@dataclass(frozen=True, slots=True)
class Complete:
    member_id: MemberId
    name: str
    data: bytes
    byte_length: int
    sha256: str


@dataclass(frozen=True, slots=True)
class StableFinalSize:
    byte_length: int


@dataclass(frozen=True, slots=True)
class ObservedLowerBound:
    byte_length: int


@dataclass(frozen=True, slots=True)
class Partial:
    member_id: MemberId
    name: str
    data: bytes
    prefix_length: int
    prefix_sha256: str
    extent: StableFinalSize | ObservedLowerBound | Unknown
    reason: str


@dataclass(frozen=True, slots=True)
class Withheld:
    member_id: MemberId
    category: str
    observed_bytes: int
    reason: str


CapturedMember = Complete | Partial | Withheld


@dataclass(frozen=True, slots=True)
class TraceAssociation:
    member: CapturedMember
    task: TaskKey | Unknown


@dataclass(frozen=True, slots=True)
class BinaryIdentity:
    spelling: bytes
    realpath: bytes
    byte_length: int
    sha256: str


@dataclass(frozen=True, slots=True)
class Launch:
    """Owned launch receipt; constructing one never establishes actual execution."""

    task: TaskKey
    argv: tuple[bytes, ...]
    environment: tuple[tuple[bytes, bytes], ...]
    cwd: bytes
    binary: BinaryIdentity
    tracer_argv: tuple[bytes, ...]
    tracer_environment: tuple[tuple[bytes, bytes], ...]
    tracer_pid: int
    session_id: int
    stdin: Literal["DEVNULL"]
    close_fds: bool
    pass_fds: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class WaitExited:
    code: int


@dataclass(frozen=True, slots=True)
class WaitSignaled:
    signal: str


@dataclass(frozen=True, slots=True)
class WaitMissing:
    reason: str


@dataclass(frozen=True, slots=True)
class Cleanup:
    tracer_reaped: bool
    owned_group_empty: bool


@dataclass(frozen=True, slots=True)
class CaptureEnd:
    trigger: str
    wait: WaitExited | WaitSignaled | WaitMissing
    cleanup: Cleanup


@dataclass(frozen=True, slots=True)
class StagePacket:
    origin: Origin
    origin_label: str
    stage: str
    launch: Launch | Unknown
    trace_members: tuple[TraceAssociation, ...]
    stdout: CapturedMember | Unknown
    stderr: CapturedMember | Unknown
    tracer_diagnostics: CapturedMember | Unknown
    binary_identities: tuple[BinaryIdentity, ...]
    end: CaptureEnd
    accounting: Checkpoint


@dataclass(frozen=True, slots=True)
class SharingEpoch:
    kind: Literal["cwd", "fd"]
    owner: TaskKey
    generation: int


@dataclass(frozen=True, slots=True)
class DependencyInterval:
    """Inherited state remains provisional until its full interval reconciles."""

    epoch: SharingEpoch
    established_at: RawRef | None
    used_at: RawRef
    causal_refs: tuple[RawRef, ...]


T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class Established(Generic[T]):
    value: T
    basis: Literal["owned-launch", "direct-operation", "causal-inheritance", "stable-identity"]
    raw_refs: tuple[RawRef, ...]
    dependencies: tuple[DependencyInterval, ...] = ()


@dataclass(frozen=True, slots=True)
class Unknown:
    reason: str
    raw_refs: tuple[RawRef, ...] = ()


@dataclass(frozen=True, slots=True)
class Exited:
    code: int


@dataclass(frozen=True, slots=True)
class Killed:
    signal: str


@dataclass(frozen=True, slots=True)
class TerminalMarker:
    terminal: Exited | Killed
    raw_refs: tuple[RawRef, ...]


@dataclass(frozen=True, slots=True)
class Task:
    key: TaskKey
    parent_image: ImageKey | None
    creation_kind: Literal["launch", "clone"]
    creation_flags: bytes | None
    birth_refs: tuple[RawRef, ...]
    tgid: Established[int] | Unknown
    terminal: Established[Exited | Killed] | Unknown


@dataclass(frozen=True, slots=True)
class Image:
    key: ImageKey
    binary: Established[BinaryIdentity] | Unknown
    cwd: Established[bytes] | Unknown


@dataclass(frozen=True, slots=True)
class ExecFailed:
    errno: str


@dataclass(frozen=True, slots=True)
class ExecSucceeded:
    image: ImageKey


@dataclass(frozen=True, slots=True)
class ExecAttempt:
    task: TaskKey
    previous_image: ImageKey
    executable: bytes
    argv: tuple[bytes, ...]
    environment: tuple[tuple[bytes, bytes], ...]
    cwd: Established[bytes] | Unknown
    result: ExecFailed | ExecSucceeded
    raw_refs: tuple[RawRef, ...]


@dataclass(frozen=True, slots=True)
class PathUse:
    task: TaskKey
    image: ImageKey
    syscall: str
    raw_path: bytes
    dirfd: bytes | None
    annotation: bytes | None
    resolution: Established[bytes] | Unknown
    result: int
    errno: str | None
    raw_refs: tuple[RawRef, ...]


@dataclass(frozen=True, slots=True)
class Reason:
    code: str
    task: TaskKey | None
    raw_refs: tuple[RawRef, ...]


@dataclass(frozen=True, slots=True)
class Usage:
    traversal_bytes: int = 0
    retained: tuple[tuple[str, int], ...] = ()
    export_files: int = 0
    physical_records: int = 0
    scope_counts: tuple[tuple[str, int, int], ...] = ()
    four_row_members: int = 0
    four_row_tasks: int = 0


@dataclass(frozen=True, slots=True)
class MemberOccurrence:
    scope: str
    role: str
    member: CapturedMember
    association: TaskKey | Unknown
    prefix: tuple[int, int] | Unknown


@dataclass(frozen=True, slots=True)
class TaskOccurrence:
    key: TaskKey
    witness: Launch | tuple[RawRef, ...]


@dataclass(frozen=True, slots=True)
class Checkpoint:
    session_id: str
    operation_sequence: int
    committed: Usage
    measured: Usage
    conservative: Usage
    closure_reserved: Usage
    basis: Book
    scope: str
    allowance: Usage


@dataclass(frozen=True, slots=True)
class OperationReceipt:
    before: Checkpoint
    measured_delta: Usage
    conservative_delta: Usage
    unused_allowance: Usage
    refusals: tuple[Reason, ...]
    encountered: Usage
    newly_charged: Usage
    coverage: tuple[MemberOccurrence | TaskOccurrence, ...]


@dataclass(frozen=True, slots=True)
class Incomplete:
    reasons: tuple[Reason, ...]


@dataclass(frozen=True, slots=True)
class Book:
    stages: tuple[Observation, ...]
    identities: tuple
    products: tuple
    operations: tuple[OperationReceipt, ...]
    occurrences: tuple[MemberOccurrence | TaskOccurrence, ...]
    terminal_operations: tuple[OperationReceipt | None, OperationReceipt | None]
    original_final: Unknown
    replay_final: Unknown
    retrieval: Unknown
    assessment: Incomplete


@dataclass(frozen=True, slots=True)
class FixedHelperIdentity:
    name: str
    byte_length: int
    sha256: str
    module_name: str


@dataclass(frozen=True, slots=True)
class ReadDebit:
    name: str
    operation: str
    requested_bytes: int
    delivered_bytes: int


@dataclass(frozen=True, slots=True)
class InitializationReceipt:
    helper_identities: tuple[FixedHelperIdentity, ...]
    bounded_reads: tuple[ReadDebit, ...]
    measured_usage: Usage
    conservative_debit: Usage
    prepaid_envelope: Usage
    adoption_reserved: Usage


@dataclass(frozen=True, slots=True)
class Observation:
    origin: Origin
    origin_label: str
    stage: str
    status: Literal["observed", "incomplete"]
    members: tuple[CapturedMember, ...]
    launch: Launch | Unknown
    tracer_diagnostics: CapturedMember | Unknown
    end: CaptureEnd
    tasks: tuple[Task, ...]
    images: tuple[Image, ...]
    exec_attempts: tuple[ExecAttempt, ...]
    path_uses: tuple[PathUse, ...]
    reasons: tuple[Reason, ...]
    terminal_markers: tuple[TerminalMarker, ...]
    operation: OperationReceipt


READ_LIMIT = 268435456
RECORD_LIMIT = 500000
SCOPE_LIMIT = 512
ROW_LIMIT = 1024
FILE_LIMIT = 64
SOURCE_LIMIT = 262144
CLOSURE_BYTES = 1048576
CLOSURE_METADATA = 65536
CONTROL_RECEIPT = 1048576
RETAINED_LIMITS = (("controls", 8388608), ("preparation-restoration-export", 8388608),
                   ("replay-reports-metadata", 16777216), ("replay-streams", 16777216),
                   ("replay-traces", 67108864))
_ROWS = ("original-row-1", "original-row-2", "original-row-3", "original-row-4")


def _coordinates(value: Usage) -> dict:
    if type(value) is not Usage:
        raise ValueError("invalid-usage")
    result = {}
    for name in ("traversal_bytes", "export_files", "physical_records", "four_row_members", "four_row_tasks"):
        count = getattr(value, name)
        if type(count) is not int or count < 0:
            raise ValueError("invalid-usage-scalar")
        if count:
            result[name] = count
    if type(value.retained) is not tuple or len(value.retained) > len(RETAINED_LIMITS):
        raise ValueError("invalid-retained-shape")
    previous = ""
    for entry in value.retained:
        if type(entry) is not tuple or len(entry) != 2:
            raise ValueError("invalid-retained-shape")
        name, count = entry
        if type(name) is not str or name <= previous or name not in dict(RETAINED_LIMITS) or type(count) is not int or count < 0:
            raise ValueError("invalid-retained-coordinate")
        previous = name
        if count:
            result[("retained", name)] = count
    if type(value.scope_counts) is not tuple or len(value.scope_counts) > 64:
        raise ValueError("invalid-scope-shape")
    previous = ""
    total_members = total_tasks = 0
    for entry in value.scope_counts:
        if type(entry) is not tuple or len(entry) != 3:
            raise ValueError("invalid-scope-shape")
        name, members, tasks = entry
        if (type(name) is not str or not 0 < len(name) <= 128 or name <= previous
                or type(members) is not int or type(tasks) is not int or min(members, tasks) < 0):
            raise ValueError("invalid-scope-coordinate")
        previous = name
        if members:
            result[("members", name)] = members
        if tasks:
            result[("tasks", name)] = tasks
        if name in _ROWS:
            total_members += members
            total_tasks += tasks
    if (total_members, total_tasks) != (value.four_row_members, value.four_row_tasks):
        raise ValueError("invalid-row-projection")
    return result


def _usage(values: dict) -> Usage:
    scalars = {key: count for key, count in values.items() if type(key) is str and count}
    retained = tuple(sorted((key[1], count) for key, count in values.items()
                            if type(key) is tuple and key[0] == "retained" and count))
    scopes = sorted({key[1] for key, count in values.items()
                     if type(key) is tuple and key[0] in ("members", "tasks") and count})
    return Usage(**scalars, retained=retained, scope_counts=tuple(
        (scope, values.get(("members", scope), 0), values.get(("tasks", scope), 0)) for scope in scopes))


def _plus(*values: Usage) -> Usage:
    result = {}
    for value in values:
        for key, count in _coordinates(value).items():
            result[key] = result.get(key, 0) + count
    return _usage(result)


def _minus(left: Usage, right: Usage) -> Usage:
    result = _coordinates(left)
    for key, count in _coordinates(right).items():
        result[key] = result.get(key, 0) - count
    if any(count < 0 for count in result.values()):
        raise ValueError("usage-overflow")
    return _usage(result)


def _closure_usage() -> Usage:
    return Usage(CLOSURE_BYTES, (("preparation-restoration-export", CLOSURE_METADATA),), 1)


def _allowance(scope: str, checkpoint: Checkpoint) -> Usage:
    used = _coordinates(checkpoint.committed)
    held = _coordinates(checkpoint.closure_reserved)
    remaining = lambda key, cap: max(0, cap - used.get(key, 0) - held.get(key, 0))
    member_room = remaining(("members", scope), SCOPE_LIMIT)
    task_room = remaining(("tasks", scope), SCOPE_LIMIT)
    original = scope in _ROWS
    if original:
        member_room = min(member_room, remaining("four_row_members", ROW_LIMIT))
        task_room = min(task_room, remaining("four_row_tasks", ROW_LIMIT))
    categories = ("replay-traces", "replay-streams", "replay-reports-metadata") if original else ("controls",)
    if scope in ("preparation", "closure"):
        categories = ("preparation-restoration-export",)
        member_room = task_room = 0
    retained = []
    for name, cap in RETAINED_LIMITS:
        if name in categories:
            room = remaining(("retained", name), cap)
            if name == "controls":
                room = min(room, CONTROL_RECEIPT)
            if room:
                retained.append((name, room))
    return Usage(remaining("traversal_bytes", READ_LIMIT), tuple(retained),
                 remaining("export_files", FILE_LIMIT), remaining("physical_records", RECORD_LIMIT),
                 ((scope, member_room, task_room),) if member_room or task_room else (),
                 member_room if original else 0, task_room if original else 0)


def _width(value) -> int:
    if type(value) in (bytes, bytearray, str):
        return len(value)
    if value is None or type(value) in (int, bool) or isinstance(value, Enum):
        return 8
    if type(value) is tuple:
        return 8 * len(value) + sum(_width(item) for item in value)
    if isinstance(value, (Complete, Partial)):
        return 8 * len(fields(value)) + sum(_width(getattr(value, field.name))
                                            for field in fields(value) if field.name != "data")
    if isinstance(value, Checkpoint):
        return 80 + len(value.session_id) + len(value.scope)
    if hasattr(type(value), "__dataclass_fields__") and not isinstance(value, Book):
        return 8 * len(fields(value)) + sum(_width(getattr(value, field.name)) for field in fields(value))
    raise ValueError("invalid-accounting-value")


class _Tally:
    def __init__(self, checkpoint: Checkpoint, allowance: Usage | None = None) -> None:
        self.before = checkpoint
        self.allowance = checkpoint.allowance if allowance is None else allowance
        self.capacity = _coordinates(self.allowance)
        self.used = {}
        self.encountered = {}
        self.coverage = []
        self.refusals = []

    def charge(self, key, amount: int) -> None:
        if amount < 0 or self.used.get(key, 0) + amount > self.capacity.get(key, 0):
            raise _Rejected("accounting-limit")
        self.used[key] = self.used.get(key, 0) + amount

    def admit(self, amount: int) -> None:
        if amount < 0 or self.used.get("traversal_bytes", 0) + amount > self.capacity.get("traversal_bytes", 0):
            raise _Rejected("accounting-limit")

    def pay(self, amount: int) -> None:
        self.charge("traversal_bytes", amount)

    def metadata(self, value) -> None:
        self.pay(_width(value))

    def count(self, kind: str, amount: int = 1) -> None:
        key = "physical_records" if kind == "records" else (kind, self.before.scope)
        keys = (key, "four_row_" + kind) if kind != "records" and self.before.scope in _ROWS else (key,)
        for coordinate in keys:
            if self.used.get(coordinate, 0) + amount > self.capacity.get(coordinate, 0):
                raise _Rejected("accounting-count-limit")
        for coordinate in keys:
            self.charge(coordinate, amount)

    def encounter(self, kind: str, amount: int = 1) -> None:
        key = "physical_records" if kind == "records" else (kind, self.before.scope)
        self.encountered[key] = self.encountered.get(key, 0) + amount
        if kind != "records" and self.before.scope in _ROWS:
            key = "four_row_" + kind
            self.encountered[key] = self.encountered.get(key, 0) + amount

    def retain(self, size: int, role: str = "metadata") -> None:
        category = "controls"
        if self.before.scope in _ROWS:
            category = {"trace": "replay-traces", "stdout": "replay-streams", "stderr": "replay-streams"}.get(role, "replay-reports-metadata")
        if self.before.scope in ("preparation", "closure"):
            category = "preparation-restoration-export"
        self.charge(("retained", category), size)

    def lookup(self, value):
        for prior in self.before.basis.occurrences:
            self.pay(8)
            if type(value) is MemberId and type(prior) is MemberOccurrence:
                if _equal(self, prior.member.member_id.value, value.value):
                    return prior
            elif type(value) is TaskKey and type(prior) is TaskOccurrence:
                if _same(self, prior.key, value):
                    return prior
        return None

    def receipt(self) -> OperationReceipt:
        measured = _usage(self.used)
        counts = replace(measured, traversal_bytes=0, retained=(), export_files=0)
        return OperationReceipt(self.before, measured, Usage(), _minus(self.allowance, measured),
                                tuple(self.refusals), _usage(self.encountered), counts, tuple(self.coverage))


def _equal(tally: _Tally, left, right) -> bool:
    if type(left) in (bytes, bytearray, str) and type(right) is type(left):
        tally.pay(len(left) + len(right))
    return left == right


def _same(tally: _Tally, left, right) -> bool:
    if left is right:
        tally.pay(8)
        return True
    if type(left) is not type(right):
        tally.pay(8)
        return False
    if type(left) in (bytes, bytearray, str, int, bool) or left is None or isinstance(left, Enum):
        return _equal(tally, left, right)
    if type(left) is tuple:
        tally.pay(16)
        return len(left) == len(right) and all(_same(tally, a, b) for a, b in zip(left, right))
    if hasattr(type(left), "__dataclass_fields__") and not isinstance(left, (Book, Checkpoint)):
        tally.pay(8 * len(fields(left)))
        return all(_same(tally, getattr(left, field.name), getattr(right, field.name)) for field in fields(left))
    raise _Rejected("invalid-accounting-value")


def _hash(tally: _Tally, raw: bytes) -> str:
    tally.pay(len(raw))
    return hashlib.sha256(raw).hexdigest()


def _slice(tally: _Tally, raw: bytes, start: int, stop: int) -> bytes:
    tally.pay(max(0, min(len(raw), stop) - min(len(raw), start)))
    return raw[start:stop]


def _regex(tally: _Tally, pattern: bytes | str, raw: bytes | str):
    tally.pay(len(raw))
    return re.fullmatch(pattern, raw)


def _contains(tally: _Tally, needle: bytes, raw: bytes) -> bool:
    tally.pay(len(raw))
    return needle in raw


def _split(tally: _Tally, raw: bytes | str, separator):
    tally.pay(len(raw))
    return raw.split(separator)


def _strip(tally: _Tally, raw: bytes) -> bytes:
    tally.pay(len(raw))
    return raw.strip()


def inspect(packet: StagePacket) -> Observation:
    """Inspect sealed data using the exact issued allowance and before-Book."""
    tally = _Tally(packet.accounting)
    reasons = []
    members = []
    markers = []
    facts = ((), (), (), ())
    try:
        if packet.stage != packet.accounting.scope or _coordinates(packet.accounting.allowance) != _coordinates(_allowance(packet.stage, packet.accounting)):
            raise _Rejected("invalid-checkpoint")
        tally.metadata(packet)
        tally.retain(_width(packet))
        if type(packet.launch) is Launch:
            _admit_task(tally, packet.launch.task, packet.launch)
        else:
            reasons.append(Reason("launch-unknown", None, ()))
        events = {}
        structural = []
        trace_names = []
        trace_tasks = []
        if len(packet.trace_members) > SCOPE_LIMIT:
            raise _Rejected("accounting-count-limit")
        for association in packet.trace_members:
            if type(association.task) is not TaskKey:
                structural.append(Reason("trace-association-unknown", None, ()))
            else:
                task = association.task
                tally.metadata(task)
                if (not _equal(tally, task.stage, packet.stage) or type(task.tid) is not int or task.tid <= 0
                        or type(task.birth_generation) is not int or task.birth_generation != 0
                        or any(_same(tally, task, prior) for prior in trace_tasks)):
                    structural.append(Reason("invalid-raw-member-association", task, ()))
                trace_tasks.append(task)
            raw = association.member
            if type(raw) in (Complete, Partial):
                if any(_equal(tally, raw.name, prior) for prior in trace_names):
                    structural.append(Reason("invalid-raw-member-association", association.task if type(association.task) is TaskKey else None, ()))
                trace_names.append(raw.name)
            occurrence = _admit_member(tally, raw, "trace", association.task)
            members.append(raw)
            try:
                verified = _verify_member(tally, raw)
                if verified and type(association.task) is TaskKey:
                    decoded, errors, found, prefix = _decode_member(raw, association.task, tally, occurrence)
                    events[association.task] = decoded
                    structural.extend(errors)
                    markers.extend(found)
                elif type(raw) is Partial:
                    structural.append(Reason("partial-raw-member", association.task if type(association.task) is TaskKey else None, ()))
                elif type(raw) is Withheld:
                    structural.append(Reason("withheld-raw-member", association.task if type(association.task) is TaskKey else None, ()))
            except _Rejected as error:
                if error.code.startswith("accounting") or error.code == "member-binding-conflict":
                    raise
                structural.append(Reason(error.code, association.task if type(association.task) is TaskKey else None, error.raw_refs))
        for role, raw in (("stdout", packet.stdout), ("stderr", packet.stderr)):
            if type(raw) is Unknown:
                structural.append(Reason("stream-unknown", None, ()))
                continue
            _admit_member(tally, raw, role, Unknown("stream", ()))
            members.append(raw)
            try:
                if not _verify_member(tally, raw):
                    structural.append(Reason("partial-raw-member" if type(raw) is Partial else "withheld-raw-member", None, ()))
            except _Rejected as error:
                structural.append(Reason(error.code, None, error.raw_refs))
        if not structural and type(packet.launch) is Launch:
            _validate_launch(packet, tally, structural)
        reasons.extend(structural)
        if not structural and type(packet.launch) is Launch:
            facts = _interpret(packet, events, reasons, tally)
        _capture_reasons(packet, reasons)
        tally.metadata((facts, tuple(reasons), tuple(markers), tuple(tally.coverage)))
        tally.retain(_width((facts, tuple(reasons), tuple(markers), tuple(tally.coverage))))
    except _Rejected as error:
        reason = Reason(error.code, None, error.raw_refs)
        reasons.append(reason)
        tally.refusals.append(reason)
        facts = ((), (), (), ())
    except (ValueError, TypeError, AttributeError):
        reason = Reason("invalid-packet", None, ())
        reasons.append(reason)
        tally.refusals.append(reason)
        facts = ((), (), (), ())
    return Observation(packet.origin, packet.origin_label, packet.stage,
                       "incomplete" if reasons else "observed", tuple(members), packet.launch,
                       packet.tracer_diagnostics, packet.end, *facts, tuple(dict.fromkeys(reasons)),
                       tuple(markers), tally.receipt())


def _admit_task(tally: _Tally, task: TaskKey, witness) -> None:
    tally.metadata(task)
    if (type(task) is not TaskKey or not _equal(tally, task.stage, tally.before.scope)
            or type(task.tid) is not int or task.tid <= 0 or type(task.birth_generation) is not int or task.birth_generation < 0):
        raise _Rejected("invalid-task-identity")
    for item in tally.coverage:
        if type(item) is TaskOccurrence and _same(tally, item.key, task):
            if not _same(tally, item.witness, witness):
                raise _Rejected("task-binding-conflict")
            return
    prior = tally.lookup(task)
    if prior is not None:
        if not _same(tally, prior.witness, witness):
            raise _Rejected("task-binding-conflict")
        occurrence = prior
    else:
        tally.count("tasks")
        occurrence = TaskOccurrence(task, witness)
    tally.encounter("tasks")
    tally.coverage.append(occurrence)


def _admit_member(tally: _Tally, member: CapturedMember, role: str, association) -> MemberOccurrence:
    if type(member) not in (Complete, Partial, Withheld) or type(member.member_id) is not MemberId:
        raise _Rejected("invalid-raw-member")
    tally.metadata(member.member_id)
    if not _regex(tally, r"[A-Za-z0-9_.-]{1,128}", member.member_id.value):
        raise _Rejected("invalid-member-id")
    prior = tally.lookup(member.member_id)
    for item in tally.coverage:
        if type(item) is MemberOccurrence and _same(tally, item.member.member_id, member.member_id):
            raise _Rejected("duplicate-member-id")
    if prior is not None:
        if (not _equal(tally, prior.scope, tally.before.scope) or not _equal(tally, prior.role, role)
                or not _same(tally, prior.association, association) or not _same(tally, prior.member, member)):
            raise _Rejected("member-binding-conflict")
        occurrence = prior
    else:
        if role == "trace":
            if type(member) in (Complete, Partial) and len(member.data) and tally.capacity.get("physical_records", 0) == 0:
                raise _Rejected("accounting-count-limit")
            tally.count("members")
        retained = len(member.data) if type(member) in (Complete, Partial) else 0
        if retained > (16777216 if role == "trace" else 8388608):
            raise _Rejected("accounting-member-limit")
        tally.retain(retained, role)
        prefix = Unknown("withheld-prefix", ()) if type(member) is Withheld else (0, 0)
        occurrence = MemberOccurrence(tally.before.scope, role, member, association, prefix)
    if role == "trace":
        tally.encounter("members")
    tally.coverage.append(occurrence)
    return occurrence


def _record_prefix(tally: _Tally, occurrence: MemberOccurrence, prefix: tuple[int, int]) -> None:
    if type(occurrence.prefix) is tuple and prefix[0] > occurrence.prefix[0]:
        position = next(index for index, value in enumerate(tally.coverage) if value is occurrence)
        tally.coverage[position] = replace(occurrence, prefix=prefix)


def _verify_member(tally: _Tally, member: CapturedMember) -> bool:
    if type(member) is Withheld:
        return False
    tally.metadata(member)
    if (not _regex(tally, r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", member.name)
            or any(part in (".", "..") for part in _split(tally, member.name, "/"))):
        raise _Rejected("invalid-raw-member-association")
    length = member.byte_length if type(member) is Complete else member.prefix_length
    digest = member.sha256 if type(member) is Complete else member.prefix_sha256
    if type(member.data) is not bytes or length != len(member.data):
        raise _Rejected("raw-length-mismatch")
    actual = _hash(tally, member.data)
    if not _equal(tally, actual, digest):
        raise _Rejected("raw-sha256-mismatch")
    return type(member) is Complete


def _capture_reasons(packet: StagePacket, reasons: list[Reason]) -> None:
    if packet.end.trigger != "returned":
        reasons.append(Reason("local-member-cap" if packet.end.trigger == "cap" else packet.end.trigger, None, ()))
    if type(packet.end.wait) is WaitMissing:
        reasons.append(Reason("tracer-incomplete", None, ()))
    if not packet.end.cleanup.tracer_reaped or not packet.end.cleanup.owned_group_empty:
        reasons.append(Reason("cleanup-incomplete", None, ()))
    if type(packet.tracer_diagnostics) is Unknown:
        reasons.append(Reason("shared-stderr-attribution-unknown", None, ()))
    elif packet.tracer_diagnostics is not packet.stderr or type(packet.stderr) is not Complete or packet.stderr.data:
        reasons.append(Reason("tracer-incomplete", None, ()))


def _interpret(packet, events, reasons, tally):
    family = _Family(packet, events, reasons, tally)
    family.reconcile()
    cwd = _CwdFacts(packet.launch.cwd, family, tally)
    tasks: list[Task] = []
    images: list[Image] = []
    attempts: list[ExecAttempt] = []
    paths: list[PathUse] = []

    for key, lineage in family.lineages.items():
        birth_refs = lineage.birth.raw_refs if lineage.birth else ()
        terminal = family.terminals.get(key)
        terminal_fact: Established[Exited] | Unknown
        if terminal is None:
            terminal_fact = Unknown("missing-task-terminal", birth_refs)
            reasons.append(Reason(terminal_fact.reason, key, birth_refs))
        else:
            terminal_fact = Established(terminal.call.value, "direct-operation", terminal.raw_refs)
        tasks.append(Task(
            key, lineage.parent_image, "clone" if lineage.birth else "launch",
            lineage.birth.call.flags if lineage.birth else None, birth_refs,
            Established(key.tid, "causal-inheritance" if lineage.birth else "owned-launch", birth_refs),
            terminal_fact,
        ))
        for event in events.get(key, ()):
            call = event.call
            image = family.previous_images[event]
            if isinstance(call, _Exec):
                working = cwd.at(lineage.epoch, event)
                _require(working, key, reasons)
                result = ExecFailed(call.errno) if call.errno else ExecSucceeded(family.next_images[event])
                attempts.append(ExecAttempt(
                    key, image, call.executable, call.argv, call.environment, working, result, event.raw_refs,
                ))
            elif isinstance(call, (_Open, _Chdir)):
                resolution = cwd.path(lineage.epoch, event)
                _require(resolution, key, reasons)
                paths.append(PathUse(
                    key, image, "openat" if isinstance(call, _Open) else "chdir", call.path,
                    call.dirfd if isinstance(call, _Open) else None,
                    call.annotation if isinstance(call, _Open) else None,
                    resolution, call.result, call.errno, event.raw_refs,
                ))

    for key, binary in family.binaries.items():
        source = family.image_sources[key]
        lineage = family.lineages[key.task]
        working = cwd.at(lineage.epoch, source) if source else Established(packet.launch.cwd, "owned-launch", ())
        _require(working, key.task, reasons)
        images.append(Image(key, binary, working))
    _reconcile_launch(packet, attempts, family.terminals, reasons, tally)
    return tuple(tasks), tuple(images), tuple(attempts), tuple(paths)


@dataclass(frozen=True, slots=True)
class _Exec:
    executable: bytes
    argv: tuple[bytes, ...]
    environment: tuple[tuple[bytes, bytes], ...]
    errno: str | None


@dataclass(frozen=True, slots=True)
class _Open:
    dirfd: bytes
    directory: bytes | None
    path: bytes
    annotation: bytes | None
    result: int
    errno: str | None


@dataclass(frozen=True, slots=True)
class _Chdir:
    path: bytes
    result: int
    errno: str | None


@dataclass(frozen=True, slots=True)
class _Clone:
    tid: int
    flags: bytes


@dataclass(frozen=True, slots=True)
class _Wait:
    tid: int
    code: int


@dataclass(frozen=True, slots=True)
class _Unshare:
    result: int


@dataclass(frozen=True, slots=True)
class _ExitRequest:
    code: int


@dataclass(frozen=True, slots=True)
class _Terminal:
    value: Exited | Killed


@dataclass(frozen=True, slots=True)
class _Point:
    task: TaskKey
    position: int


@dataclass(frozen=True, slots=True, eq=False)
class _Event:
    task: TaskKey
    call: _Exec | _Open | _Chdir | _Clone | _Wait | _Unshare | _ExitRequest | _Terminal
    raw_refs: tuple[RawRef, ...]

    @property
    def start(self) -> _Point:
        return _Point(self.task, self.raw_refs[0].physical_line * 2 - 1)

    @property
    def end(self) -> _Point:
        return _Point(self.task, self.raw_refs[-1].physical_line * 2)


class _Rejected(ValueError):
    def __init__(self, code: str, raw_refs: tuple[RawRef, ...] = ()) -> None:
        super().__init__(code)
        self.code = code
        self.raw_refs = raw_refs


def _absolute(tally: _Tally, path: bytes) -> bool:
    return bool(path) and _slice(tally, path, 0, 1) == b"/" and not _contains(tally, b"\0", path)


def _validate_launch(packet: StagePacket, tally: _Tally, reasons: list[Reason]) -> None:
    launch = packet.launch
    prefix = (
        b"/usr/bin/strace", b"-ff", b"-v", b"-s", b"131072", b"-yy", b"-ttt", b"-e",
        b"trace=%process,%file,fchdir,getcwd,close,close_range,dup,dup2,dup3,fcntl,unshare,setsid,setpgid",
        b"-o",
    )
    if (
        launch.task.stage != packet.stage or launch.task.tid <= 0 or launch.task.birth_generation != 0
        or not launch.argv or len(launch.argv) > 256
        or len(launch.environment) > 64
        or any(_contains(tally, b"\0", arg) for arg in launch.argv)
        or any(not key or _contains(tally, b"=", key) or _contains(tally, b"\0", key) or _contains(tally, b"\0", value) for key, value in launch.environment)
        or len(dict(launch.environment)) != len(launch.environment)
        or not _absolute(tally, launch.cwd)
        or not _same(tally, launch.tracer_argv[:10], prefix)
        or len(launch.tracer_argv) != 11 + len(launch.argv)
        or not _absolute(tally, launch.tracer_argv[10])
        or not _same(tally, launch.tracer_argv[11:], launch.argv)
        or not _same(tally, launch.tracer_environment, launch.environment)
        or launch.tracer_pid <= 0 or launch.session_id != launch.tracer_pid
        or launch.stdin != "DEVNULL" or launch.close_fds is not True or launch.pass_fds != ()
    ):
        reasons.append(Reason("invalid-launch-receipt", launch.task, ()))
    binaries: dict[bytes, BinaryIdentity] = {}
    for binary in (launch.binary,) + packet.binary_identities:
        if (
            not _absolute(tally, binary.spelling) or not _absolute(tally, binary.realpath)
            or binary.byte_length < 0 or not _regex(tally, r"[0-9a-f]{64}", binary.sha256)
            or binary.spelling in binaries and binaries[binary.spelling] != binary
        ):
            reasons.append(Reason("invalid-binary-identity", None, ()))
        binaries[binary.spelling] = binary


def _fields(data: bytes, tally: _Tally) -> tuple[bytes, ...]:
    if not data:
        return ()
    result = []
    stack = []
    quote = escaped = annotation = False
    start = index = 0
    pairs = {40: 41, 91: 93, 123: 125}
    while index < len(data):
        tally.pay(1)
        char = data[index]
        if quote:
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                quote = False
        else:
            if _slice(tally, data, index, index + 3) == b"..." or _slice(tally, data, index, index + 2) == b"/*":
                raise _Rejected("abbreviated-record")
            if annotation:
                if char == 62:
                    annotation = False
                elif char == 60:
                    raise _Rejected("unsupported-fd-annotation")
            elif char == 34:
                quote = True
            elif char == 60:
                annotation = True
            elif char in pairs:
                stack.append(pairs[char])
            elif char in (41, 93, 125):
                if not stack or stack.pop() != char:
                    raise _Rejected("malformed-record")
            elif char == 44 and not stack:
                result.append(_strip(tally, _slice(tally, data, start, index)))
                start = index + 1
        index += 1
    if quote or stack or annotation:
        raise _Rejected("malformed-record")
    result.append(_strip(tally, _slice(tally, data, start, len(data))))
    if any(not field for field in result):
        raise _Rejected("malformed-record")
    tally.pay(8 * len(result))
    return tuple(result)


def _string(data: bytes, tally: _Tally) -> bytes:
    if len(data) < 2 or _slice(tally, data, 0, 1) != b'"' or _slice(tally, data, len(data) - 1, len(data)) != b'"':
        raise _Rejected("incomplete-string")
    decoded = bytearray()
    index = 1
    escapes = {97: 7, 98: 8, 116: 9, 110: 10, 118: 11, 102: 12, 114: 13,
               92: 92, 34: 34, 39: 39, 63: 63}
    while index < len(data) - 1:
        tally.pay(1)
        char = data[index]
        index += 1
        if char == 92:
            if index >= len(data) - 1:
                raise _Rejected("incomplete-string")
            tally.pay(1)
            char = data[index]
            index += 1
            if char in escapes:
                char = escapes[char]
            elif 48 <= char <= 55:
                number = char - 48
                count = 1
                while count < 3 and index < len(data) - 1:
                    tally.pay(1)
                    following = data[index]
                    if not 48 <= following <= 55:
                        break
                    number = number * 8 + following - 48
                    index += 1
                    count += 1
                char = number
                if char > 255:
                    raise _Rejected("malformed-string-escape")
            elif char == 120:
                digits = _slice(tally, data, index, index + 2)
                if not _regex(tally, rb"[0-9a-fA-F]{2}", digits):
                    raise _Rejected("malformed-string-escape")
                tally.pay(len(digits))
                char = int(digits, 16)
                index += 2
            else:
                raise _Rejected("malformed-string-escape")
        elif char == 34 or char < 32 or char == 127:
            raise _Rejected("malformed-string")
        if len(decoded) >= 131072 or char == 0:
            raise _Rejected("invalid-string-boundary")
        tally.pay(1)
        decoded.append(char)
    tally.pay(len(decoded))
    return bytes(decoded)


def _strings(data: bytes, limit: int, tally: _Tally) -> tuple[bytes, ...]:
    if _slice(tally, data, 0, 1) != b"[" or _slice(tally, data, len(data) - 1, len(data)) != b"]":
        raise _Rejected("incomplete-exec-vector")
    values = _fields(_slice(tally, data, 1, len(data) - 1), tally)
    if len(values) > limit:
        raise _Rejected("exec-vector-limit")
    return tuple(_string(value, tally) for value in values)


def _result(data: bytes, tally: _Tally) -> tuple[int, bytes | None, str | None]:
    match = _regex(tally, rb"(-?[0-9]{1,10})(?:<([^<>\x00\n]+)>)?(?: ([A-Z][A-Z0-9_]*) \([^\n]*\))?", data)
    if match is None:
        raise _Rejected("unsupported-result")
    tally.pay(len(data))
    number, annotation, errno = match.groups()
    if annotation is not None and (_contains(tally, b"...", annotation) or _contains(tally, b"/*", annotation)):
        raise _Rejected("abbreviated-record")
    tally.pay(len(number))
    value = int(number)
    if (value == -1) != (errno is not None) or not -1 <= value <= 2147483647 or errno and annotation:
        raise _Rejected("unsupported-result")
    if errno:
        tally.pay(len(errno))
    return value, annotation, errno.decode("ascii") if errno else None


def _code(data: bytes, tally: _Tally) -> int:
    if not _regex(tally, rb"[0-9]{1,3}", data):
        raise _Rejected("unsupported-exit-status")
    tally.pay(len(data))
    value = int(data)
    if value > 255:
        raise _Rejected("unsupported-exit-status")
    return value


def _marker(data: bytes, tally: _Tally):
    terminal = _regex(tally, rb"\+\+\+ exited with ([0-9]+) \+\+\+", data)
    if terminal:
        tally.pay(len(data))
        return Exited(_code(terminal[1], tally))
    if _equal(tally, data, b"+++ killed by SIGTERM +++"):
        return Killed("SIGTERM")
    return None


def _decode_call(data: bytes, tally: _Tally):
    match = _regex(tally, rb"([a-z][a-z0-9_]*)\((.*)\) = (.+)", data)
    if match is None:
        raise _Rejected("unsupported-record")
    tally.pay(len(data))
    name, arguments, returned = match.groups()
    values = _fields(arguments, tally)
    if _equal(tally, name, b"exit_group") and len(values) == 1 and _equal(tally, returned, b"?"):
        return _ExitRequest(_code(values[0], tally))
    result, annotation, errno = _result(returned, tally)
    if _equal(tally, name, b"execve") and len(values) == 3 and result in (-1, 0) and annotation is None:
        executable = _string(values[0], tally)
        argv = _strings(values[1], 256, tally)
        environment = []
        raw_environment = _strings(values[2], 64, tally)
        for entry in raw_environment:
            tally.pay(len(entry))
            key, separator, value = entry.partition(b"=")
            if not key or not separator or any(_equal(tally, key, prior) for prior, _ in environment):
                raise _Rejected("invalid-exec-environment")
            environment.append((key, value))
        if not argv or sum(map(len, argv + raw_environment)) > 262144:
            raise _Rejected("exec-vector-limit")
        return _Exec(executable, argv, tuple(environment), errno)
    if _equal(tally, name, b"openat") and len(values) == 3:
        directory = _regex(tally, rb"(AT_FDCWD|[0-9]+)(?:<([^<>\x00\n]+)>)?", values[0])
        if directory is None or not _equal(tally, values[2], b"O_RDONLY"):
            raise _Rejected("unsupported-openat")
        tally.pay(len(values[0]))
        return _Open(values[0], directory[2], _string(values[1], tally), annotation, result, errno)
    if _equal(tally, name, b"chdir") and len(values) == 1 and result in (-1, 0) and annotation is None:
        path = _string(values[0], tally)
        if not _absolute(tally, path):
            raise _Rejected("unsupported-relative-chdir")
        return _Chdir(path, result, errno)
    if _equal(tally, name, b"clone") and len(values) == 2 and result > 0 and annotation is None:
        if not _equal(tally, values[0], b"child_stack=NULL") or _slice(tally, values[1], 0, 6) != b"flags=":
            raise _Rejected("unsupported-clone")
        flags = _slice(tally, values[1], 6, len(values[1]))
        tokens = _split(tally, flags, b"|")
        tally.pay(sum(map(len, tokens)))
        if b"SIGCHLD" not in tokens or len(set(tokens)) != len(tokens) or set(tokens) - {b"SIGCHLD", b"CLONE_FS"}:
            raise _Rejected("unmodeled-state-transition")
        return _Clone(result, flags)
    if _equal(tally, name, b"wait4") and len(values) == 4 and result > 0 and annotation is None:
        status = _regex(tally, rb"\[\{WIFEXITED\(s\) && WEXITSTATUS\(s\) == ([0-9]+)\}\]", values[1])
        tally.pay(10)
        returned_tid = str(result).encode("ascii")
        if not _equal(tally, values[0], returned_tid) or not _same(tally, values[2:], (b"0", b"NULL")) or status is None:
            raise _Rejected("unsupported-wait")
        tally.pay(len(values[1]))
        return _Wait(result, _code(status[1], tally))
    if _equal(tally, name, b"unshare") and _same(tally, values, (b"CLONE_FS",)) and result in (-1, 0) and annotation is None:
        return _Unshare(result)
    raise _Rejected("unsupported-syscall")


def _lines(member, tally, prior):
    data = member.data
    offset = 0
    line_number = 0
    known = prior.prefix[0] if type(prior.prefix) is tuple else 0
    while offset < len(data):
        line_number += 1
        if line_number > known:
            tally.count("records")
        tally.encounter("records")
        cursor = offset
        end = -1
        while end < 0 and cursor < len(data):
            stop = min(cursor + 128, len(data), offset + 1048577)
            if stop <= cursor:
                raise _Rejected("raw-record-limit")
            tally.pay(stop - cursor)
            end = data.find(b"\n", cursor, stop)
            cursor = stop
        stop = end + 1 if end >= 0 else len(data)
        if stop - offset > 1048576:
            raise _Rejected("raw-record-limit")
        line = _slice(tally, data, offset, stop)
        ref = RawRef(member.member_id, offset, stop, line_number)
        offset = stop
        yield line, ref


def _decode_member(member, task, tally, occurrence):
    events = []
    errors = []
    markers = []
    pending = None
    prefix = (0, 0)
    for line, ref in _lines(member, tally, occurrence):
        prefix = (ref.physical_line, ref.byte_stop)
        _record_prefix(tally, occurrence, prefix)
        occurrence = next(value for value in tally.coverage
                          if type(value) is MemberOccurrence and value.member is occurrence.member)
        refs = (ref,)
        matched = _regex(tally, rb"[0-9]+\.[0-9]{6} ([^\n]*)\n", line)
        if matched is None:
            errors.append(Reason("incomplete-physical-record", task, refs))
            break
        tally.pay(len(line))
        data = matched[1]
        marker = _marker(data, tally)
        if marker is not None:
            markers.append(TerminalMarker(marker, refs))
            if pending is not None:
                errors.append(Reason("unsupported-pending-interruption", task, refs))
            events.append(_Event(task, _Terminal(marker), refs))
            continue
        try:
            if _slice(tally, data, max(0, len(data) - 17), len(data)) == b" <unfinished ...>":
                tally.pay(len(data))
                name = re.match(rb"([a-z][a-z0-9_]*)\(", data)
                if pending is not None or name is None:
                    raise _Rejected("unmatched-unfinished-call")
                tally.pay(len(data))
                pending = (name[1], _slice(tally, data, 0, len(data) - 17), ref)
                continue
            resumed = _regex(tally, rb"<\.\.\. ([a-z][a-z0-9_]*) resumed>(.*)", data)
            if resumed:
                tally.pay(len(data))
                if pending is None or not _equal(tally, resumed[1], pending[0]):
                    raise _Rejected("unmatched-resumed-call")
                refs = (pending[2], ref)
                tally.pay(len(pending[1]) + len(resumed[2]))
                data = pending[1] + resumed[2]
                if sum(item.byte_stop - item.byte_start for item in refs) > 1048576:
                    raise _Rejected("raw-record-limit")
                pending = None
            elif pending is not None:
                raise _Rejected("unsupported-pending-interruption")
            if events and isinstance(events[-1].call, _Terminal):
                raise _Rejected("record-after-terminal")
            events.append(_Event(task, _decode_call(data, tally), refs))
        except _Rejected as error:
            if error.code.startswith("accounting"):
                raise
            errors.append(Reason(error.code, task, refs))
            if error.code not in ("unsupported-syscall", "unsupported-record", "unsupported-openat", "unsupported-result"):
                break
    if pending:
        errors.append(Reason("unfinished-call-at-eof", task, (pending[2],)))
    return tuple(events), errors, markers, prefix


def _refs(*groups: tuple[RawRef, ...]) -> tuple[RawRef, ...]:
    return tuple(dict.fromkeys(ref for group in groups for ref in group))


@dataclass(frozen=True, slots=True)
class _Edge:
    before: _Point
    after: _Point
    raw_refs: tuple[RawRef, ...]


class _Causality:
    def __init__(self) -> None:
        self.incoming: dict[TaskKey, list[_Edge]] = {}

    def add(self, before: _Point, after: _Point, raw_refs: tuple[RawRef, ...]) -> None:
        self.incoming.setdefault(after.task, []).append(_Edge(before, after, raw_refs))

    def chain(self, before: _Point, after: _Point) -> tuple[RawRef, ...] | None:
        pending = deque([(after, ())])
        visited: dict[TaskKey, int] = {}
        while pending:
            point, proof = pending.popleft()
            if point.task == before.task and before.position <= point.position:
                return proof
            if visited.get(point.task, -1) >= point.position:
                continue
            visited[point.task] = point.position
            for edge in self.incoming.get(point.task, ()):
                if edge.after.position <= point.position:
                    pending.append((edge.before, _refs(edge.raw_refs, proof)))
        return None


@dataclass(frozen=True, slots=True)
class _Lineage:
    parent_image: ImageKey | None
    birth: _Event | None
    epoch: SharingEpoch


class _Family:
    def __init__(
        self, packet: StagePacket, events: dict[TaskKey, tuple[_Event, ...]], reasons: list[Reason], tally: _Tally,
    ) -> None:
        self.packet = packet
        self.tally = tally
        self.events = events
        self.reasons = reasons
        self.graph = _Causality()
        self.lineages: dict[TaskKey, _Lineage] = {}
        self.copies: dict[SharingEpoch, tuple[SharingEpoch, _Event]] = {}
        self.previous_images: dict[_Event, ImageKey] = {}
        self.next_images: dict[_Event, ImageKey] = {}
        self.binaries: dict[ImageKey, Established[BinaryIdentity] | Unknown] = {}
        self.image_sources: dict[ImageKey, _Event | None] = {}
        self.terminals: dict[TaskKey, _Event] = {}
        self.waited: dict[TaskKey, _Event] = {}

    def reconcile(self) -> None:
        root = self.packet.launch.task
        self.tally.metadata(tuple(event.raw_refs for group in self.events.values() for event in group))
        epoch = SharingEpoch("cwd", root, 0)
        self.lineages[root] = _Lineage(None, None, epoch)
        initial = ImageKey(root, 0)
        self.binaries[initial] = Unknown("unobserved-initial-image", ())
        self.image_sources[initial] = None
        identities = {item.spelling: item for item in (self.packet.launch.binary,) + self.packet.binary_identities}
        pending = deque([root])
        while pending:
            key = pending.popleft()
            lineage = self.lineages[key]
            current = ImageKey(key, 0)
            if key not in self.events:
                refs = lineage.birth.raw_refs if lineage.birth else ()
                self.reasons.append(Reason("missing-task-trace", key, refs))
            exit_request: _Event | None = None
            for event in self.events.get(key, ()):
                call = event.call
                self.previous_images[event] = current
                if exit_request and not isinstance(call, _Terminal):
                    self.reasons.append(Reason("record-after-exit-request", key, _refs(exit_request.raw_refs, event.raw_refs)))
                if isinstance(call, _Exec) and call.errno is None:
                    current = ImageKey(key, current.generation + 1)
                    self.next_images[event] = current
                    binary = identities.get(call.executable)
                    self.binaries[current] = (
                        Established(binary, "stable-identity", event.raw_refs)
                        if binary else Unknown("unbound-binary-identity", event.raw_refs)
                    )
                    self.image_sources[current] = event
                    _require(self.binaries[current], key, self.reasons)
                elif isinstance(call, _Clone):
                    child = TaskKey(key.stage, call.tid, 0)
                    _admit_task(self.tally, child, event.raw_refs)
                    if child in self.lineages or len(self.lineages) >= 512:
                        self.reasons.append(Reason("ambiguous-task-creation", key, event.raw_refs))
                        continue
                    child_epoch = lineage.epoch
                    if b"CLONE_FS" not in _split(self.tally, call.flags, b"|"):
                        child_epoch = SharingEpoch("cwd", child, 0)
                        self.copies[child_epoch] = (lineage.epoch, event)
                    self.lineages[child] = _Lineage(current, event, child_epoch)
                    inherited = self.binaries[current]
                    child_image = ImageKey(child, 0)
                    self.binaries[child_image] = (
                        Established(inherited.value, "causal-inheritance", _refs(inherited.raw_refs, event.raw_refs))
                        if isinstance(inherited, Established) else inherited
                    )
                    self.image_sources[child_image] = event
                    self.graph.add(event.end, _Point(child, 0), event.raw_refs)
                    pending.append(child)
                elif isinstance(call, _ExitRequest):
                    exit_request = event
                elif isinstance(call, _Terminal):
                    self.terminals[key] = event
                    if exit_request and (not isinstance(call.value, Exited) or exit_request.call.code != call.value.code):
                        self.reasons.append(Reason("exit-terminal-mismatch", key, _refs(exit_request.raw_refs, event.raw_refs)))

        for key, events in self.events.items():
            if key not in self.lineages:
                self.reasons.append(Reason("orphan-task-trace", key, _refs(*(event.raw_refs for event in events))))
                continue
            for event in events:
                if isinstance(event.call, _Wait):
                    self._correlate_wait(event)

    def _correlate_wait(self, event: _Event) -> None:
        child = TaskKey(event.task.stage, event.call.tid, 0)
        lineage = self.lineages.get(child)
        if (
            lineage is None or lineage.birth is None or lineage.parent_image is None
            or lineage.parent_image.task != event.task
            or lineage.birth.end.position >= event.start.position
        ):
            self.reasons.append(Reason("unmatched-wait", event.task, event.raw_refs))
            return
        terminal = self.terminals.get(child)
        if terminal is None:
            return
        if (not isinstance(terminal.call.value, Exited) or event.call.code != terminal.call.value.code):
            self.reasons.append(Reason("wait-terminal-mismatch", child, _refs(terminal.raw_refs, event.raw_refs)))
            return
        if child in self.waited:
            self.reasons.append(Reason("duplicate-terminal-wait", child, _refs(self.waited[child].raw_refs, event.raw_refs)))
            return
        self.waited[child] = event
        self.graph.add(terminal.end, event.end, _refs(terminal.raw_refs, event.raw_refs))

    def birth_refs(self, task: TaskKey) -> tuple[RawRef, ...]:
        refs: tuple[RawRef, ...] = ()
        lineage = self.lineages[task]
        while lineage.birth and lineage.parent_image:
            refs = _refs(lineage.birth.raw_refs, refs)
            lineage = self.lineages[lineage.parent_image.task]
        return refs


@dataclass(frozen=True, slots=True)
class _Mutation:
    event: _Event
    path: bytes | None


class _CwdFacts:
    def __init__(self, initial: bytes, family: _Family, tally: _Tally) -> None:
        self.initial = initial
        self.tally = tally
        self.family = family
        self.mutations: dict[SharingEpoch, list[_Mutation]] = {}
        for key, lineage in family.lineages.items():
            for event in family.events.get(key, ()):
                call = event.call
                if isinstance(call, _Chdir) and call.result == 0:
                    self.mutations.setdefault(lineage.epoch, []).append(_Mutation(event, call.path))
                elif (
                    isinstance(call, _Unshare) and call.result == 0
                    or isinstance(call, _Exec) and call.errno is None and self._shared_at(event)
                ):
                    self.mutations.setdefault(lineage.epoch, []).append(_Mutation(event, None))
                    family.reasons.append(Reason("unmodeled-state-transition", key, event.raw_refs))

    def _shared_at(self, event: _Event) -> bool:
        epoch = self.family.lineages[event.task].epoch
        graph = self.family.graph
        for key, lineage in self.family.lineages.items():
            if key == event.task or lineage.epoch != epoch:
                continue
            if lineage.birth and graph.chain(event.end, lineage.birth.start) is not None:
                continue
            terminal = self.family.terminals.get(key)
            if terminal and graph.chain(terminal.end, event.start) is not None:
                continue
            return True
        return False

    def at(self, epoch: SharingEpoch, use: _Event) -> Established[bytes] | Unknown:
        copies: list[tuple[SharingEpoch, _Event]] = []
        while True:
            prior: list[_Mutation] = []
            unordered: list[_Mutation] = []
            for mutation in self.mutations.get(epoch, ()):
                if mutation.event == use:
                    continue
                if self.family.graph.chain(mutation.event.end, use.start) is not None:
                    prior.append(mutation)
                elif self.family.graph.chain(use.end, mutation.event.start) is None:
                    unordered.append(mutation)
            transitions = [mutation for mutation in prior + unordered if mutation.path is None]
            if transitions or unordered:
                affected = transitions if transitions else unordered
                refs = _refs(*(mutation.event.raw_refs for mutation in affected), use.raw_refs)
                code = "unmodeled-state-transition" if transitions else "unresolved-shared-state-order"
                fact: Established[bytes] | Unknown = Unknown(code, refs)
                break
            if prior:
                latest = prior[0]
                for mutation in prior[1:]:
                    if self.family.graph.chain(latest.event.end, mutation.event.start) is not None:
                        latest = mutation
                if any(
                    mutation != latest and self.family.graph.chain(mutation.event.end, latest.event.start) is None
                    for mutation in prior
                ):
                    fact = Unknown("unresolved-shared-state-order", _refs(*(item.event.raw_refs for item in prior), use.raw_refs))
                    break
                proof = self.family.graph.chain(latest.event.end, use.start)
                refs = _refs(self.family.birth_refs(latest.event.task), latest.event.raw_refs, proof or (), use.raw_refs)
                interval = DependencyInterval(epoch, latest.event.raw_refs[-1], use.raw_refs[0], refs)
                fact = Established(latest.path, "causal-inheritance", refs, (interval,))
                break
            if epoch in self.family.copies:
                copies.append((epoch, use))
                epoch, use = self.family.copies[epoch]
                continue
            refs = _refs(self.family.birth_refs(use.task), use.raw_refs)
            interval = DependencyInterval(epoch, None, use.raw_refs[0], refs)
            fact = Established(self.initial, "causal-inheritance", refs, (interval,))
            break

        for copied_epoch, copied_use in reversed(copies):
            birth = self.family.copies[copied_epoch][1]
            refs = _refs(fact.raw_refs, birth.raw_refs, copied_use.raw_refs)
            if isinstance(fact, Unknown):
                fact = Unknown(fact.reason, refs)
            else:
                interval = DependencyInterval(copied_epoch, birth.raw_refs[-1], copied_use.raw_refs[0], refs)
                fact = Established(fact.value, "causal-inheritance", refs, fact.dependencies + (interval,))
        return fact

    def path(self, epoch: SharingEpoch, event: _Event) -> Established[bytes] | Unknown:
        call = event.call
        if isinstance(call, _Open) and call.annotation is not None:
            return self._direct(call.annotation, event)
        if _absolute(self.tally, call.path):
            return Established(call.path, "direct-operation", event.raw_refs)
        if not call.path or b".." in _split(self.tally, call.path, b"/"):
            return Unknown("unresolved-path", event.raw_refs)
        if isinstance(call, _Open) and call.directory is not None:
            directory = self._direct(call.directory, event)
            if isinstance(directory, Unknown):
                return directory
            self.tally.pay(2 * len(directory.value) + len(call.path) + 1)
            return Established(directory.value.rstrip(b"/") + b"/" + call.path, "direct-operation", event.raw_refs)
        if isinstance(call, _Open) and not _equal(self.tally, call.dirfd, b"AT_FDCWD"):
            return Unknown("unknown-directory-fd", event.raw_refs)
        working = self.at(epoch, event)
        if isinstance(working, Unknown):
            return working
        self.tally.pay(2 * len(working.value) + len(call.path) + 1)
        return Established(
            working.value.rstrip(b"/") + b"/" + call.path,
            "causal-inheritance", working.raw_refs, working.dependencies,
        )

    def _direct(self, path: bytes, event: _Event) -> Established[bytes] | Unknown:
        if not _absolute(self.tally, path) or _slice(self.tally, path, max(0, len(path) - 10), len(path)) == b" (deleted)":
            return Unknown("unresolved-path-annotation", event.raw_refs)
        return Established(path, "direct-operation", event.raw_refs)


def _require(fact: Established[T] | Unknown, task: TaskKey, reasons: list[Reason]) -> None:
    if isinstance(fact, Unknown):
        reasons.append(Reason(fact.reason, task, fact.raw_refs))


def _reconcile_launch(packet, attempts, terminals, reasons, tally):
    launch = packet.launch
    first = next((attempt for attempt in attempts if attempt.task == launch.task and isinstance(attempt.result, ExecSucceeded)), None)
    if first is None:
        reasons.append(Reason("missing-launch-exec", launch.task, ()))
    elif (not _equal(tally, first.executable, launch.binary.spelling)
          or not _same(tally, first.argv, launch.argv) or not _same(tally, first.environment, launch.environment)
          or isinstance(first.cwd, Established) and not _equal(tally, first.cwd.value, launch.cwd)):
        reasons.append(Reason("launch-exec-mismatch", launch.task, first.raw_refs))
    terminal = terminals.get(launch.task)
    if terminal is not None:
        value = terminal.call.value
        wait = packet.end.wait
        agrees = (type(value) is Exited and type(wait) is WaitExited and value.code == wait.code
                  or type(value) is Killed and type(wait) is WaitSignaled and _equal(tally, value.signal, wait.signal))
        if not agrees:
            reasons.append(Reason("tracer-wait-mismatch", launch.task, terminal.raw_refs))
