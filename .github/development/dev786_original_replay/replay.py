from __future__ import annotations

import hashlib
import json
import os
import re
import resource
import signal
import stat
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path

ob = _observation


@dataclass(frozen=True, slots=True)
class _Initial:
    session_id: str
    book: ob.Book
    measured: ob.Usage
    conservative: ob.Usage
    initialization: ob.InitializationReceipt


@dataclass(frozen=True, slots=True)
class _Pending:
    before: ob.Checkpoint
    scope: str
    allowance: ob.Usage
    kind: str


@dataclass(frozen=True, slots=True)
class _State:
    checkpoint: ob.Checkpoint
    book: ob.Book
    initialization: ob.InitializationReceipt
    pending: _Pending | None
    closure: str
    stopped: ob.Reason | None


@dataclass(frozen=True, slots=True)
class _IdentityResult:
    identity: CaptureIdentity
    operation: ob.OperationReceipt


def _empty_book():
    return ob.Book((), (), (), (), (), (None, None), ob.Unknown("original-not-run"),
                   ob.Unknown("replay-not-finished"), ob.Unknown("retrieval-not-run"), ob.Incomplete(()))


def _bounded_usage(value):
    coordinates = ob._coordinates(value)
    limits = {"traversal_bytes": ob.READ_LIMIT, "physical_records": ob.RECORD_LIMIT,
              "export_files": ob.FILE_LIMIT, "four_row_members": ob.ROW_LIMIT, "four_row_tasks": ob.ROW_LIMIT}
    limits.update({("retained", name): cap for name, cap in ob.RETAINED_LIMITS})
    for scope, _, _ in value.scope_counts:
        limits[("members", scope)] = ob.SCOPE_LIMIT
        limits[("tasks", scope)] = ob.SCOPE_LIMIT
    if any(count > limits.get(key, 0) for key, count in coordinates.items()):
        raise ValueError("usage-cap")
    return coordinates


def _counts(occurrences):
    values = {}
    for item in occurrences:
        if type(item) is ob.MemberOccurrence:
            if item.role != "trace":
                continue
            key = ("members", item.scope)
            records = item.prefix[0] if type(item.prefix) is tuple else 0
            values["physical_records"] = values.get("physical_records", 0) + records
            scope, kind = item.scope, "four_row_members"
        elif type(item) is ob.TaskOccurrence:
            key = ("tasks", item.key.stage)
            scope, kind = item.key.stage, "four_row_tasks"
        else:
            raise ValueError("invalid-occurrence")
        values[key] = values.get(key, 0) + 1
        if scope in ob._ROWS:
            values[kind] = values.get(kind, 0) + 1
    return ob._usage(values)


def _count_only(usage):
    return replace(usage, traversal_bytes=0, retained=(), export_files=0)


def _prefix(tally, item, prior):
    if type(item.member) is ob.Withheld:
        if type(item.prefix) is not ob.Unknown:
            raise ValueError("withheld-prefix")
        return
    if type(item.member) not in (ob.Complete, ob.Partial) or item.role not in ("trace", "stdout", "stderr"):
        raise ValueError("member-occurrence-shape")
    if (type(item.prefix) is not tuple or len(item.prefix) != 2
            or any(type(number) is not int or number < 0 for number in item.prefix)):
        raise ValueError("member-prefix-shape")
    lines, stop = item.prefix
    data = item.member.data
    if stop > len(data) or item.role != "trace" and (lines, stop) != (0, 0):
        raise ValueError("member-prefix-bound")
    old_lines, start = (0, 0) if prior is None else prior.prefix
    if lines < old_lines or stop < start:
        raise ValueError("member-prefix-regression")
    if stop == start:
        if lines != old_lines:
            raise ValueError("member-prefix-count")
        return
    tally.pay(stop - start)
    actual = data.count(b"\n", start, stop)
    tally.pay(1)
    final = data[stop - 1]
    if final != 10:
        if stop != len(data):
            raise ValueError("member-prefix-boundary")
        actual += 1
    if lines - old_lines != actual:
        raise ValueError("member-prefix-count")


class _Budget:
    def __init__(self, initial: _Initial) -> None:
        if (type(initial) is not _Initial or type(initial.session_id) is not str
                or not 0 < len(initial.session_id) <= 128 or type(initial.book) is not ob.Book):
            raise ValueError("invalid-initial-state")
        book = initial.book
        if any(type(value) is not tuple for value in (book.stages, book.identities, book.products,
                                                      book.operations, book.occurrences, book.terminal_operations)):
            raise ValueError("invalid-history-shape")
        if (len(book.operations) > 64 or len(book.occurrences) > 32768 or len(book.stages) > 64
                or book.terminal_operations != (None, None) or book.identities or book.products):
            raise ValueError("invalid-initial-history")
        _bounded_usage(ob._plus(initial.measured, initial.conservative, ob._closure_usage()))
        adopted = self._initialization(initial.initialization)
        prior = ob._plus(initial.measured, initial.conservative, adopted.measured_usage, adopted.conservative_debit)
        _bounded_usage(ob._plus(prior, ob._closure_usage()))
        checkpoint = ob.Checkpoint(initial.session_id, len(book.operations), prior,
            ob._plus(initial.measured, adopted.measured_usage), ob._plus(initial.conservative, adopted.conservative_debit),
            ob._closure_usage(), book, "preparation", ob.Usage())
        history_cost = self._history_cost(book)
        if history_cost > ob.READ_LIMIT - prior.traversal_bytes - ob.CLOSURE_BYTES:
            raise ValueError("history-validation-cap")
        if book.operations or book.occurrences or book.stages:
            tally = ob._Tally(checkpoint, ob.Usage(traversal_bytes=history_cost))
            try:
                self._history(initial, tally)
            except ob._Rejected as error:
                raise ValueError(error.code) from None
            actual_history = ob.Usage(traversal_bytes=tally.used.get("traversal_bytes", 0))
            checkpoint = replace(checkpoint,
                measured=ob._plus(checkpoint.measured, actual_history),
                committed=ob._plus(checkpoint.committed, actual_history))
        elif ob._coordinates(initial.measured) or ob._coordinates(initial.conservative):
            raise ValueError("unwitnessed-history")
        prepared = _State(checkpoint, book, adopted, None, "held", None)
        self._state = prepared

    @property
    def _snapshot(self):
        return self._state

    @staticmethod
    def _initialization(receipt):
        if type(receipt) is not ob.InitializationReceipt or type(receipt.bounded_reads) is not tuple or len(receipt.bounded_reads) > 64:
            raise ValueError("invalid-initialization")
        if type(receipt.helper_identities) is not tuple or len(receipt.helper_identities) != 2:
            raise ValueError("invalid-initialization-identities")
        _bounded_usage(receipt.prepaid_envelope)
        reserve = receipt.adoption_reserved
        if reserve.traversal_bytes <= 0:
            raise ValueError("initialization-adoption-missing")
        ob._minus(receipt.prepaid_envelope, ob._plus(receipt.measured_usage, receipt.conservative_debit, reserve))
        before = ob.Checkpoint("initialization", 0, ob.Usage(), ob.Usage(), ob.Usage(), ob._closure_usage(),
                               _empty_book(), "preparation", reserve)
        tally = ob._Tally(before)
        try:
            if not ob._same(tally, receipt, _loaded_initialization):
                raise ValueError("initialization-identity")
            tally.metadata(receipt)
            tally.pay(80)
            tally.pay(8 * len(receipt.bounded_reads))
            cost = tally.used.get("traversal_bytes", 0)
            debits = []
            for item in receipt.bounded_reads:
                if item.operation == "adoption-compare":
                    if cost > item.requested_bytes:
                        raise ValueError("initialization-adoption-plan")
                    debits.append(replace(item, delivered_bytes=cost))
                else:
                    debits.append(item)
        except ob._Rejected as error:
            raise ValueError(error.code) from None
        return replace(receipt, bounded_reads=tuple(debits), measured_usage=ob._plus(
            receipt.measured_usage, ob.Usage(traversal_bytes=cost)), adoption_reserved=ob.Usage())

    @staticmethod
    def _history_cost(book):
        occurrences = book.occurrences
        cost = 8 * (len(book.operations) + len(occurrences) + len(book.stages))
        cost += sum(ob._width(item) for item in book.operations)
        cost += 2 * sum(ob._width(item) for item in occurrences)
        cost += sum(ob._width(item) for item in book.stages)
        member_lookup = 8 * len(occurrences) + sum(
            8 + len(item.member.member_id.value) for item in occurrences if type(item) is ob.MemberOccurrence)
        member_count = sum(type(item) is ob.MemberOccurrence for item in occurrences)
        for item in occurrences:
            if type(item) is ob.MemberOccurrence:
                cost += ob._width(item.member.member_id)
                if type(item.member) in (ob.Complete, ob.Partial):
                    cost += len(item.member.data) + 128
                    if type(item.prefix) is tuple and len(item.prefix) == 2:
                        cost += max(0, item.prefix[1]) + 1
            elif type(item) is ob.TaskOccurrence:
                cost += ob._width(item.key)
                if type(item.witness) is ob.Launch:
                    cost += 2 * ob._width(item.key) + 16
                elif type(item.witness) is tuple:
                    for ref in item.witness:
                        if type(ref) is not ob.RawRef:
                            raise ValueError("history-birth-witness")
                        cost += member_lookup + member_count * len(ref.member.value)
                        cost += max(0, ref.byte_start) + 8 * max(0, ref.byte_stop - ref.byte_start) + 512
        for receipt in book.operations:
            cost += sum(ob._width(item) + 8 + 16 * len(occurrences) for item in receipt.coverage)
            cost += 8 * (len(receipt.before.basis.operations) + len(receipt.before.basis.occurrences))
        cost += 8 * len(book.stages) * len(book.operations)
        return cost

    @staticmethod
    def _historical_birth(item, book, tally):
        refs = item.witness
        if not 1 <= len(refs) <= 2:
            raise ValueError("history-birth-witness")
        records = []
        parent = None
        for ref in refs:
            if type(ref) is not ob.RawRef or ref.byte_start < 0 or ref.byte_stop <= ref.byte_start:
                raise ValueError("history-birth-witness")
            member = None
            for entry in book.occurrences:
                tally.pay(8)
                if type(entry) is ob.MemberOccurrence and ob._same(tally, entry.member.member_id, ref.member):
                    member = entry
                    break
            if (member is None or member.role != "trace" or type(member.prefix) is not tuple
                    or type(member.member) is not ob.Complete or type(member.association) is not ob.TaskKey
                    or member.scope != item.key.stage or ref.byte_stop > member.prefix[1]):
                raise ValueError("history-birth-witness")
            tally.metadata(member.association)
            tally.metadata(item.key)
            if parent is not None and not ob._same(tally, member.association, parent):
                raise ValueError("history-birth-parent")
            parent = member.association
            data = member.member.data
            if ref.byte_start:
                tally.pay(1)
                if data[ref.byte_start - 1] != 10:
                    raise ValueError("history-birth-boundary")
            tally.pay(ref.byte_start)
            if data.count(b"\n", 0, ref.byte_start) + 1 != ref.physical_line:
                raise ValueError("history-birth-line")
            record = ob._slice(tally, data, ref.byte_start, ref.byte_stop)
            match = ob._regex(tally, rb"[0-9]+\.[0-9]{6} ([^\n]*)\n", record)
            if match is None:
                raise ValueError("history-birth-record")
            tally.pay(len(record))
            records.append(match[1])
        if len(records) == 1:
            data = records[0]
        else:
            first, last = records
            suffix = b" <unfinished ...>"
            tally.pay(len(first) + len(last))
            if not first.endswith(suffix) or not last.startswith(b"<... clone resumed>"):
                raise ValueError("history-birth-pair")
            leading = ob._slice(tally, first, 0, len(first) - len(suffix))
            trailing = ob._slice(tally, last, 19, len(last))
            tally.pay(len(leading) + len(trailing))
            data = leading + trailing
        match = ob._regex(tally, rb"clone\(child_stack=NULL, flags=(?:SIGCHLD|CLONE_FS\|SIGCHLD|SIGCHLD\|CLONE_FS)\) = ([1-9][0-9]{0,9})", data)
        if match is None:
            raise ValueError("history-birth-call")
        tally.pay(len(data))
        tid = match[1]
        tally.pay(len(tid))
        if int(tid) != item.key.tid or item.key.birth_generation != 0 or parent == item.key:
            raise ValueError("history-birth-task")

    @staticmethod
    def _history(initial, tally):
        book = initial.book
        tally.pay(8 * (len(book.operations) + len(book.occurrences) + len(book.stages)))
        measured = ob.Usage()
        conservative = ob.Usage()
        accepted = []
        keys = set()
        for item in book.occurrences:
            tally.metadata(item)
            if type(item) is ob.MemberOccurrence:
                raw = item.member
                if type(raw) not in (ob.Complete, ob.Partial, ob.Withheld):
                    raise ValueError("invalid-history-member")
                key = ("member", raw.member_id.value)
                if item.role not in ("trace", "stdout", "stderr") or type(item.scope) is not str:
                    raise ValueError("invalid-history-role")
                if type(item.association) is ob.TaskKey and item.association.stage != item.scope:
                    raise ValueError("invalid-history-association")
                if type(raw) is ob.Withheld:
                    if type(item.prefix) is not ob.Unknown:
                        raise ValueError("withheld-prefix")
                else:
                    expected_length = raw.byte_length if type(raw) is ob.Complete else raw.prefix_length
                    expected_digest = raw.sha256 if type(raw) is ob.Complete else raw.prefix_sha256
                    if len(raw.data) != expected_length or not ob._equal(tally, ob._hash(tally, raw.data), expected_digest):
                        raise ValueError("history-member-identity")
                    if (type(item.prefix) is not tuple or len(item.prefix) != 2
                            or any(type(value) is not int or value < 0 for value in item.prefix)):
                        raise ValueError("history-prefix")
                    lines, stop = item.prefix
                    data = raw.data
                    if stop > len(data) or item.role != "trace" and (lines, stop) != (0, 0):
                        raise ValueError("history-prefix")
                    tally.pay(stop)
                    actual = data.count(b"\n", 0, stop)
                    if stop:
                        tally.pay(1)
                        last = data[stop - 1]
                        if last != 10:
                            if stop != len(data):
                                raise ValueError("history-prefix-boundary")
                            actual += 1
                    if lines != actual:
                        raise ValueError("history-prefix")
            elif type(item) is ob.TaskOccurrence:
                key = ("task", item.key)
                if type(item.witness) is ob.Launch:
                    if not ob._same(tally, item.witness.task, item.key):
                        raise ValueError("history-task-witness")
                elif type(item.witness) is tuple and item.witness:
                    _Budget._historical_birth(item, book, tally)
                else:
                    raise ValueError("history-task-witness")
            else:
                raise ValueError("history-occurrence-type")
            tally.metadata(item.member.member_id if type(item) is ob.MemberOccurrence else item.key)
            if key in keys:
                raise ValueError("duplicate-history-key")
            keys.add(key)
        for index, receipt in enumerate(book.operations):
            tally.metadata(receipt)
            if (type(receipt) is not ob.OperationReceipt or receipt.before.session_id != initial.session_id
                    or receipt.before.operation_sequence != index or receipt.refusals
                    or ob._coordinates(receipt.before.measured) != ob._coordinates(measured)
                    or ob._coordinates(receipt.before.conservative) != ob._coordinates(conservative)
                    or ob._coordinates(receipt.before.committed) != ob._coordinates(ob._plus(measured, conservative))
                    or ob._coordinates(receipt.before.closure_reserved) != ob._coordinates(ob._closure_usage())
                    or ob._coordinates(receipt.before.allowance) != ob._coordinates(ob._allowance(receipt.before.scope, receipt.before))):
                raise ValueError("invalid-history-operation")
            if ob._coordinates(ob._plus(receipt.measured_delta, receipt.conservative_delta, receipt.unused_allowance)) != ob._coordinates(receipt.before.allowance):
                raise ValueError("history-partition")
            if ob._coordinates(receipt.newly_charged) != ob._coordinates(_count_only(receipt.measured_delta)):
                raise ValueError("history-count-delta")
            measured = ob._plus(measured, receipt.measured_delta)
            conservative = ob._plus(conservative, receipt.conservative_delta)
            tally.pay(8 * (len(receipt.before.basis.operations) + len(receipt.before.basis.occurrences)))
            if (len(receipt.before.basis.operations) != index
                    or any(left is not right for left, right in zip(receipt.before.basis.operations, book.operations))
                    or len(receipt.before.basis.occurrences) != len(accepted)
                    or any(left is not right for left, right in zip(receipt.before.basis.occurrences, accepted))):
                raise ValueError("history-before-binding")
            for item in receipt.coverage:
                tally.pay(ob._width(item) + 8)
                found = False
                for canonical in book.occurrences:
                    tally.pay(8)
                    if item is canonical:
                        found = True
                        break
                if not found:
                    raise ValueError("history-coverage-binding")
                for prior in accepted:
                    tally.pay(8)
                    if prior is item:
                        raise ValueError("duplicate-history-coverage")
                accepted.append(item)
        tally.pay(sum(ob._width(item) for item in book.occurrences))
        if (len(accepted) != len(book.occurrences)
                or ob._coordinates(measured) != ob._coordinates(initial.measured)
                or ob._coordinates(conservative) != ob._coordinates(initial.conservative)
                or ob._coordinates(_counts(book.occurrences)) != ob._coordinates(_count_only(measured))):
            raise ValueError("history-sum")
        for stage in book.stages:
            tally.metadata(stage)
            tally.pay(8 * len(book.operations))
            if not any(stage.operation is receipt for receipt in book.operations):
                raise ValueError("history-stage-receipt")

    def _adopt_initialization(self, receipt):
        prepared = replace(self._state, stopped=ob.Reason("initialization-reused", None, ()))
        self._state = prepared
        raise ValueError("initialization-reused")

    @contextmanager
    def _operation(self, scope):
        with self._guard(scope, "optional") as checkpoint:
            yield checkpoint

    @contextmanager
    def _closure(self):
        with self._guard("closure", "closure") as checkpoint:
            yield checkpoint

    @contextmanager
    def _guard(self, scope, kind):
        before = self._state
        if before.pending is not None:
            self._lose(before.pending, "nested-operation")
            raise ValueError("nested-operation")
        if kind == "optional" and before.stopped is not None or kind == "closure" and before.closure != "held":
            raise ValueError("operation-stopped")
        if type(scope) is not str or not 0 < len(scope) <= 128:
            raise ValueError("invalid-scope")
        grant = ob._allowance(scope, before.checkpoint) if kind == "optional" else before.checkpoint.closure_reserved
        checkpoint = replace(before.checkpoint, basis=before.book, scope=scope, allowance=grant)
        pending = _Pending(checkpoint, scope, grant, kind)
        try:
            prepared = replace(before, checkpoint=checkpoint, pending=pending,
                               closure="pending" if kind == "closure" else before.closure)
            self._state = prepared
            yield checkpoint
        except BaseException:
            if self._state.pending is pending:
                self._lose(pending, "interrupted-operation")
            elif self._state.stopped is None:
                prepared = replace(self._state, stopped=ob.Reason("interrupted-after-commit", None, ()))
                self._state = prepared
            raise
        finally:
            if self._state.pending is pending:
                self._lose(pending, "missing-receipt")

    def _lose(self, pending, code):
        current = self._state
        if current.pending is not pending:
            return
        reason = ob.Reason(code, None, ())
        receipt = ob.OperationReceipt(pending.before, ob.Usage(), pending.allowance, ob.Usage(),
                                      (reason,), ob.Usage(), ob.Usage(), ())
        optional, closure = current.book.terminal_operations
        slots = (receipt, closure) if pending.kind == "optional" else (optional, receipt)
        book = replace(current.book, terminal_operations=slots, assessment=ob.Incomplete((reason,)))
        conservative = ob._plus(current.checkpoint.conservative, pending.allowance)
        checkpoint = replace(current.checkpoint, operation_sequence=current.checkpoint.operation_sequence + 1,
            conservative=conservative, committed=ob._plus(current.checkpoint.measured, conservative),
            closure_reserved=ob.Usage() if pending.kind == "closure" else current.checkpoint.closure_reserved,
            basis=book, allowance=ob.Usage())
        prepared = _State(checkpoint, book, current.initialization, None,
                          "spent" if pending.kind == "closure" else current.closure, reason)
        self._state = prepared

    def _receive(self, returned):
        current = self._state
        pending = current.pending
        if pending is None:
            prepared = replace(current, stopped=ob.Reason("duplicate-receipt", None, ()))
            self._state = prepared
            raise ValueError("duplicate-receipt")
        try:
            receipt = returned.operation if type(returned) in (ob.Observation, _IdentityResult) else returned
            if type(receipt) is not ob.OperationReceipt or receipt.before is not pending.before:
                raise ValueError("receipt-before")
            if receipt.before.basis is not current.book or receipt.before.allowance is not pending.allowance:
                raise ValueError("receipt-authority")
            for value in (receipt.measured_delta, receipt.conservative_delta, receipt.unused_allowance,
                          receipt.encountered, receipt.newly_charged):
                _bounded_usage(value)
            partition = ob._plus(receipt.measured_delta, receipt.conservative_delta, receipt.unused_allowance)
            if ob._coordinates(partition) != ob._coordinates(pending.allowance):
                raise ValueError("receipt-partition")
            if type(receipt.coverage) is not tuple or len(receipt.coverage) > 32768:
                raise ValueError("receipt-coverage")
            if (ob._coordinates(receipt.encountered) != ob._coordinates(_count_only(receipt.encountered))
                    or ob._coordinates(receipt.newly_charged) != ob._coordinates(_count_only(receipt.measured_delta))):
                raise ValueError("receipt-count-shape")
            if any(reason.code in ("member-binding-conflict", "task-binding-conflict") for reason in receipt.refusals):
                raise ValueError("receipt-binding-conflict")
            tally = ob._Tally(receipt.before, receipt.unused_allowance)
            tally.metadata(receipt)
            new_metadata = ob._width(receipt) + 8 * (len(current.book.operations) + len(current.book.occurrences) + len(current.book.stages) + 3)
            tally.retain(new_metadata)
            tally.pay(8 * (len(current.book.operations) + len(current.book.occurrences) + len(current.book.stages) + 3))
            occurrences = list(current.book.occurrences)
            identities = current.book.identities
            inspected = type(returned) is ob.Observation
            if inspected or type(returned) is ob.OperationReceipt and pending.kind != "closure":
                if inspected:
                    if returned.stage != pending.scope:
                        raise ValueError("receipt-scope")
                    tally.metadata(returned)
                member_ids = []
                covered_tasks = []
                for item in receipt.coverage:
                    tally.metadata(item)
                    if type(item) is ob.MemberOccurrence:
                        if not ob._equal(tally, item.scope, pending.scope):
                            raise ValueError("receipt-member-scope")
                        if (type(item.member) not in (ob.Complete, ob.Partial, ob.Withheld)
                                or type(item.member.member_id) is not ob.MemberId
                                or item.role not in ("trace", "stdout", "stderr")):
                            raise ValueError("receipt-member-shape")
                        if (type(item.association) not in (ob.TaskKey, ob.Unknown)
                                or type(item.association) is ob.TaskKey
                                and not ob._equal(tally, item.association.stage, item.scope)):
                            raise ValueError("receipt-member-association")
                        if type(item.association) is ob.TaskKey and (
                                type(item.association.tid) is not int or item.association.tid <= 0
                                or type(item.association.birth_generation) is not int or item.association.birth_generation < 0):
                            raise ValueError("receipt-member-association")
                        if inspected:
                            tally.pay(8 * len(returned.members))
                            if not any(item.member is raw for raw in returned.members):
                                raise ValueError("receipt-member-binding")
                        if any(ob._same(tally, value, item.member.member_id) for value in member_ids):
                            raise ValueError("duplicate-member-coverage")
                        member_ids.append(item.member.member_id)
                        tally.pay(8 * len(occurrences))
                        index = next((i for i, prior in enumerate(occurrences) if type(prior) is ob.MemberOccurrence
                                      and ob._same(tally, prior.member.member_id, item.member.member_id)), None)
                        if index is not None:
                            prior = occurrences[index]
                            if (not ob._same(tally, prior.member, item.member) or not ob._equal(tally, prior.scope, item.scope)
                                    or not ob._equal(tally, prior.role, item.role) or not ob._same(tally, prior.association, item.association)):
                                raise ValueError("receipt-member-binding")
                        if not inspected:
                            if type(item.prefix) is tuple and item.prefix != (0, 0):
                                raise ValueError("capture-unparsed-prefix")
                            if type(item.member) in (ob.Complete, ob.Partial):
                                ob._verify_member(tally, item.member)
                        _prefix(tally, item, occurrences[index] if index is not None else None)
                    elif type(item) is ob.TaskOccurrence:
                        if type(item.key) is not ob.TaskKey or not ob._equal(tally, item.key.stage, pending.scope):
                            raise ValueError("receipt-task-scope")
                        if (type(item.key.tid) is not int or item.key.tid <= 0
                                or type(item.key.birth_generation) is not int or item.key.birth_generation < 0):
                            raise ValueError("receipt-task-identity")
                        if any(ob._same(tally, value, item.key) for value in covered_tasks):
                            raise ValueError("duplicate-task-coverage")
                        covered_tasks.append(item.key)
                        if type(item.witness) is ob.Launch:
                            if (not ob._same(tally, item.witness.task, item.key)
                                    or inspected and item.witness is not returned.launch):
                                raise ValueError("receipt-task-binding")
                        elif not inspected or not any(
                                ob._same(tally, task.key, item.key) and ob._same(tally, task.birth_refs, item.witness)
                                for task in returned.tasks):
                            raise ValueError("receipt-task-binding")
                        tally.pay(8 * len(occurrences))
                        index = next((i for i, prior in enumerate(occurrences) if type(prior) is ob.TaskOccurrence
                                      and ob._same(tally, prior.key, item.key)), None)
                        if index is not None and not ob._same(tally, occurrences[index].witness, item.witness):
                            raise ValueError("receipt-task-binding")
                    else:
                        raise ValueError("receipt-coverage-type")
                    if index is None:
                        occurrences.append(item)
                    else:
                        occurrences[index] = item
                if inspected and not receipt.refusals and len(member_ids) != len(returned.members):
                    raise ValueError("receipt-coverage-missing")
                tally.pay(sum(ob._width(item) for item in occurrences) + sum(ob._width(item) for item in current.book.occurrences))
                if ob._coordinates(ob._minus(_counts(tuple(occurrences)), _counts(current.book.occurrences))) != ob._coordinates(receipt.newly_charged):
                    raise ValueError("receipt-counts")
            elif type(returned) is _IdentityResult:
                if pending.scope != "preparation" or receipt.coverage or ob._coordinates(receipt.newly_charged):
                    raise ValueError("identity-receipt-scope")
                identity = returned.identity
                if (type(identity) is not CaptureIdentity or type(identity.byte_length) is not int
                        or identity.byte_length < 0 or not ob._regex(tally, r"[0-9a-f]{64}", identity.sha256)):
                    raise ValueError("identity-receipt-shape")
                tally.metadata(identity)
                tally.pay(8 * (len(identities) + 1))
                identities += (identity,)
            elif pending.kind == "closure":
                if receipt.coverage or ob._coordinates(receipt.newly_charged):
                    raise ValueError("receipt-closure-coverage")
            paid = ob._usage(tally.used)
            finalized = replace(receipt, measured_delta=ob._plus(receipt.measured_delta, paid),
                                unused_allowance=ob._minus(receipt.unused_allowance, paid))
            stages = current.book.stages
            if type(returned) is ob.Observation:
                stages += (replace(returned, operation=finalized),)
            stopped = current.stopped
            if receipt.refusals:
                stopped = receipt.refusals[0]
            book = replace(current.book, stages=stages, identities=identities, operations=current.book.operations + (finalized,),
                           occurrences=tuple(occurrences) if receipt.coverage else current.book.occurrences,
                           assessment=ob.Incomplete((stopped,) if stopped else ()))
            measured = ob._plus(current.checkpoint.measured, finalized.measured_delta)
            conservative = ob._plus(current.checkpoint.conservative, finalized.conservative_delta)
            checkpoint = replace(current.checkpoint, operation_sequence=current.checkpoint.operation_sequence + 1,
                measured=measured, conservative=conservative, committed=ob._plus(measured, conservative),
                closure_reserved=ob.Usage() if pending.kind == "closure" else current.checkpoint.closure_reserved,
                basis=book, allowance=ob.Usage())
            prepared = _State(checkpoint, book, current.initialization, None,
                              "spent" if pending.kind == "closure" else current.closure, stopped)
            self._state = prepared
        except (ValueError, TypeError, AttributeError, ob._Rejected) as error:
            self._lose(pending, "untrusted-receipt")
            raise ValueError("untrusted-receipt") from error


@dataclass(frozen=True, slots=True)
class OwnedRoots:
    root: Path


@dataclass(frozen=True, slots=True)
class ControlCase:
    name: str
    scope_ids: tuple[str, ...]
    qualified: bool


@dataclass(frozen=True, slots=True)
class ClockCase:
    name: str
    gap_start: float
    gap_end: float
    owner_end_before: float
    owner_end_after: float
    collection_started_before_gap: float | None
    original_manifest: dict


@dataclass(frozen=True, slots=True)
class ControlQualification:
    book: ob.Book
    cases: tuple[ControlCase, ...]
    progression_allowed: bool
    clock_cases: tuple[ClockCase, ...]


@dataclass(frozen=True, slots=True)
class CaptureIdentity:
    role: str
    path: str
    byte_length: int
    sha256: str
    applied_limits: tuple = ()


_TRACE = ("/usr/bin/strace", "-ff", "-v", "-s", "131072", "-yy", "-ttt", "-e",
          "trace=%process,%file,fchdir,getcwd,close,close_range,dup,dup2,dup3,fcntl,unshare,setsid,setpgid", "-o")
_CONTENT = b"dev786-harmless-sensitive-content-786"
_NAME = b"dev786-harmless-sensitive-name-786"
_CONTROLS = (
    ("exit-seven", b"exit 7\n"),
    ("sigterm", b'kill -TERM "$$"\n'),
    ("prefix-4096", b'printf "%08192d" 0\n'),
    ("trace-members-two", b"(exit 0) &\n(exit 0) &\nwait\n"),
    ("withhold-content", b"printf '" + _CONTENT + b"'\n"),
    ("withhold-name", b"printf 'safe control output'\n"),
    ("unsupported-syntax", b"exit 0\n"),
    ("collector-exception", b"while :; do :; done\n"),
    ("owned-timeout", b"while :; do :; done\n"),
    ("successive-captures-1", b"exit 0\n"),
    ("successive-captures-2", b"exit 0\n"),
    ("reread-refusal", b"printf 'reread-control\\n'\n"),
)


def _resource_limits():
    values = []
    for name, resource_id, cap in (("cpu_seconds", resource.RLIMIT_CPU, 240),
            ("address_bytes", resource.RLIMIT_AS, 2147483648),
            ("file_bytes", resource.RLIMIT_FSIZE, 268435456),
            ("processes", resource.RLIMIT_NPROC, 128), ("core_bytes", resource.RLIMIT_CORE, 0)):
        soft, hard = resource.getrlimit(resource_id)
        applied = min(cap, hard) if hard != resource.RLIM_INFINITY else cap
        if soft != resource.RLIM_INFINITY:
            applied = min(applied, soft)
        values.append((name, resource_id, applied, hard))
    return tuple(values)


def _apply_resource_limits():
    for _, resource_id, soft, hard in _resource_limits():
        resource.setrlimit(resource_id, (soft, hard))


def _group_exists(pid):
    try:
        os.killpg(pid, 0)
        return True
    except ProcessLookupError:
        return False


def _cleanup(process, abnormal):
    group = process.pid
    if abnormal and process.poll() is None:
        if os.getpgid(process.pid) != group:
            return ob.Cleanup(False, False)
        os.killpg(group, signal.SIGTERM)
    until = time.monotonic() + 5
    while process.poll() is None and time.monotonic() < until:
        time.sleep(0.01)
    if process.poll() is None and os.getpgid(process.pid) == group and _group_exists(group):
        os.killpg(group, signal.SIGKILL)
    until = time.monotonic() + 5
    while process.poll() is None and time.monotonic() < until:
        time.sleep(0.01)
    reaped = False
    try:
        process.wait(timeout=5)
        reaped = True
    except subprocess.TimeoutExpired:
        pass
    return ob.Cleanup(reaped, not _group_exists(group))


def _read(tally, path, maximum):
    tally.pay(64)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("capture-file-kind")
    request = min(before.st_size, maximum) + 1
    tally.admit(request)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        tally.pay(128)
        opened = os.fstat(stream.fileno())
        raw = stream.read(request)
        tally.pay(len(raw))
        after = os.fstat(stream.fileno())
    tally.pay(128)
    current = path.lstat()
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    stable = identity(before) == identity(opened) == identity(after) == identity(current)
    return raw, before.st_size, stable


def _directory(tally, directory):
    entries = []
    with os.scandir(directory) as iterator:
        while True:
            tally.admit(255)
            entry = next(iterator, None)
            if entry is None:
                break
            tally.pay(len(entry.name))
            if len(entries) == 520:
                raise ValueError("capture-directory-cap")
            tally.pay(64)
            status = entry.stat(follow_symlinks=False)
            if not stat.S_ISREG(status.st_mode):
                raise ValueError("capture-directory-kind")
            entries.append((directory / entry.name, status.st_size))
    return tuple(entries)


def _sensitive(tally, raw):
    for value in (_CONTENT, _NAME):
        if ob._contains(tally, value, raw):
            return True
    tally.pay(len(raw))
    return re.search(rb"(?i)(?:authorization\s*:\s*bearer |github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9]+|X-Amz-Signature=|(?:token|password|secret|credential|cookie)[=:])", raw) is not None


class Replay:
    @classmethod
    def open(cls, owned_roots, verified_policy, *, initialization):
        if type(owned_roots) is not OwnedRoots:
            raise ValueError("owned-roots-required")
        root = owned_roots.root
        if not root.is_absolute() or not stat.S_ISDIR(root.lstat().st_mode) or any(root.iterdir()):
            raise ValueError("owned-root-not-empty")
        if any(not hasattr(verified_policy, name) for name in ("materialization", "GitHub", "identities")):
            raise ValueError("verified-policy-required")
        run = cls.__new__(cls)
        run._root, run._policy = root, verified_policy
        run._budget = _Budget(_Initial("replay-" + os.urandom(16).hex(), _empty_book(), ob.Usage(), ob.Usage(), initialization))
        run._started = False
        return run

    def harmless_controls(self):
        if self._started:
            raise ValueError("controls-already-run")
        self._started = True
        self._deadline = time.monotonic() + 300
        if sys.platform != "linux" or not Path("/usr/bin/strace").is_file():
            return ControlQualification(self._budget._snapshot.book, (), False, ())
        self._home = self._root / "home"
        self._tmp = self._root / "tmp"
        self._home.mkdir(mode=0o700)
        self._tmp.mkdir(mode=0o700)
        self._environment = {"HOME": str(self._home), "TMPDIR": str(self._tmp), "PATH": "/usr/bin:/bin",
            "LC_ALL": "C.UTF-8", "VIRTUAL_ENV": str(Path(sys.executable).parent.parent),
            "SPECFACT_MODULES_REPO": str(self._root / "synthetic-modules"),
            "SPECFACT_MODULES_ROOTS": str(self._root / "synthetic-modules/packages")}
        self._shell = self._binary("/bin/sh", "control-shell")
        self._binary("/usr/bin/strace", "tracer")
        self._binary(sys.executable, "clock-python")
        clocks = self._clock_cases()
        cases = []
        packets = {}
        for name, body in _CONTROLS:
            if self._budget._snapshot.stopped is not None or time.monotonic() + 15 >= self._deadline:
                break
            packet = self._capture(name, body)
            packets[name] = packet
            observed = self._inspect_control(packet, name)
            qualified = self._qualifies(name, observed)
            if name.startswith("successive-captures-"):
                if name.endswith("2"):
                    cases.append(ControlCase("successive-captures", ("control-successive-captures-1", "control-successive-captures-2"), qualified))
            else:
                cases.append(ControlCase(name, (packet.stage,), qualified))
            if name == "exit-seven":
                for edit in ("missing-terminal-synthetic", "missing-reap-synthetic"):
                    changed = self._synthetic_edit(packet, edit)
                    result = self._inspect_control(changed, edit)
                    code = "missing-task-terminal" if edit == "missing-terminal-synthetic" else "cleanup-incomplete"
                    cases.append(ControlCase(edit, (changed.stage,), any(reason.code == code for reason in result.reasons)))
        book = self._budget._snapshot.book
        with self._budget._closure() as checkpoint:
            tally = ob._Tally(checkpoint)
            tally.metadata(tuple(cases))
            tally.retain(ob._width(tuple(cases)))
            self._budget._receive(tally.receipt())
        book = self._budget._snapshot.book
        return ControlQualification(book, tuple(cases), False, clocks)

    def _binary(self, spelling, role):
        with self._budget._operation("preparation") as checkpoint:
            tally = ob._Tally(checkpoint)
            path = Path(spelling).resolve(strict=True)
            raw, size, stable = _read(tally, path, 16777216)
            if not stable or len(raw) != size:
                raise ValueError("binary-identity-incomplete")
            digest = ob._hash(tally, raw)
            identity = CaptureIdentity(role, str(path), size, digest, _resource_limits())
            tally.metadata(identity)
            tally.retain(ob._width(identity))
            self._budget._receive(_IdentityResult(identity, tally.receipt()))
        return ob.BinaryIdentity(os.fsencode(spelling), os.fsencode(path), size, digest)

    def _capture(self, name, body):
        scope = "control-" + name
        directory = self._root / scope
        directory.mkdir(mode=0o700)
        with self._budget._operation(scope) as checkpoint:
            tally = ob._Tally(checkpoint)
            code = b'printf "%s\\n" "$$" > pid\n' + body
            tally.pay(len(code))
            (directory / "control.sh").write_bytes(code)
            argv = ("/bin/sh", str(directory / "control.sh"))
            trace_argv = _TRACE + (str(directory / "trace"),) + argv
            output_name = os.fsdecode(_NAME) if name == "withhold-name" else "stdout"
            output, error = directory / output_name, directory / "stderr"
            trigger = "returned"
            process = None
            cleanup = ob.Cleanup(True, True)
            wait = ob.WaitMissing("not-launched")
            try:
                with output.open("xb") as stdout, error.open("xb") as stderr:
                    process = subprocess.Popen(trace_argv, cwd=directory, env=self._environment,
                        stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, shell=False,
                        close_fds=True, pass_fds=(), start_new_session=True, preexec_fn=_apply_resource_limits)
                    deadline = min(self._deadline - 15, time.monotonic() + (1 if name == "owned-timeout" else 30))
                    while process.poll() is None:
                        if time.monotonic() >= deadline:
                            trigger = "timeout"
                            break
                        if name == "collector-exception" and (directory / "pid").exists():
                            _read(tally, directory / "missing-fixed-collector-input", 1)
                        entries = _directory(tally, directory)
                        traces = sum(path.name.startswith("trace.") for path, _ in entries)
                        if (any(size > 1048576 for path, size in entries if path.name != "control.sh")
                                or traces > (2 if name == "trace-members-two" else 512)):
                            trigger = "cap"
                            break
                        time.sleep(0.01)
            except OSError:
                trigger = "collector-error" if process is not None else "launch-error"
            except ValueError as error:
                if str(error).startswith("capture-directory-"):
                    trigger = "cap"
                else:
                    raise
            finally:
                if process is not None:
                    cleanup = _cleanup(process, trigger != "returned")
                    if process.returncode is not None:
                        wait = (ob.WaitSignaled(signal.Signals(-process.returncode).name) if process.returncode < 0
                                else ob.WaitExited(process.returncode))
            target = ob.Unknown("launch-failed")
            launch = ob.Unknown("launch-failed")
            if process is not None and (directory / "pid").exists():
                pid_raw, _, stable = _read(tally, directory / "pid", 32)
                tally.pay(len(pid_raw))
                if not stable or not pid_raw.strip().isdigit():
                    raise ValueError("control-pid-identity")
                target = ob.TaskKey(scope, int(pid_raw), 0)
                encoded_argv = tuple(os.fsencode(value) for value in argv)
                environment = tuple((os.fsencode(key), os.fsencode(value)) for key, value in self._environment.items())
                launch = ob.Launch(target, encoded_argv, environment, os.fsencode(directory), self._shell,
                    tuple(os.fsencode(value) for value in trace_argv), environment, process.pid, process.pid,
                    "DEVNULL", True, ())
                ob._admit_task(tally, target, launch)
            trace_paths = []
            for path, _ in _directory(tally, directory):
                tally.pay(len(path.name))
                if path.name.startswith("trace."):
                    if len(trace_paths) >= 512:
                        trigger = "cap"
                        break
                    trace_paths.append(path)
            if name == "trace-members-two" and len(trace_paths) > 2:
                trigger = "cap"
                trace_paths = trace_paths[:2]
            traces = []
            for index, path in enumerate(trace_paths):
                suffix = path.name.removeprefix("trace.")
                tally.pay(len(suffix))
                association = ob.TaskKey(scope, int(suffix), 0) if suffix.isdigit() else ob.Unknown("task-association-unknown")
                member = self._member(tally, path, scope + "-trace-" + str(index), "trace", association, 1048576)
                traces.append(ob.TraceAssociation(member, association))
            stdout = self._member(tally, output, scope + "-stdout", "stdout", ob.Unknown("stream"),
                                  4096 if name == "prefix-4096" else 1048576)
            stderr = self._member(tally, error, scope + "-stderr", "stderr", ob.Unknown("stream"), 1048576)
            diagnostics = stderr if type(stderr) is ob.Complete and not stderr.data else ob.Unknown("shared-stderr-attribution-unknown")
            packet = ob.StagePacket(ob.Origin.ACTUAL_CONTROL, name, scope, launch, tuple(traces), stdout, stderr,
                diagnostics, (self._shell,), ob.CaptureEnd(trigger, wait, cleanup), checkpoint)
            tally.metadata(packet)
            tally.retain(ob._width(packet))
            self._budget._receive(tally.receipt())
        return packet

    @staticmethod
    def _member(tally, path, member_id, role, association, cap):
        if role == "trace":
            tally.count("members")
            tally.encounter("members")
        tally.metadata(member_id)
        tally.pay(64)
        projected = min(path.lstat().st_size, cap)
        key = ("retained", "controls")
        if projected > tally.capacity.get(key, 0) - tally.used.get(key, 0):
            raise ob._Rejected("accounting-limit")
        cap = projected
        raw, size, stable = _read(tally, path, cap)
        tally.pay(len(path.name))
        unsafe_name = _sensitive(tally, os.fsencode(path.name))
        unsafe_content = _sensitive(tally, raw)
        if unsafe_name or unsafe_content:
            member = ob.Withheld(ob.MemberId(member_id), "control", size,
                                  "sensitive-name" if unsafe_name else "sensitive-content")
        else:
            retained = ob._slice(tally, raw, 0, min(cap, len(raw)))
            digest = ob._hash(tally, retained)
            if stable and size == len(retained):
                member = ob.Complete(ob.MemberId(member_id), path.name, retained, size, digest)
            else:
                extent = ob.StableFinalSize(size) if stable else ob.ObservedLowerBound(len(raw))
                member = ob.Partial(ob.MemberId(member_id), path.name, retained, len(retained), digest, extent, "local-cap")
        tally.retain(len(member.data) if type(member) in (ob.Complete, ob.Partial) else 0, role)
        prefix = ob.Unknown("withheld-prefix") if type(member) is ob.Withheld else (0, 0)
        tally.coverage.append(ob.MemberOccurrence(tally.before.scope, role, member, association, prefix))
        return member

    def _inspect_control(self, packet, name):
        with self._budget._operation(packet.stage) as checkpoint:
            result = ob.inspect(replace(packet, accounting=checkpoint))
            if name == "reread-refusal":
                tally = ob._Tally(checkpoint, result.operation.unused_allowance)
                source = self._root / packet.stage / "stdout"
                remaining = 32
                for _ in range(3):
                    tally.pay(64)
                    request = source.lstat().st_size + 1
                    if request > remaining:
                        break
                    raw, _, _ = _read(tally, source, remaining)
                    remaining -= len(raw)
                else:
                    raise ValueError("fixed-reread-control-did-not-refuse")
                reason = ob.Reason("local-reread-cap", None, ())
                tally.metadata(reason)
                delta = ob.Usage(traversal_bytes=tally.used.get("traversal_bytes", 0))
                receipt = replace(result.operation, measured_delta=ob._plus(result.operation.measured_delta, delta),
                    unused_allowance=ob._minus(result.operation.unused_allowance, delta), refusals=(reason,))
                result = replace(result, status="incomplete", reasons=result.reasons + (reason,), operation=receipt)
            self._budget._receive(result)
        return self._budget._snapshot.book.stages[-1]

    def _synthetic_edit(self, actual, edit):
        scope = "control-" + edit
        with self._budget._operation(scope) as checkpoint:
            tally = ob._Tally(checkpoint)
            root = next(item.member for item in actual.trace_members if item.task == actual.launch.task)
            data = root.data
            tally.pay(len(data))
            lines = data.splitlines(keepends=True)
            selected = []
            for line in lines:
                tally.pay(3 * len(line))
                if b" execve(" in line or b" exit_group(" in line or b" +++ exited with " in line:
                    if edit == "missing-terminal-synthetic" and b" +++ exited with " in line:
                        continue
                    selected.append(line)
            tally.pay(sum(map(len, selected)))
            raw = b"".join(selected)
            target = replace(actual.launch.task, stage=scope)
            launch = replace(actual.launch, task=target)
            trace = ob.Complete(ob.MemberId(scope + "-trace"), "trace", raw, len(raw), ob._hash(tally, raw))
            empty_hash = ob._hash(tally, b"")
            stdout = ob.Complete(ob.MemberId(scope + "-stdout"), "stdout", b"", 0, empty_hash)
            stderr = ob.Complete(ob.MemberId(scope + "-stderr"), "stderr", b"", 0, empty_hash)
            end = actual.end
            if edit == "missing-reap-synthetic":
                end = replace(end, cleanup=ob.Cleanup(False, True))
            for role, member, association in (("trace", trace, target), ("stdout", stdout, ob.Unknown("stream")),
                                               ("stderr", stderr, ob.Unknown("stream"))):
                ob._admit_member(tally, member, role, association)
            ob._admit_task(tally, target, launch)
            packet = ob.StagePacket(ob.Origin.SYNTHETIC, edit, scope, launch, (ob.TraceAssociation(trace, target),),
                                    stdout, stderr, stderr, (self._shell,), end, checkpoint)
            self._budget._receive(tally.receipt())
        return packet

    @staticmethod
    def _qualifies(name, result):
        clean = result.end.cleanup.tracer_reaped and result.end.cleanup.owned_group_empty
        if name == "exit-seven":
            return clean and result.end.wait == ob.WaitExited(7)
        if name == "sigterm":
            return clean and any(marker.terminal == ob.Killed("SIGTERM") for marker in result.terminal_markers)
        if name == "prefix-4096":
            return clean and any(type(member) is ob.Partial and member.prefix_length == 4096 for member in result.members)
        if name == "trace-members-two":
            return clean and result.end.trigger == "cap"
        if name in ("withhold-content", "withhold-name"):
            return clean and any(type(member) is ob.Withheld for member in result.members)
        if name in ("collector-exception", "owned-timeout"):
            return clean and result.end.trigger == ("timeout" if name == "owned-timeout" else "collector-error")
        if name == "unsupported-syntax":
            return clean and any(reason.raw_refs for reason in result.reasons)
        return clean

    def _clock_cases(self):
        cases = []
        mat = self._policy.materialization
        for name in ("read-gap-before", "read-gap-after"):
            if time.monotonic() + 61 >= self._deadline:
                raise ValueError("control-window")
            workspace = self._root / name
            workspace.mkdir(mode=0o700)
            evidence = _driver.Evidence(self._root / (name + "-evidence"))
            state = {}
            saved, transport = mat.shutil, self._policy.GitHub._https_get
            source = b"# Synthetic clock fixture source\n"
            with _driver.Timer(1200, mat._private_root.__wrapped__.__code__) as timer:
                with _driver.cleanup_observer(mat, workspace, evidence, timer, state):
                    with mat._private_root(workspace) as root:
                        fixture = root / "fixture.py"
                        with self._budget._operation("preparation") as checkpoint:
                            tally = ob._Tally(checkpoint)
                            tally.pay(len(source))
                            fixture.write_bytes(source)
                            tally.pay(16 + len(source))
                            header = b"blob " + str(len(source)).encode() + b"\0" + source
                            tally.pay(len(header))
                            blob = hashlib.sha1(header).hexdigest()
                            tally.pay(len(source) + len(blob) + 256)
                            tree_record = ("100644 blob " + blob + "\tfixture.py\0").encode()
                            emitter = ('import sys; data=' + repr(source) + '; '
                                'sys.stdout.buffer.write(data if "cat-file" in sys.argv else ' + repr(tree_record) + ')')
                            tally.pay(len(emitter))
                            raw, size, stable = _read(tally, fixture, 65536)
                            identity = CaptureIdentity("Synthetic-clock-fixture", str(fixture), size, ob._hash(tally, raw))
                            if not stable or raw != source:
                                raise ValueError("clock-fixture-identity")
                            tally.metadata(identity)
                            tally.retain(ob._width(identity))
                            self._budget._receive(_IdentityResult(identity, tally.receipt()))
                        commands = mat._Commands(root, mat._environment(root))
                        commands.run([sys.executable, "-I", "-S", "-c", emitter, "-C", str(root), "ls-tree"])
                        commands.run([sys.executable, "-I", "-S", "-c", emitter, "-C", str(root), "cat-file", "blob", blob])
                        if name == "read-gap-after":
                            evidence.capture(root)
                        collection_started = evidence.collection_started
                        owner_end = timer.end
                        gap_start = time.monotonic()
                        time.sleep(61)
                        gap_end = time.monotonic()
                        timer.check()
                        owner_after = timer.end
            restored = mat.shutil is saved and self._policy.GitHub._https_get is transport
            manifest = {"control": name, "origin": "Synthetic", "cleanup": state, "restored": restored}
            evidence.finish(manifest)
            cases.append(ClockCase(name, gap_start, gap_end, owner_end, owner_after, collection_started, manifest))
            workspace.rmdir()
        return tuple(cases)
