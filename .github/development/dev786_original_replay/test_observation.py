"""Synthetic behavior packets for the first pure observer boundary."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
import unittest
from dataclasses import fields, replace
from pathlib import Path


sys.dont_write_bytecode = True
_module_name = f"{__name__}._observation"
if _module_name in sys.modules:
    raise RuntimeError("The test-owned observation module name is already occupied")
_module_spec = importlib.util.spec_from_file_location(
    _module_name, Path(__file__).resolve().with_name("observation.py")
)
if _module_spec is None or _module_spec.loader is None:
    raise RuntimeError("The fixed sibling observation.py must be loadable")
observation = importlib.util.module_from_spec(_module_spec)
sys.modules[_module_name] = observation
try:
    _module_spec.loader.exec_module(observation)
finally:
    if sys.modules.get(_module_name) is observation:
        del sys.modules[_module_name]


STAGE = "synthetic-observer-unit"
PARENT = observation.TaskKey(STAGE, 100, 0)
CHILD = observation.TaskKey(STAGE, 101, 0)
ORPHAN = observation.TaskKey(STAGE, 102, 0)
ENVIRONMENT = (
    (b"HOME", b"/owned/home"),
    (b"TMPDIR", b"/owned/tmp"),
    (b"PATH", b"/owned/bin:/usr/bin:/bin"),
    (b"LC_ALL", b"C.UTF-8"),
    (b"VIRTUAL_ENV", b"/owned/venv"),
    (b"SPECFACT_MODULES_REPO", b"/owned/modules"),
    (b"SPECFACT_MODULES_ROOTS", b"/owned/modules/packages"),
)
RAW_ENVIRONMENT = (
    b'["HOME=/owned/home", "TMPDIR=/owned/tmp", '
    b'"PATH=/owned/bin:/usr/bin:/bin", "LC_ALL=C.UTF-8", '
    b'"VIRTUAL_ENV=/owned/venv", "SPECFACT_MODULES_REPO=/owned/modules", '
    b'"SPECFACT_MODULES_ROOTS=/owned/modules/packages"]'
)
FIRST_ARGV = (b"/owned/bin/first", b"literal,...")
FIRST_IDENTITY_BYTES = b"Synthetic first executable identity, never executed"
SECOND_IDENTITY_BYTES = b"Synthetic second executable identity, never executed"
FIRST_BINARY = observation.BinaryIdentity(
    b"/owned/bin/first",
    b"/owned/libexec/first",
    len(FIRST_IDENTITY_BYTES),
    hashlib.sha256(FIRST_IDENTITY_BYTES).hexdigest(),
)
SECOND_BINARY = observation.BinaryIdentity(
    b"/owned/bin/second",
    b"/owned/libexec/second",
    len(SECOND_IDENTITY_BYTES),
    hashlib.sha256(SECOND_IDENTITY_BYTES).hexdigest(),
)
TRACE_OPTIONS = (
    b"/usr/bin/strace", b"-ff", b"-v", b"-s", b"131072", b"-yy", b"-ttt",
    b"-e",
    b"trace=%process,%file,fchdir,getcwd,close,close_range,dup,dup2,dup3,"
    b"fcntl,unshare,setsid,setpgid",
    b"-o", b"/owned/traces/trace",
)
FIRST_EXEC = (
    b'1700000000.000001 execve("/owned/bin/first", '
    b'["/owned/bin/first", "literal,..."], ' + RAW_ENVIRONMENT + b') = 0\n'
)
FAILED_EXEC = (
    b'1700000000.000002 execve("/missing", ["/missing", "probe"], '
    + RAW_ENVIRONMENT + b') = -1 ENOENT (No such file or directory)\n'
)
SECOND_EXEC = (
    b'1700000000.000005 execve("/owned/bin/second", '
    b'["/owned/bin/second", "exit7"], ' + RAW_ENVIRONMENT + b') = 0\n'
)
DIRECT_OPEN = (
    b'1700000000.000003 openat(AT_FDCWD</owned/work>, "direct", '
    b'O_RDONLY) = 3</owned/work/direct>\n'
)
UNANNOTATED_OPEN = (
    b'1700000000.000004 openat(AT_FDCWD, "unseen", O_RDONLY) '
    b'= -1 ENOENT (No such file or directory)\n'
)
AFTER_WAIT_OPEN = (
    b'1700000000.000012 openat(AT_FDCWD, "missing", O_RDONLY) '
    b'= -1 ENOENT (No such file or directory)\n'
)
AFTER_UNSHARE_DIRECT = (
    b'1700000000.000013 openat(AT_FDCWD</owned/other>, "direct", '
    b'O_RDONLY) = 3</owned/other/direct>\n'
)
CLONE_COPY = b'1700000000.000002 clone(child_stack=NULL, flags=SIGCHLD) = 101\n'
CLONE_SHARED = (
    b'1700000000.000002 clone(child_stack=NULL, flags=CLONE_FS|SIGCHLD) = 101\n'
)
WAIT_CHILD = (
    b'1700000000.000010 wait4(101, [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], '
    b'0, NULL) = 101\n'
)
CHILD_CHDIR = b'1700000000.000003 chdir("/owned/other") = 0\n'
CHILD_EXIT_REQUEST = b'1700000000.000006 exit_group(0) = ?\n'
CHILD_TERMINAL = b'1700000000.000007 +++ exited with 0 +++\n'
EXIT_REQUEST_0 = b'1700000000.000020 exit_group(0) = ?\n'
TERMINAL_0 = b'1700000000.000021 +++ exited with 0 +++\n'
EXIT_REQUEST_7 = b'1700000000.000020 exit_group(7) = ?\n'
TERMINAL_7 = b'1700000000.000021 +++ exited with 7 +++\n'
UNSHARE = b'1700000000.000011 unshare(CLONE_FS) = 0\n'


TRACE_IDS = {"trace.100": "m-parent", "trace.101": "m-child", "trace.102": "m-orphan"}


def require_capture_shape() -> None:
    for name in ("MemberId", "Complete", "TraceAssociation", "CaptureEnd", "WaitExited",
                 "WaitSignaled", "Usage", "Checkpoint", "Book", "Incomplete",
                 "MemberOccurrence", "TaskOccurrence", "OperationReceipt"):
        unittest.TestCase().assertTrue(
            hasattr(observation, name), f"NEW canonical capture data type is missing: {name}"
        )
    unittest.TestCase().assertTrue(callable(getattr(observation, "_allowance", None)),
                                   "NEW shared fixed-limit allowance calculation is missing")
    unittest.TestCase().assertEqual(tuple(field.name for field in fields(observation.Checkpoint)),
        ("session_id", "operation_sequence", "committed", "measured", "conservative", "closure_reserved",
         "basis", "scope", "allowance"), "NEW expanded Checkpoint constructor must match the frozen SPEC")


def empty_book():
    return observation.Book(
        (), (), (), (), (), (None, None), observation.Unknown("original-not-run", ()),
        observation.Unknown("replay-not-finished", ()), observation.Unknown("retrieval-not-run", ()),
        observation.Incomplete(()),
    )


def member_id(name: str):
    return observation.MemberId(TRACE_IDS[name])


def member(task: observation.TaskKey, lines: tuple[bytes, ...]):
    data = b"".join(lines)
    name = f"trace.{task.tid}"
    return observation.TraceAssociation(
        observation.Complete(member_id(name), name, data, len(data), hashlib.sha256(data).hexdigest()),
        task,
    )


def packet(
    label: str,
    parent_lines: tuple[bytes, ...],
    child_lines: tuple[bytes, ...] | None = None,
    returncode: int = 0,
) -> observation.StagePacket:
    require_capture_shape()
    members = (member(PARENT, parent_lines),)
    if child_lines is not None:
        members += (member(CHILD, child_lines),)
    stdout = observation.Complete(observation.MemberId("m-stdout"), "stdout", b"", 0,
                                  hashlib.sha256(b"").hexdigest())
    stderr = observation.Complete(observation.MemberId("m-stderr"), "stderr", b"", 0,
                                  hashlib.sha256(b"").hexdigest())
    closure = observation.Usage(traversal_bytes=1048576,
                                retained=(("preparation-restoration-export", 65536),), export_files=1)
    checkpoint = observation.Checkpoint("synthetic-preservation-session", 0, observation.Usage(),
                                        observation.Usage(), observation.Usage(), closure,
                                        empty_book(), STAGE, observation.Usage())
    checkpoint = replace(checkpoint, allowance=observation._allowance(STAGE, checkpoint))
    return observation.StagePacket(
        origin=observation.Origin.SYNTHETIC,
        origin_label=label,
        stage=STAGE,
        launch=observation.Launch(
            task=PARENT,
            argv=FIRST_ARGV,
            environment=ENVIRONMENT,
            cwd=b"/owned/work",
            binary=FIRST_BINARY,
            tracer_argv=TRACE_OPTIONS + FIRST_ARGV,
            tracer_environment=ENVIRONMENT,
            tracer_pid=900,
            session_id=900,
            stdin="DEVNULL",
            close_fds=True,
            pass_fds=(),
        ),
        trace_members=members,
        stdout=stdout,
        stderr=stderr,
        tracer_diagnostics=stderr,
        binary_identities=(FIRST_BINARY, SECOND_BINARY),
        end=observation.CaptureEnd("returned", observation.WaitExited(returncode),
                                    observation.Cleanup(tracer_reaped=True, owned_group_empty=True)),
        accounting=checkpoint,
    )


class ObservationBehaviorTests(unittest.TestCase):
    def assert_incomplete(self, result: observation.Observation, code: str) -> None:
        self.assertEqual(result.status, "incomplete")
        self.assertEqual(result.origin, observation.Origin.SYNTHETIC)
        self.assertIn(code, {reason.code for reason in result.reasons})

    def assert_reference(
        self,
        ref: observation.RawRef,
        supplied: observation.StagePacket,
        name: str,
        start: int,
        line: int,
        expected: bytes,
    ) -> None:
        self.assertEqual(ref.member, member_id(name))
        self.assertEqual(ref.byte_start, start)
        self.assertEqual(ref.byte_stop, start + len(expected))
        self.assertEqual(ref.physical_line, line)
        raw = next(item.member for item in supplied.trace_members if item.member.member_id == ref.member)
        self.assertEqual(raw.name, name)
        self.assertEqual(raw.data[ref.byte_start:ref.byte_stop], expected)

    def test_complete_exec_binds_identity_arguments_environment_and_raw_bytes(self) -> None:
        lines = (FIRST_EXEC, DIRECT_OPEN, EXIT_REQUEST_0, TERMINAL_0)
        supplied = packet("complete-exec", lines)

        result = observation.inspect(supplied)

        self.assertEqual(result.status, "observed")
        self.assertEqual(result.reasons, ())
        self.assertEqual(result.origin, observation.Origin.SYNTHETIC)
        self.assertEqual(result.origin_label, "complete-exec")
        self.assertEqual(result.stage, STAGE)
        self.assertEqual(result.launch.argv, (b"/owned/bin/first", b"literal,..."))
        self.assertEqual(result.launch.environment, ENVIRONMENT)
        self.assertEqual(result.launch.cwd, b"/owned/work")
        self.assertEqual(result.end.trigger, "returned")
        self.assertIsInstance(result.end.wait, observation.WaitExited)
        self.assertEqual(result.end.wait.code, 0)
        self.assertEqual(result.tracer_diagnostics, supplied.stderr)
        self.assertEqual(result.tracer_diagnostics.data, b"")
        self.assertTrue(result.end.cleanup.tracer_reaped)
        self.assertTrue(result.end.cleanup.owned_group_empty)
        self.assertEqual(len(supplied.trace_members), 1)
        self.assertEqual(len(result.members), 3)
        self.assertEqual({raw.member_id for raw in result.members},
                         {member_id("trace.100"), supplied.stdout.member_id, supplied.stderr.member_id})
        raw = next(item for item in result.members if item.member_id == member_id("trace.100"))
        self.assertEqual(raw, supplied.trace_members[0].member)
        self.assertEqual(raw.data, b"".join(lines))
        self.assertEqual(raw.byte_length, sum(map(len, lines)))
        self.assertEqual(raw.sha256, hashlib.sha256(b"".join(lines)).hexdigest())

        self.assertEqual(len(result.exec_attempts), 1)
        attempt = result.exec_attempts[0]
        self.assertEqual(attempt.task, PARENT)
        self.assertEqual(attempt.executable, b"/owned/bin/first")
        self.assertEqual(attempt.argv, (b"/owned/bin/first", b"literal,..."))
        self.assertEqual(attempt.environment, ENVIRONMENT)
        self.assertEqual(attempt.previous_image.generation, 0)
        self.assertEqual(attempt.result.image.generation, 1)
        self.assertEqual(attempt.cwd.value, b"/owned/work")
        self.assertEqual(len(attempt.raw_refs), 1)
        self.assert_reference(attempt.raw_refs[0], supplied, "trace.100", 0, 1, FIRST_EXEC)
        image = next(item for item in result.images if item.key == attempt.result.image)
        self.assertEqual(image.binary.value.spelling, b"/owned/bin/first")
        self.assertEqual(image.binary.value.realpath, b"/owned/libexec/first")
        self.assertEqual(image.binary.value.byte_length, len(FIRST_IDENTITY_BYTES))
        self.assertEqual(image.binary.value.sha256, hashlib.sha256(FIRST_IDENTITY_BYTES).hexdigest())

        use = next(item for item in result.path_uses if item.raw_path == b"direct")
        self.assertEqual(use.image, attempt.result.image)
        self.assertEqual(use.resolution.value, b"/owned/work/direct")
        self.assertEqual(use.resolution.basis, "direct-operation")
        self.assert_reference(use.raw_refs[0], supplied, "trace.100", len(FIRST_EXEC), 2, DIRECT_OPEN)
        self.assertEqual(len(result.tasks), 1)
        terminal = result.tasks[0].terminal
        self.assertEqual(terminal.value.code, 0)
        self.assert_reference(
            terminal.raw_refs[0], supplied, "trace.100", sum(map(len, lines[:3])), 4, TERMINAL_0
        )

    def test_declared_member_length_and_digest_are_binding(self) -> None:
        supplied = packet("member-binding", (FIRST_EXEC, EXIT_REQUEST_0, TERMINAL_0))
        association = supplied.trace_members[0]
        raw = association.member
        cases = (
            (replace(raw, byte_length=raw.byte_length - 1), "raw-length-mismatch"),
            (replace(raw, sha256="0" * 64), "raw-sha256-mismatch"),
        )
        for changed, code in cases:
            with self.subTest(code=code):
                result = observation.inspect(replace(
                    supplied, trace_members=(replace(association, member=changed),)))
                self.assert_incomplete(result, code)
                self.assertEqual(result.exec_attempts, (), "Unbound bytes cannot establish an exec")
                self.assertEqual(result.path_uses, ())

    def test_launch_and_tracer_wait_do_not_replace_observed_child_facts(self) -> None:
        supplied = packet("independent-receipts", (FIRST_EXEC, EXIT_REQUEST_0, TERMINAL_0))
        cases = (
            (
                replace(
                    supplied,
                    launch=replace(
                        supplied.launch,
                        argv=(b"/owned/bin/first", b"wrong"),
                        tracer_argv=TRACE_OPTIONS + (b"/owned/bin/first", b"wrong"),
                    ),
                ),
                "launch-exec-mismatch",
            ),
            (
                replace(supplied, end=replace(supplied.end, wait=observation.WaitExited(7))),
                "tracer-wait-mismatch",
            ),
        )
        for changed, code in cases:
            with self.subTest(code=code):
                result = observation.inspect(changed)
                self.assert_incomplete(result, code)
                self.assertEqual(result.exec_attempts[0].argv, (b"/owned/bin/first", b"literal,..."))
                self.assertEqual(result.tasks[0].terminal.value.code, 0)
                self.assertIsInstance(result.end.wait, observation.WaitExited)
                self.assertEqual(result.end.wait.code, changed.end.wait.code)

    def test_failed_exec_preserves_old_image_before_success_and_normal_exit_seven(self) -> None:
        lines = (FIRST_EXEC, FAILED_EXEC, DIRECT_OPEN, SECOND_EXEC, EXIT_REQUEST_7, TERMINAL_7)
        supplied = packet("failed-exec-then-seven", lines, returncode=7)

        result = observation.inspect(supplied)

        self.assertEqual(result.status, "observed")
        self.assertEqual(result.reasons, ())
        self.assertEqual(len(result.exec_attempts), 3)
        first, failed, second = result.exec_attempts
        self.assertEqual(failed.executable, b"/missing")
        self.assertEqual(failed.argv, (b"/missing", b"probe"))
        self.assertEqual(failed.environment, ENVIRONMENT)
        self.assertEqual(failed.result.errno, "ENOENT")
        self.assertEqual(failed.previous_image, first.result.image)
        self.assertEqual(second.previous_image, first.result.image)
        self.assertEqual(second.result.image.generation, first.result.image.generation + 1)
        self.assertEqual(second.argv, (b"/owned/bin/second", b"exit7"))
        self.assertEqual(second.environment, ENVIRONMENT)
        self.assert_reference(failed.raw_refs[0], supplied, "trace.100", len(FIRST_EXEC), 2, FAILED_EXEC)
        self.assert_reference(
            second.raw_refs[0], supplied, "trace.100", sum(map(len, lines[:3])), 4, SECOND_EXEC
        )
        self.assertEqual(result.path_uses[0].image, first.result.image)
        new_image = next(item for item in result.images if item.key == second.result.image)
        self.assertEqual(new_image.binary.value.spelling, b"/owned/bin/second")
        self.assertEqual(new_image.binary.value.realpath, b"/owned/libexec/second")
        self.assertEqual(new_image.binary.value.sha256, hashlib.sha256(SECOND_IDENTITY_BYTES).hexdigest())
        self.assertEqual(result.tasks[0].terminal.value.code, 7)
        self.assert_reference(
            result.tasks[0].terminal.raw_refs[0], supplied, "trace.100",
            sum(map(len, lines[:5])), 6, TERMINAL_7,
        )
        self.assertEqual(result.end.trigger, "returned")
        self.assertIsInstance(result.end.wait, observation.WaitExited)
        self.assertEqual(result.end.wait.code, 7)
        self.assertEqual(result.tracer_diagnostics, supplied.stderr)
        self.assertEqual(result.tracer_diagnostics.data, b"")

    def test_child_without_exec_requires_its_own_actual_terminal(self) -> None:
        parent = (FIRST_EXEC, CLONE_COPY, WAIT_CHILD, EXIT_REQUEST_0, TERMINAL_0)
        supplied = packet("no-exec-child", parent, (CHILD_EXIT_REQUEST, CHILD_TERMINAL))

        result = observation.inspect(supplied)

        self.assertEqual(result.status, "observed")
        self.assertEqual(result.reasons, ())
        tasks = {task.key.tid: task for task in result.tasks}
        self.assertEqual(set(tasks), {100, 101})
        self.assertEqual(tasks[101].parent_image, result.exec_attempts[0].result.image)
        self.assertEqual(tasks[101].creation_kind, "clone")
        self.assertEqual(tasks[101].creation_flags, b"SIGCHLD")
        self.assertEqual(tasks[101].tgid.value, 101)
        self.assertEqual(tasks[101].terminal.value.code, 0)
        self.assertEqual(tasks[100].terminal.value.code, 0)
        self.assertFalse(any(attempt.task == CHILD for attempt in result.exec_attempts))
        inherited = next(image for image in result.images if image.key.task == CHILD)
        self.assertEqual(inherited.key.generation, 0)
        self.assertEqual(inherited.binary.value.spelling, b"/owned/bin/first")
        self.assertEqual(inherited.binary.value.sha256, hashlib.sha256(FIRST_IDENTITY_BYTES).hexdigest())
        self.assert_reference(
            tasks[101].birth_refs[0], supplied, "trace.100", len(FIRST_EXEC), 2, CLONE_COPY
        )
        self.assert_reference(
            tasks[101].terminal.raw_refs[0], supplied, "trace.101",
            len(CHILD_EXIT_REQUEST), 2, CHILD_TERMINAL,
        )

    def test_wait_and_exit_request_cannot_supply_a_missing_child_terminal(self) -> None:
        parent = (FIRST_EXEC, CLONE_COPY, WAIT_CHILD, EXIT_REQUEST_0, TERMINAL_0)
        supplied = packet("missing-child-terminal", parent, (CHILD_EXIT_REQUEST,))

        result = observation.inspect(supplied)

        self.assert_incomplete(result, "missing-task-terminal")
        child = next(task for task in result.tasks if task.key == CHILD)
        self.assertEqual(child.terminal.reason, "missing-task-terminal")
        self.assertEqual(next(task for task in result.tasks if task.key == PARENT).terminal.value.code, 0)
        self.assertIsInstance(result.end.wait, observation.WaitExited)
        self.assertEqual(result.end.wait.code, 0)
        self.assertNotIn("raw-sha256-mismatch", {reason.code for reason in result.reasons})

    def test_missing_and_orphan_trace_members_refuse_task_inference(self) -> None:
        parent = (FIRST_EXEC, CLONE_COPY, WAIT_CHILD, EXIT_REQUEST_0, TERMINAL_0)
        supplied = packet("task-membership", parent, (CHILD_EXIT_REQUEST, CHILD_TERMINAL))
        cases = (
            (replace(supplied, trace_members=supplied.trace_members[:1]), "missing-task-trace"),
            (
                replace(supplied, trace_members=supplied.trace_members + (member(ORPHAN, (CHILD_TERMINAL,)),)),
                "orphan-task-trace",
            ),
        )
        for changed, code in cases:
            with self.subTest(code=code):
                result = observation.inspect(changed)
                self.assert_incomplete(result, code)
                self.assertNotIn("raw-sha256-mismatch", {reason.code for reason in result.reasons})

    def test_unordered_shared_cwd_stays_unknown_despite_timestamps_and_one_direct_use(self) -> None:
        parent = (FIRST_EXEC, CLONE_SHARED, DIRECT_OPEN, UNANNOTATED_OPEN, SECOND_EXEC,
                  WAIT_CHILD, EXIT_REQUEST_7, TERMINAL_7)
        times = (
            ("equal", b"1700000000.000004", b"1700000000.000004"),
            ("overlap", b"1700000000.000003", b"1700000000.000005"),
            ("reversed", b"1700000000.000005", b"1700000000.000003"),
        )
        for label, entered, completed in times:
            entry = entered + b' chdir("/owned/other" <unfinished ...>\n'
            resume = completed + b' <... chdir resumed>) = 0\n'
            supplied = packet(
                label, parent, (entry, resume, CHILD_EXIT_REQUEST, CHILD_TERMINAL), returncode=7
            )
            for reverse_members in (False, True):
                with self.subTest(clock=label, reverse_members=reverse_members):
                    ordered = (
                        replace(supplied, trace_members=tuple(reversed(supplied.trace_members)))
                        if reverse_members else supplied
                    )
                    result = observation.inspect(ordered)
                    self.assert_incomplete(result, "unresolved-shared-state-order")
                    uses = {use.raw_path: use for use in result.path_uses}
                    self.assertEqual(uses[b"direct"].resolution.value, b"/owned/work/direct")
                    self.assertEqual(uses[b"direct"].resolution.basis, "direct-operation")
                    unresolved = uses[b"unseen"]
                    self.assertEqual(unresolved.resolution.reason, "unresolved-shared-state-order")
                    self.assertEqual(unresolved.errno, "ENOENT")
                    second = next(
                        attempt for attempt in result.exec_attempts
                        if attempt.executable == b"/owned/bin/second"
                    )
                    self.assertEqual(second.cwd.reason, "unresolved-shared-state-order")
                    self.assertEqual(second.result.image.generation, 2)
                    refs = unresolved.resolution.raw_refs
                    entry_ref = next(
                        ref for ref in refs if ref.member == member_id("trace.101") and ref.physical_line == 1
                    )
                    resume_ref = next(
                        ref for ref in refs if ref.member == member_id("trace.101") and ref.physical_line == 2
                    )
                    self.assert_reference(entry_ref, ordered, "trace.101", 0, 1, entry)
                    self.assert_reference(resume_ref, ordered, "trace.101", len(entry), 2, resume)
                    own_ref = next(
                        ref for ref in refs if ref.member == member_id("trace.100") and ref.physical_line == 4
                    )
                    self.assert_reference(
                        own_ref, ordered, "trace.100", sum(map(len, parent[:3])), 4, UNANNOTATED_OPEN
                    )

    def test_correlated_wait_justifies_shared_cwd_with_a_complete_dependency_chain(self) -> None:
        parent = (FIRST_EXEC, CLONE_SHARED, WAIT_CHILD, AFTER_WAIT_OPEN, EXIT_REQUEST_0, TERMINAL_0)
        child = (CHILD_CHDIR, CHILD_EXIT_REQUEST, CHILD_TERMINAL)
        supplied = packet("causal-shared-cwd", parent, child)

        result = observation.inspect(supplied)

        self.assertEqual(result.status, "observed")
        self.assertEqual(result.reasons, ())
        use = next(item for item in result.path_uses if item.raw_path == b"missing")
        self.assertEqual(use.resolution.value, b"/owned/other/missing")
        self.assertEqual(use.resolution.basis, "causal-inheritance")
        self.assertEqual(use.errno, "ENOENT")
        dependencies = use.resolution.dependencies
        self.assertTrue(dependencies, "Inherited cwd needs its interval and sharing epoch")
        for dependency in dependencies:
            self.assertEqual(dependency.epoch.kind, "cwd")
            self.assert_reference(
                dependency.used_at, supplied, "trace.100", sum(map(len, parent[:3])), 4, AFTER_WAIT_OPEN
            )
        refs = tuple(ref for dependency in dependencies for ref in dependency.causal_refs)
        expected_chain = (
            ("trace.100", len(FIRST_EXEC), 2, CLONE_SHARED),
            ("trace.101", 0, 1, CHILD_CHDIR),
            ("trace.101", len(CHILD_CHDIR) + len(CHILD_EXIT_REQUEST), 3, CHILD_TERMINAL),
            ("trace.100", len(FIRST_EXEC) + len(CLONE_SHARED), 3, WAIT_CHILD),
            ("trace.100", sum(map(len, parent[:3])), 4, AFTER_WAIT_OPEN),
        )
        for name, start, line, raw in expected_chain:
            matching = [ref for ref in refs if ref.member == member_id(name) and ref.byte_start == start]
            self.assertTrue(matching, f"Missing causal evidence at {name}:{line}")
            self.assert_reference(matching[0], supplied, name, start, line, raw)

    def test_unmodeled_unshare_invalidates_inference_but_not_a_direct_operation(self) -> None:
        parent = (FIRST_EXEC, CLONE_SHARED, WAIT_CHILD, UNSHARE, AFTER_WAIT_OPEN,
                  AFTER_UNSHARE_DIRECT, EXIT_REQUEST_0, TERMINAL_0)
        supplied = packet("unmodeled-unshare", parent, (CHILD_CHDIR, CHILD_EXIT_REQUEST, CHILD_TERMINAL))

        result = observation.inspect(supplied)

        self.assert_incomplete(result, "unmodeled-state-transition")
        uses = {use.raw_path: use for use in result.path_uses}
        self.assertEqual(uses[b"missing"].resolution.reason, "unmodeled-state-transition")
        self.assertEqual(uses[b"direct"].resolution.value, b"/owned/other/direct")
        self.assertEqual(uses[b"direct"].resolution.basis, "direct-operation")
        transition = next(
            ref for ref in uses[b"missing"].resolution.raw_refs
            if ref.member == member_id("trace.100") and ref.physical_line == 4
        )
        self.assert_reference(transition, supplied, "trace.100", sum(map(len, parent[:3])), 4, UNSHARE)


    def test_unquoted_ellipsis_in_each_fd_annotation_refuses_path_credit(self) -> None:
        records = (
            b'1700000000.000003 openat(AT_FDCWD, "leaf", O_RDONLY) = 3</owned/partial...>\n',
            b'1700000000.000003 openat(AT_FDCWD</owned/partial...>, "leaf", O_RDONLY) '
            b'= -1 ENOENT (No such file or directory)\n',
        )
        for record in records:
            with self.subTest(record=record):
                supplied = packet(
                    "unquoted-annotation-ellipsis",
                    (FIRST_EXEC, record, EXIT_REQUEST_0, TERMINAL_0),
                )

                result = observation.inspect(supplied)

                self.assert_incomplete(result, "abbreviated-record")
                self.assertFalse(any(
                    isinstance(use.resolution, observation.Established)
                    for use in result.path_uses
                ), "An ambiguous annotation cannot establish a required path")

    def test_quoted_path_and_argv_ellipses_remain_literal_data(self) -> None:
        record = (
            b'1700000000.000003 openat(AT_FDCWD, "literal,...", O_RDONLY) '
            b'= -1 ENOENT (No such file or directory)\n'
        )
        supplied = packet(
            "quoted-literal-ellipsis",
            (FIRST_EXEC, record, EXIT_REQUEST_0, TERMINAL_0),
        )

        result = observation.inspect(supplied)

        self.assertEqual(result.status, "observed")
        self.assertEqual(result.reasons, ())
        self.assertEqual(result.exec_attempts[0].argv, FIRST_ARGV)
        self.assertEqual(result.path_uses[0].raw_path, b"literal,...")
        self.assertEqual(result.path_uses[0].resolution.value, b"/owned/work/literal,...")
        self.assertEqual(result.path_uses[0].errno, "ENOENT")



if __name__ == "__main__":
    unittest.main()
