# First pure observation unit

TL;DR. This unit specifies facts and refusals returned by `inspect(StagePacket)`.
It contains behavior tests and an unconditional unimplemented scaffold only.
It does not authorize or perform replay, capture, native assertion RED, or any
protected operation.

26 October 2026, Europe/Berlin. The controlling contract is 77,391 bytes with
SHA256 `df6de11d252841b29e509caae79c0eb3ed5d5af5127930a7d6061fa9826894ab`.
Its accepted independent review has SHA256
`5466e066bd53d840f0592432ad877fe8c0b686350647ce511f76f080ad5837da`.
The selected implementation synthesis has SHA256
`c2cf6a3ff6ba229feb62009c248cc77893a994b58f1f1e467be1148ed1a0a9cd`.
Those complete documents remain controlling. This first unit does not replace
or narrow their final acceptance requirements.

## Boundary and data

The sole pure boundary is `inspect(packet: StagePacket) -> Observation`.
`observation.py` contains only imports, immutable record/type declarations,
and that function with an unconditional `raise NotImplementedError` body.
There is no decoder, validator, causal algorithm, capture helper, or effect.
`test_observation.py` supplies the small synthetic packets. `SPEC.md` was
written before the tests; the scaffold is written after the tests.

One immutable observation book owns the returned tasks, images, exec attempts,
path uses, raw members, launch/wait/cleanup receipts and incompleteness reasons.
Task identity is stage, TID and birth generation. Image identity adds the
successful-exec generation. Generation zero denotes the pre-exec or inherited
image; successful exec advances the generation, failed exec does not.
Established values and unknown facts are distinct alternatives.

Origin is explicitly `OriginalRow`, `ActualControl`, or `Synthetic` and is
preserved from packet to observation. Every fixture here is Synthetic, including
valid packets with declared binary and launch receipts. Data construction does
not authenticate execution. `observed` means this finite packet's first-unit
facts reconcile; it is not whole-development acceptance or readiness.

Every input raw member has exact immutable bytes, declared byte length, SHA256,
safe relative name and stage-local task association. This unit admits complete
members only; partial and withheld member alternatives remain later work.
Returned raw references use zero-based, half-open byte ranges including the
physical record's newline, and one-based physical line numbers. A paired call
keeps both physical references. A digest of altered retained bytes cannot stand
in for a digest of the original member.

Launch data contains the target task, exact byte argv/environment/cwd, declared
binary identity and explicit tracer argv/environment/session/descriptor facts.
Tracer wait and owned cleanup are independent receipts. Binary receipts bind
spelling, realpath, byte length and SHA256; in these Synthetic fixtures their
identities are descriptions of test bytes, not executable files or live hashes.
Inspect may join those receipts to a matching successful exec, but may not
invent a binary identity for another path.

Inherited cwd facts retain a sharing epoch and dependency interval, with raw
evidence for their causal chain. These facts remain provisional until the whole
packet has been reconciled for unordered foreign mutation. Direct evidence
belongs to its particular operation and does not update unrelated inferences.

## First behavior families

| Family | Required observable behavior | Contract predicates |
| --- | --- | --- |
| Complete exec and terminal | Preserve literal argv/environment bytes, successful image generation, matching declared binary identity, launch cwd and exact exec/path/terminal raw references. Preserve Synthetic origin. Keep tracer wait separate from task terminal. Reject declared byte-length or digest mismatch and launch/exec or tracer-wait disagreement with specific reasons. | Section 7 receipt table and parsing rules 1, 2, 3, 6, 7, 10; section 9 literal data and completeness controls |
| Failed exec, later replacement, exit 7 | Retain ENOENT, complete argv/environment and failed-attempt raw reference. A subsequent path use still belongs to the old image. Only the later successful exec creates the next image. Exit 7 is a normal terminal outcome, corroborated by tracer wait 7. | Section 7 rules 3 and 10; section 9 failed-exec/nonzero control |
| Child without exec | A clone with SIGCHLD creates a distinct task inheriting the parent's image. Both actual terminal markers are required. Removing only the child's marker while retaining its exit request and the parent's successful wait yields `missing-task-terminal`. Removing the member yields `missing-task-trace`; adding an uncreated member yields `orphan-task-trace`. | Section 7 rules 3, 4, 9, 10; section 9 missing-task control |
| Shared cwd and causal resolution | CLONE_FS shares cwd. An unordered child chdir with unfinished/resumed spans leaves another task's unannotated relative use and exec cwd `unresolved-shared-state-order`. Equal, overlapping and reversed timestamps, and member order, cannot resolve them. A direct `-yy` open annotation resolves only that open. A child mutation followed by its terminal and the parent's correlated wait can justify a later shared-cwd use. A successful unmodeled unshare invalidates affected inference. | Section 7 rules 4, 5, 6 and causal paragraphs; revised review finding 2; section 9 shared-state control |

All path uses and exec cwd facts exercised here are required facts for this
unit. An unresolved one makes the observation `incomplete`. A failed open can
still have an established attempted pathname when its cwd is justified; it
never establishes file contents, an import, or module execution.

The finite positive causal rule in these tests is explicit. CLONE_FS establishes
sharing before the child chdir. Child record order puts successful chdir before
its actual terminal. A matching successful parent wait establishes that terminal
before the later parent use. The resulting dependency interval must retain the
creation, mutation, terminal, wait and use references. No timestamp order or
successful foreign return alone supplies any of those edges.

For this initial unit, `unshare(CLONE_FS)` is recognized but has no admitted state
transition rule. It produces `unmodeled-state-transition` for subsequent cwd
inference, while a direct annotation still resolves its own operation. Later
support requires a separately reviewed finite rule and positive controls; it
must not silently change these initial expectations to permissive inference.

Specific refusal codes under test are `raw-length-mismatch`,
`raw-sha256-mismatch`, `launch-exec-mismatch`, `tracer-wait-mismatch`,
`missing-task-terminal`, `missing-task-trace`, `orphan-task-trace`,
`unresolved-shared-state-order`, and `unmodeled-state-transition`. Reasons bind
affected tasks and available raw references. Invalid member identity cannot
produce established task/image/exec/path facts from that member.

## Fixture origin and test execution

The literal exec, openat FD annotations, wait4, exit_group and terminal grammar
is grounded in the retained tiny real traces `trace.2016` and `trace.2017` from
run 40272766665. This suite constructs smaller records, changes paths/tasks and
adds timestamps. Every resulting packet is explicitly Synthetic. The tiny
actual traces are neither copied wholesale nor reclassified as these fixtures.
The clone/sharing and unfinished/resumed records are constructed contract
controls, not claims about what that earlier run emitted.

Expected strings, image relationships, paths, errno and terminal codes are
specified from the hand-auditable literals. Test-only length/hash construction
and offset arithmetic do not invoke the candidate parser. Malformed member
controls alter one declared identity field; missing-marker controls recompute
the new complete member identity so an earlier hash failure cannot mask the
terminal requirement.

The test file uses only standard-library unittest. It loads the fixed sibling
`observation.py` with `spec_from_file_location`, registers the module before
execution for dataclass initialization, and disables bytecode writes. It needs
no ambient sys.path addition, PYTHONPATH, package install or test dependency.
Root may run an existing isolated interpreter with `-I -S` and this file's
absolute path. This author performs no execution, import, collection or tests.

No test expects NotImplementedError as success. Root must first demonstrate
successful import/fixture construction and failures reaching `inspect` itself.
Those failures prove missing NEW functionality only. They are not an observed
old defect or any of the fifteen original native assertion failures. Root reads
all three frozen files and obtains fresh independent SPEC/TEST/scaffold
acceptance before assigning runtime implementation to a separate author.

## Still required later

The remaining finite grammar, signal/thread/execveat/TID-reuse rules, descriptor
and cache lineage, all malformed/truncated/withheld forms, namespace/escape
handling, limits and sensitive export controls are not implemented here.
Neither are capture, the single new budget owner, owned cleanup, literal stage
vectors, genuine R preparation, product joins, named source predicates,
packaging or original-driver integration. Every admitted transition still needs
the contract's actual harmless controls before original replay.

All original P/C/M/R bytes, fifteen tests/assertions, 57-item closure, fixture
positions, caps, expiry and owner grants remain unchanged. Actual replay,
cleanup/restoration/retrieval, independent raw review and later protected gates
remain separate obligations. No original source, workflow, asset, Git state or fourth
file is part of this unit.

Confidence is High in the stated contract mapping and Medium in unexecuted
test/scaffold correctness. Risks are a fixture construction/import mistake,
false shared-state inference, and synthetic evidence being overstated. Root's
focused run, independent review of literal traces/dependencies, and explicit
origin/limited outcome address those risks. The author incurs no hosted run or
acquisition cost. Runtime duration remains unmeasured. Root can discard these
three private diagnostic files if the unit is rejected.

Model the Domain keeps unknown facts, provenance and dependency intervals in
the data. Test Behavior, Not Implementation keeps assertions on returned facts,
identity bindings and refusal reasons rather than private parser structure.
The next action belongs to root: establish the intended failing-before evidence,
review the frozen unit independently, then decide runtime-author authority.

## Finite annotation correction after independent runtime review

The complete REQUEST_CHANGES report SHA256
`caa39f406fd09a2a59f2f31f1854e19a9155ce084e0c8a97abcd9493a56eda28`
identified two currently admitted openat forms that establish ambiguous paths.
An unquoted ellipsis in either the returned-FD annotation or directory-FD
annotation must yield `incomplete` with `abbreviated-record` before the
annotation can establish a path. This applies the existing closed lexical
grammar and outside-string abbreviation rule to both annotation channels.
It does not introduce a new tracing feature or an exception for a literal
unquoted filename spelling that cannot be distinguished by this finite rule.

Quoted pathname and argv bytes containing literal ellipses remain valid data.
A separate positive control must retain those exact bytes and resolve the
attempted quoted pathname when the cwd is justified. All original ten test
methods, eighteen original calls, data declarations and expectations remain
unchanged. New packets are Synthetic with complete recomputed member identity.
This correction provides no native RED, original replay, or readiness credit.
The original scaffold-only description above records the accepted test-first
phase; the separately authorized runtime implementation remains subject to
this specification and independent acceptance.

## Capture handoff amendment, SPEC and tests only

26 October 2026, Europe/Berlin. This amendment follows accepted synthesis
`f7aee65667479f4d2466f14da25b83656f8396f23c6fbff84bfb41a899f7a42b`
and complete independent ACCEPT
`d307f39d014784d390867f84cdac7d492671abc2e192e569a801778f108bb6a1`.
It specifies the next finite handoff. The preceding sections retain their
historical first-unit meaning and all their semantic oracles. Neither old test
file changes at this checkpoint. Runtime, actual capture, and external gates
remain closed until root obtains intended failing evidence and fresh independent
test acceptance. No production scaffold is part of this checkpoint.

The next completed runtime unit is fixed harmless-control capture, truthful
sealing, and inspection through the actual generated two-helper loader. It ends
before genuine R preparation or any original C/M/R execution. Unsupported actual
syntax may leave that unit incomplete. A missing API assertion demonstrates
missing NEW behavior only. Import, collection, and setup errors earn no such
credit, and none of these outcomes is original native assertion RED.

### Canonical raw values and independent outcomes

`MemberId(value)` is an opaque safe identifier. `RawRef.member` uses that value,
with the existing half-open byte offsets and one-based physical line. A member's
filename never supplies task, image, ordering, or execution authority. The
capture variants are immutable and mutually exclusive.

| Variant | Retained evidence |
| --- | --- |
| `Complete(member_id, name, data, byte_length, sha256)` | Exact stable EOF bytes, full length and digest, and completed confidentiality checks. A safe retained name is allowed. |
| `Partial(member_id, name, data, prefix_length, prefix_sha256, extent, reason)` | Retained prefix bytes and their own identity only. `StableFinalSize(byte_length)`, `ObservedLowerBound(byte_length)`, or `Unknown` describes extent. There is no full-member digest. |
| `Withheld(member_id, category, observed_bytes, reason)` | Safe category, count, and reason only. There is no filename, data, digest, or sensitive marker. |

`TraceAssociation(member, task)` carries `TaskKey` or `Unknown` independently
of raw identity. `StagePacket` retains origin, origin_label, stage, launch,
trace_members, stdout, stderr, tracer_diagnostics, binary_identities, end, and
accounting. Launch may be Unknown. Stdout and stderr are captured members or
Unknown. Only trace_members enter the trace decoder. Streams and later products
have distinct roles. A later complete JSON or XML product also retains its
producing row and attempt, absence before write, fresh identity, and frozen
predecessor. Partial structured products cannot be admitted.

The one retained stderr member contains the shared stream produced by the fixed
strace command. `tracer_diagnostics` is a byte-bound logical view referencing
that member where attribution is justified, or Unknown. It is never a second
physical stderr stream or a duplicate raw value. Unattributed bytes cannot be
called tracer diagnostics or child stderr. Unknown required attribution or
completion blocks acceptance. The original argv and FD rules remain literal.

`CaptureEnd(trigger, wait, cleanup)` retains returned, timeout, cap,
collector-error, or launch-error independently of final `WaitExited(code)`,
`WaitSignaled(signal)`, or `WaitMissing(reason)`. Existing Cleanup booleans remain
actual reaping and owned-group facts. Timeout followed by final signal wait
retains both. Task terminals remain Established Exited, Established Killed, or
Unknown. Normal exit 7 cannot become signal 7 or 128 plus a signal. A missing
launch, association, wait, terminal, or safe cleanup stays explicitly incomplete.

`Observation.terminal_markers` retains finite normal or SIGTERM terminal markers
with exact RawRefs even when another complete trace record has unsupported
syntax. Each marker has terminal and raw_refs fields. Those unjoined markers
establish no task generation, launch, image, exec success, or semantic success.
Identity or lexical failure still yields no established task, image, exec, or
path facts. Partial and withheld required raw input cannot establish these facts.
Specific refusal reasons include partial-raw-member, withheld-raw-member,
launch-unknown, trace-association-unknown, and the existing lexical and semantic
refusals. Output retains all independent capture receipts without normalization.

### One cumulative owner

Replay owns the only mutable cumulative allowance and current immutable Book.
One outstanding operation consumes a Checkpoint with session_id,
operation_sequence, committed, measured, conservative, and closure_reserved.
The observation invocation uses a local tally only. Its returned operation
receipt binds before, measured_delta, conservative_delta, unused_allowance,
and refusals. A fixed-limit Usage includes traversal_bytes, retained category
bytes, export_files, physical_records, per-scope members and task generations,
and four-original-row combined members and tasks. No caller limit, callback,
path lookup, transport, or operational override enters `inspect(packet)`.

Every hash, split, scan, token decode, copy, encode, verification, export, and
rejection traversal checks remaining capacity before work and spends bytes.
Rereading identical bytes spends again. Size-plus-one reads and refused data
spend the bytes actually traversed. Captured occurrences consume member and
task counts once. The same occurrence does not consume those counts again
merely because it is inspected twice. Successive fixed captures share the
original session's allowance and cannot borrow retained-byte categories.

Both helper sources' bounded initialization reads and hash verification derive
from one manifest and yield one immutable InitializationReceipt. The source
owner adopts it once before controls. Reuse cannot renew a session. Matching
operation commits are one-use. Duplicate, foreign, stale, or over-budget
receipts refuse without granting capacity. A missing or untrustworthy return
consumes the full outstanding optional allowance as conservative debit and
stops that session. Lost work is never reclassified as measured reads or
refunded. There is no multiplier reservation, second fact writer, or retry.

Fixed closure headroom stays inside existing categories and ceilings. Its
proposed reservation is 65536 retained metadata bytes, 1048576 traversal bytes,
and one export file in preparation/restoration/export. A bounded footer must
fit there or stay unknown/withheld. Cleanup still runs. Actual operational
exhaustion or cleanup uncertainty stops progression. A deliberately stricter
local negative control can qualify while its packet remains incomplete.

The tests assert fixed controls' immutable operation records where available.
Before runtime acceptance, root must separately scope a real-owner test-only
fault seam if needed to exercise duplicate/stale/foreign/over-budget commit,
initialization reuse, and missing/untrustworthy report paths. Each terminal
fault uses a separate disposable test attempt. No test begins another optional
operation after that same session stops. Separate diagnostic sessions cannot
be combined into one original attempt. No generic begin/commit/launcher API is
introduced here, and unexercised fault paths receive no passing credit.

### Fixed controls and later lifetime proof

`Replay.open(owned_roots, verified_policy, initialization=receipt)` receives only
trusted driver-owned roots and the original already verified policy modules.
`harmless_controls()` takes no arguments. It returns immutable qualification
with book, cases, progression_allowed, and clock_cases. Each case identifies its
name, scope_ids, and qualified result. Task/path/image facts remain stored once
in book.stages. Book.operations owns the immutable accounting receipts. There
is no arbitrary command, expected-outcome, local-limit, or source argument.

The first finite case names are exit-seven, sigterm, prefix-4096,
trace-members-two, withhold-content, withhold-name, unsupported-syntax,
missing-terminal-synthetic, missing-reap-synthetic, collector-exception,
owned-timeout, successive-captures, and reread-refusal. They preserve real
retained bytes and exact RawRefs. The prefix case must really retain 4096 bytes
of a larger output. The two-member local case must really encounter a third
member. Content and filename controls must really trigger whole-member
withholding without exposing the harmless marker or its digest in ordinary
serialized returned evidence. Unsupported syntax retains byte references.
Edited missing terminal/reap packets carry Synthetic origin. A missing marker
is ActualControl only if the missing event was actually caused and retained.

Exit-seven and sigterm retain distinct actual waits. The inspector may keep
unsupported actual grammar incomplete rather than invent success. The timeout
and collector-error controls preserve their actual trigger, final wait, owned
group termination, and direct-child reaping. Actual controls must retain exact
clean argv/environment, DEVNULL stdin, close_fds, empty pass_fds, owned session,
and actual resource limits. Traced children remain within 30 seconds each.
Cleanup remains bounded by 5 plus 5 plus 5 seconds within the 300-second
combined control envelope. No original materializer cleanup credit transfers.

The paired read-gap-before and read-gap-after clock cases each use a real
untraced parent gap of at least 61 seconds around the first unchanged
Evidence.read. No mocked clock or traced-child limit extension is allowed.
Their immutable clock records retain gap_start, gap_end, owner_end_before,
owner_end_after, collection_started_before_gap, and the actual original
Evidence manifest. Charged pre-use fixture identities remain in Book.identities.
Before-read placement permits the original collection/deletion to complete;
after-read placement truthfully exhausts its original 60-second collection
window. Both preserve timer.end, original source/blob collection, exact saved
deletion, and restoration. The pair costs at least 122 real seconds inside the
same 300-second control envelope. This is later actual execution, not a result
of these unrun tests.

Eventual actual/main caller integration remains a separate code unit. Replay
owns all section-8 live pre-use/cache/post-use evidence, including M evidence.py
and lifecycle.py. The driver checks original timer.end before unchanged deferred
tool_facts and retains original Evidence, collection, deletion, and restoration.
finish starts the one new 60-second final window before its first new post-unwind
R read, identity reread, export validation, or serialization. Unchanged
publish_safe completes on its own old tree before its actual collector/export
usage can be joined. New rereads remain charged. No old/new cap or clock renews.
Retrieval authentication, transport, one-time exclusive continuation, deployment,
and authority remain later gates. No route for them is added at this checkpoint.

### Preservation and evidence cutoff

The existing complete exec, failed exec, normal exit 7, child without exec,
missing terminal, causal dependency interval, unmodeled transition, and both
annotation refusal/quoted-literal oracles remain exact. Later migration must
enumerate old RawMember construction to Complete plus TraceAssociation, member
names to opaque RawRef IDs with the same byte resolution, packet receipts to
CaptureEnd, and the embedded bundle-child constructors/assertions. It must retain
every literal argv/environment, image relationship, errno, path, byte range,
line, identity, and refusal. Merely changing source hash pins is insufficient.

Neither test_observation.py nor test_bundle_loading.py changes now. No actual,
main, Evidence, tool_facts, cleanup, publisher, manifest, fixture, original
source, or owner body changes. All original 33/eight files/15 selectors,
assertions, mappings/plans/plugin, P/C/M/R, caps, expiries, and separate protected
gates remain controlling. Confidence is High for this contract mapping and
Medium for unexecuted new tests. Root next runs the bounded intended failures,
reads every changed line, obtains fresh independent test acceptance, and then
separately scopes runtime and the remaining migration/fault seams.

## Preservation migration amendment, SPEC and tests only

26 October 2026, Europe/Berlin. This amendment supersedes only the preceding
checkpoint's instruction to leave the old test sources unchanged. It implements
the preservation prerequisite in independent test ACCEPT
`f9c207ff1597c99146ed99674b06426e74a2fb6683b715aa2d0fd0006719b024`.
The accepted canonical evidence shape and all old semantic expectations remain
controlling. Runtime and all original owner bodies remain unchanged.

Every old RawMember becomes a Complete with the same safe name, exact literal
bytes, full length and full digest, paired with its original TaskKey through
TraceAssociation. Fixed opaque IDs m-parent, m-child and m-orphan identify the
same trace bytes formerly referenced as trace.100, trace.101 and trace.102.
RawRefs retain their exact half-open ranges and one-based physical lines.
Neither the ID nor the retained filename supplies task authority.

The old normal TracerWait and Cleanup inputs become CaptureEnd with returned
trigger, WaitExited of the same literal code, and the same cleanup facts.
Normal exit 7 remains WaitExited(7). The mismatch negative changes only that
wait code, retaining the actual task terminal and the tracer-wait-mismatch
reason. Empty complete stdout and stderr have distinct opaque IDs. The empty
stderr also supplies its own zero-byte diagnostic view, so the old empty
diagnostics oracle remains exact without a second physical stream or raw copy.
Nonempty shared stderr with unsupported attribution remains Unknown as already
specified. The canonical returned member store contains each trace and stream
once. Trace associations retain their original order or explicit reversal.

The migrated tests preserve complete exec, failed exec and previous image,
successful generation changes, literal argv/environment/cwd and binary bytes,
normal exit 7, child-without-exec inheritance, both actual terminals, missing
terminal despite wait and exit request, missing/orphan trace refusals, all
causal interval references, equal/overlap/reversed timestamps and member order,
unmodeled unshare, both unquoted annotation refusals and quoted-literal positives.
Malformed full length/digest controls still change only the declared field.
No source digest assertion replaces any of these behavior assertions.

The marker test uses that same canonical packet helper. Its unsupported record
still prevents task/image/exec/path inference, while the exact normal exit-7
or SIGTERM terminal bytes retain their original offsets and physical line.
Its independent capture wait uses WaitExited(7) or WaitSignaled("SIGTERM").
An explicit missing-NEW-type assertion precedes construction in each intended
test boundary. The current old runtime can import and collect every test.
There is no old/new constructor branch, missing-import credit, compatibility
loader, fake inspector, skip, or expected failure.

Only this SPEC, BUNDLE_SPEC and the three named test sources migrate. Accounting
fault APIs, real-owner interruption/commit/exhaustion tests and exhaustive
traversal admission remain separately scoped To-Validate gates. The preceding
root-failing-001 result retains exactly its historical 15 methods and 16
missing-NEW assertions. It proves no migrated test or downstream native fact.
Root owns the new bounded failing run and fresh independent review.

## Real-owner accounting amendment, SPEC and tests only

26 October 2026, Europe/Berlin. This amendment follows the reconciled synthesis
`666ed678ba7891865c085d58c73a03e2820a7b35b6652d37dec0c57f1e06b961`
and independent accounting ACCEPT-for-SPEC-tests-only
`368dd2c0d725a6c54968012754ba3b660280df58891eb9dbe3912a0e55291f4e`.
It supersedes only the preceding deferral of direct accounting tests. Corrected
A supplies the lexical guard and tuple/span representation. B contributes only
caller source-submission debits and genuine-inspect-then-lose controls. No
runtime source, original owner, fixture, manifest, or operational API changes.

### Frozen constructor and reference schema

All records below are frozen dataclasses. Existing fact fields retain their
previous meaning. `FixedScope` uses the existing safe stage string. The public
packet field remains `stage`, as in every preserved test. `Checkpoint.scope`
must equal that field. Operational scopes come from the fixed row/control
table. Explicitly Synthetic private-constructor histories are diagnostic data.

```python
Usage(traversal_bytes=0, retained=(), export_files=0, physical_records=0,
	scope_counts=(), four_row_members=0, four_row_tasks=0)
# retained is tuple[(category: str, bytes: int), ...].
# scope_counts is tuple[(scope: str, members: int, tasks: int), ...].
MemberOccurrence(scope, role, member, association, prefix)
TaskOccurrence(key, witness)
Checkpoint(session_id, operation_sequence, committed, measured, conservative,
	closure_reserved, basis, scope, allowance)
OperationReceipt(before, measured_delta, conservative_delta, unused_allowance,
	refusals, encountered, newly_charged, coverage)
Incomplete(reasons)
Book(stages, identities, products, operations, occurrences, terminal_operations,
	original_final, replay_final, retrieval, assessment)
_Initial(session_id, book, measured, conservative, initialization)
_Pending(before, scope, allowance, kind)
_State(checkpoint, book, initialization, pending, closure, stopped)
```

The Usage tuples contain unique, deterministically ordered coordinates. Missing
coordinates mean zero. Four-row counts equal the sums of their original-row
coordinates. They cannot be seeded independently. Count-only encountered and
newly_charged Usage values have zero traversal, retained, and export coordinates.
Member roles are `trace`, `stdout`, and `stderr`. A shared-stderr diagnostic view
uses its existing stderr occurrence. Prefix is `(physical_lines, byte_stop)` or
Unknown for Withheld. A TaskOccurrence witness is its exact Launch or the tuple
of actual creation RawRefs. Book's two terminal slots are `(optional, closure)`.
An empty Book has empty tuples, `(None, None)`, Unknown final receipts, and
`Incomplete(())`. It contains no fabricated historical task or raw facts.

Checkpoint.basis is the exact before-Book object. The issued allowance is the
same object received by inspection. Recursive Book equality cannot authenticate
a receipt. In-memory coverage references canonical retained members and facts.
For the new wire fields only, Checkpoint.basis becomes
`{"session_id": session_id, "operation_sequence": operation_sequence}`.
MemberOccurrence becomes scope, role, member_id, association, and prefix.
TaskOccurrence becomes key and either launch_task or birth_refs. These new
references contain no name, payload, digest, nested Book, or copied Launch.
Parent, bundle-child, and control-child serializers use these same projections.
Every existing fact/raw serialization oracle remains exact. Repeated real
operations must retain these bounded references without historical expansion.

### One guarded lifetime and one canonical installation

The only cumulative owner is private `replay._Budget(_Initial(...))`.
Its ordinary constructor validates the input and adopts the real
InitializationReceipt once. Normal Replay.open supplies empty history through
this same guard and exposes no state override. Diagnostic tests call that
constructor with explicitly Synthetic prior history. There is no public begin,
commit, fault, callback, limit, launcher, or alternative accounting route.

```python
with owner._operation(packet.stage) as checkpoint:
	returned = observation.inspect(replace(packet, accounting=checkpoint))
	owner._receive(returned)
state = owner._snapshot
with owner._closure() as checkpoint:
	owner._receive(receipt)
```

`observation._allowance(scope, checkpoint)` is the one fixed-limit calculation.
The owner issues it and the invocation-local tally checks it before content
work. The guard exposes the accepted `_operation`, `_receive`, `_closure`,
`_adopt_initialization`, and read-only `_snapshot` signatures. The finalizer is
established before pending authority. Only one operation can be pending.

Receiving first bounds scalar shapes and checks the exact before-checkpoint,
session, sequence, basis identity, and allowance partition. Inspector measured,
conservative, and unused coordinates sum to the issued allowance. Validation
prepays every identity/coverage comparison and immutable Book construction
from that unused part. The finalized canonical receipt includes those visits
in measured_delta and subtracts them from unused_allowance. No free hash,
deep equality, index, history copy, or receipt traversal is permitted.

The finalized receipt, Observation, Book, checkpoint, pending removal, and
matching stopped partner are prepared before one `self._state` assignment.
Before that store, loss, BaseException, missing, malformed, stale, foreign, or
over-budget return preserves trusted measured history and all trusted history
tuples, adds the FULL issued grant to conservative usage, advances sequence
once, fills the optional terminal slot, clears pending, and stops. Its coverage
is empty. It invents no occurrence IDs. Nested entry takes this path for the
first pending grant and denies the nested body. No finalizer can debit it again.
After the store, interruption preserves the committed receipt and Book with no
second debit. A duplicate with no pending authority stops with
`duplicate-receipt` and no debit. Later optional bodies cannot enter.

The one closure transitions held to pending to spent, including after stop.
Its failure fills only the closure terminal slot and consumes the held grant
once. No second closure body enters and no capacity renews. Cleanup still
belongs to the actual process owner's finally. Abrupt process death and
repeated interruption of recovery are not persistence guarantees here.

### Identity credit and jointly feasible allowances

MemberId binds session-wide scope, role, association, variant, retained name,
extent, length, digest where present, and exact retained bytes. A changed
binding refuses before reread credit. Task identity includes scope, TID, birth
generation, and its canonical birth witness. A fresh ID with identical bytes
is a new occurrence. A physical record is its verified MemberId and one-based
line. Only trace roles consume trace-member and physical-record counts.
Withheld keeps safe metadata only and prefix Unknown. It earns no invented
bytes, name, digest, verified-prefix credit, or semantic acceptance. Shared
stderr retains one payload and no additional diagnostic occurrence.

Prior-count credit follows paid lookup, binding comparisons, hash verification,
and exact byte comparison. Hash equality alone is insufficient. A bounded
framing walk admits each next new physical record before extraction, including
a malformed final line. Previously counted prefix lines may be reread at the
500000-record ceiling while their hash/framing visits still spend bytes. There
is no eager whole-member split before admission and no post-parse count refund.

Let U be measured plus conservative usage and H the held closure. For the
selected scope only, new traversal allowance is `256 MiB-U.bytes-H.bytes`.
An original-row member or task allowance is
`min(512-U.scope, 1024-sum(U.original_rows))`. Every other scope coordinate is
zero. Other fixed scopes use their applicable 512 ceiling without a fictitious
four-row grant. Record allowance is `500000-U.records`. Retention and files
use their own residuals and holds. Controls additionally obey 1 MiB per receipt
and 8 MiB combined. A full conservative loss must fit every projection.

Original holds remain 512 MiB reads, 48 MiB retained, and 64 files until verified
original usage replaces only those projections. New work never borrows them.
Closure holds 1 MiB traversal, 64 KiB preparation metadata, and one file inside
the new 256 MiB and combined 768 MiB read bounds. Retention remains
48+64+16+16+8+8 = 160 MiB and 128 files. No aggregate balance or cap multiplier
can create capacity. Boundary fixtures solve these component equations with
initialization, constructor validation, receiving validation, and holds included.

Before any nonempty history visit, the constructor admits its whole validation
itinerary against proposed prior usage plus real initialization and closure.
That itinerary hashes each distinct retained member once, frames each counted
prefix once, and pays exact metadata comparisons/copies and requested equality
separately. A compact Synthetic witness uses 499999 or 500000 newline bytes
with its real full digest, association, prefix, and coherent historical receipt.
It establishes count metadata, not task success or actual historical capture.
Synthetic historical traversal is an explicit assumption. Actual constructor
and later visits are separately measured. Inconsistent spans, digests, sums,
bindings, and duplicate keys refuse before becoming trusted history.

### Direct tests and evidence cutoff

New methods remain in CaptureHandoffTests. Each terminal fault gets a fresh
ordinary owner. Tests first obtain a genuine real-inspect result, then lose,
corrupt, replay, or interrupt it. A one-shot source-bound observer targets both
sides of the actual canonical store. Exact Book/sequence/measured/conservative,
pending, terminal slots, closure, and denied later optional work are oracles.
Each denial observer is paired with admission to the same real hash, framing,
field/string/regex, copy, source-verification, or history visit. Returned counters
alone cannot establish admission. An unobservable visit remains unproved.

The bounded correction checks successful final member/task admission at 511
per row and 1023 across the original rows, then uses separate exhausted owners
to refuse the next new occurrence before its content traversal. The existing
lost-return cases remain separate. Retained member names remain opaque.

For the inspected control scope, the only retained allowance is
`controls = min(1 MiB, 8 MiB-U.controls-H.controls)`. Original-row operations
instead receive the residuals for replay-traces, replay-streams, and
replay-reports-metadata, with ceilings 64, 16, and 16 MiB respectively.
Other retained coordinates are zero in these operations. Preparation metadata
belongs to its separate fixed operation or the held closure. The file allowance
is `128-64-U.files-H.files`. Initialization and constructor work remain in U.
These issued grants can be checked before capture/export receipts exist. The
current inspector's control-retention check commits a genuine small packet,
checks its exact 1 MiB grant and inclusive retained total, and refuses a
separate member whose raw bytes alone exceed 1 MiB. The inclusive limit also
covers receipt metadata. Raw payload alone need not reach the limit on an
admitted packet. This proves no later export-file production or exhaustion of
every large retained category.

Traversal tests identify exact AST and opcode operation positions, actual
inputs, and repeat counts. Empty hash creation is no input visit. A subsequent
hash update must be observed. Delegating hash/regex observers and exact byte
index, slice, iteration, and native framing observations establish disjoint
caller-level visits. Search operations may expose only a conservative positive
lower bound on examined bytes, which must be labeled separately from the full
presented input extent. Unsupported required operation attribution fails
explicitly. Cumulative independently observed bytes must fit each issued room
and the finalized measured debit. Each successful-path site receives paired
denied/admitted checks for its full observed occurrence count, so an earlier
event cannot stand in for a later event. Unexecuted source paths and compiler
internals receive no coverage claim.

The existing 33 methods and all their fact/raw/owner/fixture oracles remain.
New methods enter through the actual generated no-argument loader and require
the real _Budget and _Initial explicitly. The current first cutoff is
`NEW no-argument _load_helpers is missing in the real extracted driver`.
No fake module, replay.py, optional fallback, import/setup error, AttributeError,
skip, or expected NotImplementedError substitutes for that assertion. Root runs
the changed test boundary once after freeze and obtains fresh independent
acceptance before runtime authoring. Downstream semantics remain unexercised.
Original P/C/M/R, 33 native sources, eight files, 15 selectors, plans, timers,
and all separate capture, clock, original execution, and protected gates remain.

## Runtime review corrections, SPEC and tests only

26 October 2026, Europe/Berlin. Independent runtime REQUEST_CHANGES
`642f724f7d3555fbe7a1a99db6225f646638a752a4865e22c44c58924cbd953f`
identified violations of the existing receipt, directory, clock, and cleanup
rules. These clarifications add no runtime API or authority. The four runtime
files and all 45 existing test methods and literal oracles remain unchanged
during this test-first correction. The loader test's directory observer alone
may delegate to Path iteration or OS scandir without counting an entry twice.

A plain capture `OperationReceipt` enters the same issued-grant receiving
boundary as an inspection return. Before the canonical installation, its
coverage must have unique TaskKeys with stable Launch witnesses, valid member
roles, and trace associations in the selected scope. Complete and Partial
capture members have the unparsed prefix `(0, 0)`. Withheld has Unknown prefix.
Duplicate task coverage, changed launch binding, invalid role, foreign trace
association, and Complete with Unknown prefix each lose the whole pending
grant once. Exact prior history tuples and measured usage survive, closure
remains held, and no occurrence ID is invented. Copied-before and foreign-task
scope returns remain separate rejection controls. A valid plain capture must
commit its canonical identities. Subsequent real inspections of those retained
members must pay reread work without charging existing identities twice.

Cleanup authority must survive until the last nonzero process-group signal.
Once the direct child's exit status has been consumed, numeric group existence
alone cannot prove that the group still belongs to that child. If ownership is
unprovable, cleanup must avoid the signal and report the group as incomplete.
An already reaped child with an absent group remains a valid complete cleanup.
A Synthetic regression may reap its own short-lived child and replace only
the group-existence and group-signal OS boundary with a safe recording adapter.
It models a reused group number without signaling another process or claiming
an observed PID reuse. Actual child creation and wait remain real.

The read-gap-after case must reach its first unchanged Evidence collection
without a competing armed Timer. New helper sequencing must preserve the
original `timer.end`, the Timer guard, and the original 60-second collection
window. The existing four Linux methods keep their single shared actual control
attempt. A separate private Darwin debug script may call the actual verified
helper's `_clock_cases` with owned Synthetic fixtures and unchanged original
Timer, Evidence, and cleanup definitions. Its real 61-second gaps use no clock
replacement. The expected before-fix failure is the existing-timer error after
the first real gap. After correction, both genuine gaps and original collection
outcomes must complete within the unchanged bounds. This private route grants
no Linux qualification, original replay, or native evidence.

Root owns execution, exact failing-before source evidence, and independent
test acceptance. Runtime implementation stays closed at this checkpoint.


### Root feasibility reconciliation, 27 October 2026

The private Darwin clock route is now measured as unavailable under the frozen
original process limits. Its one actual attempt failed in the first command's
preexec setup, before any gap. A separate owned resource-API child confirmed
that Darwin rejects the original 2 GiB RLIMIT_AS setting. No timer failure or
clock qualification follows from that attempt. Do not retry unchanged or relax
the original limits. The unmodified private script and all raw evidence remain
historical; a separate root script version removed only a harness-imposed hard
file limit that conflicted with the original child limit.

RUNTIME01, RUNTIME02 and RUNTIME04 have genuine new local regression failures.
They may proceed as one bounded implementation unit after independent test
acceptance. RUNTIME03 stays closed until the unchanged clock function is
reproduced on Linux. After the other three corrections receive fresh review, an
exact separately reviewed, unprotected diagnostic run may collect failing-before
evidence for the clock case. It uses the selected complete-suite operation and
one actual control attempt; any failure remains FAILED, never qualification or
native RED. Its exact source, workflow, ordinary authorization and safety still
need review before execution. This does not authorize protected adoption.

After the real Linux clock failure, correct only the new helper's sequencing,
then require a fresh complete passing run, both real gaps and all existing
clock assertions. No test, original owner, process bound, authority, or native
evidence rule is waived. This is sequencing of verified units after an observed
platform refusal, not a successful substitute for clock evidence.

### Receiving TaskKey domain clarification, 27 October 2026

The common receiving boundary requires every `TaskOccurrence.key` and every
TaskKey-valued member association to have an exact `int` TID greater than zero
and an exact `int` birth generation at least zero; `bool` is invalid in either
field. These numeric requirements apply before canonical installation or
identity credit, including when a malformed key, its Launch witness, and its
trace association agree. Unknown associations remain valid. Positive birth
generations remain in the canonical identity domain; the finite inspector's
separate generation semantics do not impose a global generation-zero rule.
An invalid numeric identity loses the whole pending grant once and preserves
the existing trusted-history, closure, and duplicate-return guarantees. This
clarification adds no public validator, API, or authority. Root owns the
focused failing-before run and independent test acceptance before runtime edits.
