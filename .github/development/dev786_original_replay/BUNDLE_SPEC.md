# Isolated delivery of the accepted observer

TL;DR. The existing preflight must load the exact accepted `observation.py`
from its real generated bundle before local Synthetic inspection. This unit
adds no capture, replay, acquisition, public import option or observation type.

26 October 2026, Europe/Berlin. The accepted synthesis's "Explicit isolated
loading and packaging" section and the complete next-unit grounding control
this unit. The existing contract and first-unit SPEC remain controlling.
The first-unit runtime, SPEC and tests stay byte-frozen. In particular, the
runtime remains 37,683 bytes with SHA256
`6978576cb112ec9546a24bdaa3474bb55a1d98dff25fb6e16ccfb7ee32a094c9`.
The public 23 types and `inspect(StagePacket) -> Observation` do not change.

## Caller first

The existing `preflight.py` gains one private `_load_observation()` function
with no arguments. Its caller obtains the verified observer module and calls
its existing packet constructors and `inspect`. The module is loaded from
`Path(__file__).parent / "observation.py"`, after verifying the directory and
the exact source bytes. It is never found through an ordinary import.
This is the same private loading path that later replay integration will use.
The local test child explicitly loads the extracted preflight, invokes this
function, and constructs one complete and one malformed Synthetic packet.
It does not supply a replacement loader or decoder.

The directly callable function is sufficient for this unit. No new CLI mode
is required. Existing `actual`, `controls`, `creation-control`, transport,
materializer Timer and cleanup/restoration owners retain their behavior.
No generated materialization or acquisition step is run by these tests.
The workflow does not gain capture or original replay merely by delivering
the observer. No genuine shared-interface or ownership fork was found here.
Partial/Withheld members, signal terminals and cumulative replay accounting
remain the separately identified later architecture decisions.

## One trusted identity and closed paths

`preflight.py` owns one literal immutable tuple named `HELPER_MANIFEST`.
Each entry contains filename, byte length, SHA256 and fixed module identity.
Its sole admitted entry in this unit is:

```python
HELPER_MANIFEST = (
    ("observation.py", 37683,
     "6978576cb112ec9546a24bdaa3474bb55a1d98dff25fb6e16ccfb7ee32a094c9",
     "_dev786_original_replay_observation"),
)
```

The existing builder reads this trusted literal using its existing AST and
literal-evaluation pattern. It obtains the helper only from its own fixed
source directory. The source copy used by tests places the accepted sibling
`observation.py` beside the copied `build.py` and `preflight.py`.
The builder checks the length and digest against this trusted identity.
Neither a changed helper nor a helper's newly declared digest can authorize
itself. SPECs, tests, empty `replay.py`, generic modules and arbitrary paths
are never operational members.

The builder emits the existing `manifest` and `expected_names` declarations
and the actual `PY_DECODE` extraction program. It derives helper membership,
names and counts from `HELPER_MANIFEST`, alongside the existing preflight and
nine-fixture identities. Any generated copy of the trusted helper tuple is
derived from that one literal, never a second hand-maintained helper list.
The decoder independently checks payload entries against that trusted tuple.
Changing payload bytes and their payload-manifest digest together still fails.
There is no hardcoded ten-member assumption after this addition.

The extraction program retains its strict base64/zlib envelope, bounded
decompression, complete-stream checks, exclusive output creation and reread
verification. The decoded-source ceiling stays `256 * 1024` bytes. Names are
safe, unique and closed. Missing, extra, renamed, length-mismatched,
digest-mismatched or altered helper entries fail before helper execution.
The transport file is removed after successful extraction. The extracted root
contains only preflight, the fixture directory and the admitted helper.

The loader checks the closed helper set and rejects missing/renamed/extra
helper source files, symlinks and nonregular helper paths. It verifies length
and SHA256 before executing the same verified bytes with their fixed filename.
It registers `_dev786_original_replay_observation` before execution so the
accepted dataclasses initialize normally. Any existing module under that
identity is rejected even if its claimed path resembles the accepted path.
The returned module's file and spec origin identify the explicit extracted
path. The loader adds no `sys.path` entry, has no path/hash/module override,
and never imports a same-name ambient file. This makes no hostile same-UID
race-containment claim.

## Preserved fixture authority

All nine fixture byte identities remain fixed:

| Fixture | Bytes | SHA256 |
| --- | ---: | --- |
| compare.json | 326 | `e49c731f723a5bfe5daae171806b3e37caad1f46902e37a27d7bb6800a0f8599` |
| corrupt-input-envelope.json | 738 | `873544e96ec37ac6b2557691048493a492557aaade29a6eab0eb2606a451eeb5` |
| corrupt-requirements.in | 413 | `b909849caf501cb1343aecf0e80fc26bf997126a78d574c46881d5e54741b18b` |
| index-envelope.json | 638 | `50e7030d2509d0adeae22777643fcae3af4ce8656c65fc623fe46fc7ea9ef520` |
| index.json | 347 | `8bb0276e13664a5208a26451fd66a7e83620c445209b0d24a569daf78d78bc27` |
| main.json | 101 | `2e6ee0a8cf7619f4dbe5624eb4814d59df4a701158d64c8af177c426e30b71db` |
| moved-main.json | 101 | `9187f2fd6a58682fcd4965fefc100865e6d7b8f5155034d382a24b478e8d664e` |
| wrong-index-envelope.json | 638 | `29ef78589ab54e3eba309f464d21d5051d0041eb93a1a05fda292d43034805b5` |
| wrong-index.json | 347 | `cd491ae49ee174fc79d4eed775b22c03156d2d39ad147769da3a5afbed171359` |

Original P, its four module hashes, release hashes, all 18 transport positions
and original policy loading stay fixed. The tests compare the original
ownership functions' ASTs between recovery input and extracted driver.
The accepted old policy loader's own path behavior is outside this addition.
Historical restoration main `9f952f1bc591b9d58403a8a362ce9fe21fdfe47d`
is not reconciled to the newer authorized main in this unit.

## Behavioral proof and initial absence

`test_bundle_loading.py` uses standard library only. A root-supplied absolute
`DEV786_PREFLIGHT_INPUTS` identifies the existing local build/preflight/fixture
inputs. That variable configures the test copier only. It is not passed to
the builder, decoder or operational loader. Missing configuration stops
explicitly before collection. Original input bytes are read and copied,
never edited. The accepted observer is read from the test's fixed sibling.

The test runs the actual copied builder. It parses only the known generated
workflow format, joins the actual emitted transport chunks and executes the
actual emitted `PY_DECODE` Python through a test-only `runpy` observer. That
observer records helper-file execution events without replacing any decoder
statement. Extraction must record none. The separate loader child must record
exactly one helper-file execution on success and none on refusal. These audit
observations supplement the owned poison sentinels. The test executes no shell workflow, actual,
acquisition, materialization or tracer command. Test children use the existing
interpreter with `-I -S -B`, DEVNULL stdin, closed descriptors, private HOME
and TMPDIR, explicit PATH/locale, finite output acceptance and deadlines.
No credentials, parent environment copy, network, installs or PYTHONPATH
are supplied. Stdout/stderr are monitored in owned files with a 1 MiB bound
per stream and a 15-second process deadline. Polling is not an atomic quota.

After successful extraction, the exact helper reaches its accepted `inspect`.
The complete packet uses the already accepted literal exec, direct open,
exit request and terminal family. Assertions bind Synthetic origin, literal
argv/environment/cwd, byte-bound member, image generation and binary identity,
direct pathname, actual terminal, separate tracer wait/cleanup and exact
exec/open/terminal RawRefs. A separately malformed declared member digest
returns `raw-sha256-mismatch`, incomplete, with no derived task/image/exec/path
facts. No expected fact comes from candidate output.

Each loader mutation starts from an actually generated/extracted valid bundle.
A positive initialization must succeed before any guard result earns credit.
Negative inputs remove, rename, replace, truncate or add only owned helper
data, or preload the fixed module identity. Same-name poison files exist only
in owned ambient directories. Their sole possible sentinel effect is writing
an owned temporary file, which must remain absent. The poison body is valid
Python and does not depend on secrets, network or external state.

Decoder negatives perturb only payload `manifest`/`expected_names` declarations
and coherent transport envelope lengths/digests/total, leaving the actual
generated verification and extraction logic, trusted helper tuple and source
cap intact. This is an adversarial input control over the generated program's
data declarations, not a replacement decoder. Missing, extra, renamed,
altered, declared-length, declared-digest and self-rehashed helper inputs must
be refused. The self-rehashed case changes both source bytes and the untrusted
payload digest while preserving the trusted helper tuple. A separate coherent
oversize preflight payload keeps the accepted helper intact and tests the
unchanged decoded-source ceiling. A changed fixture with its original declared
digest also refuses. The valid extraction round trip rules out blanket refusal.

The real old builder has ten payload entries and no observer. The driver has
no `_load_observation`. A child may report structured `LOADER_UNAVAILABLE`
for that actual absence. Tests assert successful initialization explicitly;
this marker can never count as `REFUSED` or guard success. Missing new manifest
or helper membership also fails intended feature assertions. No old runtime,
stub or fake accepted decoder is created. Later guards are unreachable in the
initial missing-feature context and receive no initial correctness evidence.
Root owns actual failing-before execution and fresh independent test acceptance.

## Scope and handoff

Only this SPEC and its new test are authored now, in that order. No candidate
program, builder, import, collection or test is run by this author. Inert AST,
hash and scope checks are permitted. The report records their exact identities
and root's launch requirements. The author stops before implementation.

Confidence is High in the source ownership mapping and Medium in the unrun
test code. Assumptions are the exact accepted observer bytes, the existing
generated workflow format and the existing supported interpreter. A format
change may require test-adapter review; no permissive fallback is allowed.
Identity drift, helper execution before verification and Synthetic authority
overstatement are the main failure modes. Fixed identities, owned poison
sentinels and explicit outcome/origin assertions address them. Local runtime
duration remains unmeasured, with no hosted cost. Rollback removes these two
private diagnostic files. Root next reads every line, runs the initial focused
suite, obtains independent review, then separately authorizes runtime code.

Poteto-mode 0.9.102 and its Codex mapping were read. Architect Phase D keeps
this unit within the accepted loading design. Test Behavior, Not Implementation
keeps returned facts and pre-execution refusal effects as the assertions.
The explicit two-file/no-execution/no-delegation brief supersedes auxiliary
tracking, broader redesign and skill fan-out. No capture, native RED, replay,
Linux execution, protected adoption, deployment or readiness evidence follows.

## Two-helper capture handoff amendment, SPEC and tests only

26 October 2026, Europe/Berlin. The accepted capture handoff synthesis
`f7aee65667479f4d2466f14da25b83656f8396f23c6fbff84bfb41a899f7a42b`
and complete independent ACCEPT
`d307f39d014784d390867f84cdac7d492671abc2e192e569a801778f108bb6a1`
control this addition. The prior unit above remains the historical one-helper
acceptance. This amendment and the new test_capture_handoff.py specify the next
boundary. Existing test_bundle_loading.py and its six methods remain byte-exact.
No runtime helper, manifest, builder, driver, fixture, or owner changes now.

The eventual single no-argument `_load_helpers()` replaces the private
one-helper loader. It returns observation, replay, and immutable initialization.
One HELPER_MANIFEST admits exactly observation.py followed by replay.py, under
fixed `_dev786_original_replay_observation` and `_dev786_original_replay_replay`
identities. Exact reviewed length/hash values must cover both real source
bodies. The same manifest derives packaging membership, source identities,
bounded initialization reads, and counts. There is no independently maintained
helper authority, source override, compatibility loader, or empty replay module.

Both sources verify completely before either helper executes. Observation
registers and initializes first. Replay initializes second and uses that exact
observation class module. Either fixed module identity already present causes
refusal before either executes, even if it claims the expected path. A
BaseException before either helper body executes rolls back only registrations
owned by this call. It preserves unrelated modules and propagates interruption.
After the fault is disarmed, the actual valid loader must succeed in the same
child. A rejected or absent new loader is never counted as guard success.

The actual builder and emitted PY_DECODE still enforce the aggregate 262144-byte
decoded-source ceiling, complete compression envelope, safe closed membership,
exclusive creation, and exact reread verification. All nine original fixture
bytes and the old source-cap/PREFIX/SUFFIX/owner/constant oracles remain intact.
Changing a replay payload and its untrusted declared digest together must fail
against the one trusted table. A wrong second helper must refuse with zero
helper executions, proving verification is not interleaved with execution.
Ambient same-name files cannot replace either verified sibling. The loader adds
no sys.path entry and executes the same verified bytes under fixed filenames.

The new suite copies only real admitted sibling sources and the nine fixed
fixtures, invokes the actual builder, extracts its actual emitted transport and
decoder through the accepted test adapter, and calls the actual extracted
loader. It never creates replay.py to make collection succeed. Missing
`_load_helpers`, second membership, or new observation output produces an
explicit NEW-behavior assertion. Later guard and capture cases are then
unexercised, not passes or native RED. Test imports stay valid against the
current one-helper runtime.

The fixture-only loader tests and Synthetic inspector tests need no Linux
capture. The fixed real-control test requires later actual Linux execution and
has no default skip. Its test child uses original load_policy on the fixed
diagnostic worktree, supplies only already verified modules and an owned root
to Replay.open, and never calls actual, main, acquisition, or R preparation.
Its single harmless_controls invocation is shared read-only by the control
assertions. The child has private bounded output, a 330-second outer deadline,
and closed descriptors. Root must additionally enforce the 300-second inner
control limit and the whole-suite bound. The paired 61-second gaps stay in
untraced parent work. No test supplies credentials or copies a parent map.

Constructor/RawRef/embedded-child migration and an explicit preservation-test
amendment remain separately reviewed prerequisites for a runtime shape change.
The existing OWNER_SOURCE_SHA cannot be replaced to authorize actual/main
changes. Original Evidence, tool_facts, cleanup, and publish_safe bodies remain
fixed. This checkpoint grants no original replay, retrieval, publication,
signing, protected action, exception, cap increase, or authority transfer.

## Preservation migration amendment, SPEC and tests only

26 October 2026, Europe/Berlin. The six old bundle methods and their embedded
child now target the accepted actual two-helper boundary. This supersedes only
the preceding checkpoint's byte-freeze for those tests. It grants no runtime,
manifest, fixture, original owner or caller-body edit.

The test copier reads the one actual HELPER_MANIFEST from copied preflight
source, validates its fixed admitted names/module identities and each genuine
sibling's exact declared length/hash, and copies those real sources. It does
not fabricate replay.py or reject the current one-helper baseline in setup.
Individual tests explicitly require both observation.py and replay.py under
their fixed identities. The future table must contain both genuinely reviewed
source bodies. Historical observation length/hash are baseline evidence only,
not a replacement authority for a future source-body change. No independent
helper identity table or runtime compatibility route is introduced.

The embedded child calls only extracted _load_helpers(), requires observation,
replay and immutable initialization, and constructs the canonical Complete,
TraceAssociation, stream, CaptureEnd and Checkpoint inputs. Its complete and
malformed Synthetic outputs preserve every old literal assertion. RawRefs use
m-parent with the same trace.100 bytes/ranges/lines. The normal wait and cleanup
wire assertion moves to end. Empty diagnostics reference the one empty stderr.
The returned canonical raw store contains the exact trace and both empty
streams once. Helper execution now means exactly observation followed by replay
with both fixed registrations, exact file/spec origins, unchanged sys.path and
manifest-derived immutable initialization. An absent loader reports only
NEW_LOADER_UNAVAILABLE and fails the required positive assertion.

The actual builder, generated transport and PY_DECODE remain the tested path.
Their strict envelope, source cap, closed membership, reread verification,
all nine fixture literals/hashes, PREFIX/SUFFIX and old owner/constant pins
remain exact. Missing/renamed/extra/length/hash/symlink/directory/preload guards,
ambient poison, coherent self-rehashing and builder refusals apply to each real
helper after positive loading. Both preloads and both BaseException interruption
and rollback cases remain in test_capture_handoff.py. No source runs at the
author checkpoint.

OWNER_SOURCE_SHA remains exact, including actual and main. Evidence, tool_facts,
cleanup and publish_safe stay exact. Any later actual/main caller change still
requires its separate explicit preservation amendment and review. The existing
test adapter utilities remain available to the new suite without moving its
missing-NEW boundary into setup. Baseline failing assertions and all dominated
coverage must be reported separately from root's unchanged historical run.

## Prepaid initialization amendment, SPEC and tests only

26 October 2026, Europe/Berlin. The accounting SPEC amendment and independent
ACCEPT-for-SPEC-tests-only
`368dd2c0d725a6c54968012754ba3b660280df58891eb9dbe3912a0e55291f4e`
authorize only the coherent five-file test amendment. Both SPECs are frozen
before the first test edit. The prior one-helper runtime stays unchanged.

There is one HELPER_MANIFEST and one no-argument `_load_helpers`. Its fixed
order is observation.py then replay.py under the two existing fixed module
identities. One immutable InitializationReceipt uses the following exact
constructors. No second initializer or independent identity table is added.

```python
FixedHelperIdentity(name, byte_length, sha256, module_name)
ReadDebit(name, operation, requested_bytes, delivered_bytes)
InitializationReceipt(helper_identities, bounded_reads, measured_usage,
	conservative_debit, prepaid_envelope, adoption_reserved)
```

ReadDebit.operation is source-read, source-hash, source-submit,
identity-compare, order-compare, receipt-copy, directory-entry, or
adoption-compare. Bounded_reads is the immutable ordered itinerary. Requested
and delivered byte lengths are nonnegative scalar bounds, not inferred work
from a positive total. For a source of n bytes the loader prepays read(n+1),
records the actual n delivered bytes, hashes exactly those n bytes, and charges
the n-byte caller submission to compile. An actual additional source copy
costs its n bytes again. Identity/name/order comparisons, receipt construction,
and later adoption comparisons have explicit operand-length bounds. Their
actual visits are part of the measured total. Compiler-internal work is not
claimed or profiled by this caller-level debit.

Before helper source I/O, the loader installs its manifest-derived prepaid
plan against canonical fixed limits, real original holds, and the one closure.
Measured plus conservative usage and the unspent adoption allocation cannot
exceed that envelope in any coordinate. The envelope cannot be increased after
a read. Directory enumeration admits only closed root membership plus one
refusal entry. It cannot first materialize an unbounded directory list or set.
Unexpected entries refuse before helper execution. A missing or inconsistent
plan, wrong helper identity/order, excess read request, or impossible partition
refuses before a Replay session exists.

Both exact sources verify before either executes. Observation registers and
initializes first. Replay receives that exact observation module. BaseException
at either helper keeps the existing owned-registration rollback and unrelated
module preservation. The loader adds no sys.path entry or source/configuration
override. All old poison, preload, decoder, compression, source-cap, fixture,
PREFIX/SUFFIX, original-owner, and literal constant oracles remain unchanged.

The ordinary _Budget constructor adopts this real receipt once through the
same guard used by normal Replay.open. It spends the held adoption allocation
before the corresponding identity/order/receipt visits. The canonical adopted
receipt retains its original envelope and records those visits. Reuse stops
without renewing measured, conservative, file, or closure capacity. Synthetic
history validation is separately paid and cannot hide in a free constructor.
Tests may corrupt a copy of a genuine receipt only as explicitly Synthetic
diagnostic input. They do not invent a loader receipt or an operational fault
argument. Failed loader attempts cannot be pooled into another attempt.

The bundle child, parent, and control child project only the new Checkpoint
basis and coverage references as the accounting SPEC defines. Existing complete
and malformed facts, stream bytes, RawRefs, launch/wait/cleanup, and every
original literal oracle remain. Initialization assertions bind exact manifest
identities, requested/delivered read lengths, hash and submission lengths,
prepaid allocation, order, and one-time adoption. Source-bound observations
pair refused source work with an admitted real load. A bounded repeated real
inspection case detects recursive history and added payload copies in the new
wire references. None of these tests creates or executes a replacement helper.

All added methods first require the actual generated _load_helpers. Its current
absence is missing NEW behavior, with later guards unexercised. Authoring runs
no builder, candidate, collection, compiler, or test. Root owns the one changed
boundary run, raw evidence review, and fresh independent test acceptance.
No runtime, actual/main, old Evidence/tool_facts/cleanup/exporter, long clock,
genuine R, original C/M/R, native RED, deployment, readiness, or renewed grant
is part of this amendment.

## Runtime directory-work clarification, SPEC and tests only

26 October 2026, Europe/Berlin. The runtime review's directory finding applies
the existing prepaid admission rule at the OS boundary. With four closed root
names, directory admission may visit at most five entries, including refusal,
even when the owned test root contains eight additional unexpected files.
An eager OS directory list counts every returned name when materialized.
A lazy iterator counts every entry actually requested. Limiting later Path
yields cannot hide earlier directory work. Admission precedes each next visit.

The focused regression delegates to the real `os.listdir` and `os.scandir`,
returns their actual values or entries unchanged, and records both kinds of
work. It requires a real valid load first, then bounded refusal with no helper
execution, no leaked owned registration, unchanged unrelated registrations,
and unchanged `sys.path`. It prescribes no replacement enumeration API.
Both exact helper sources must still verify before either body executes.
The one manifest, nine fixtures, 262144-byte source cap, and all 45 existing
test methods and oracles remain unchanged. The existing loader child's
directory observer may delegate to Path iteration or OS scandir. Nested
enumeration records an entry once, while the independent OS-work regression
still counts eager materialization. Its wrapper preserves actual entries,
context exit, closure, and BaseException propagation. Root owns failing-before
execution and fresh review of this narrow observer change.
