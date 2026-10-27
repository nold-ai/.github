# Linux diagnostic operator contract

TL;DR. One fixed operator runs the complete suite once in an ephemeral Linux job. Tests own one shared actual attempt and two real gaps. Implementation, publication, and execution remain closed.

27 October 2026, Europe/Berlin. Selected synthesis SHA256 is `76fa4dabab24b35557645febae4a1241e6cc1a778db7e196c51b1c245ce30af3`.

## Caller and source identity

The caller invokes `/usr/bin/python3 -I -S -B .github/development/dev786_linux_qualification/qualify.py`. Its sole `main()` accepts no options, configuration, fault selectors, or alternate launch interface. It imports no policy, preflight, or helpers.

The repository is `nold-ai/.github`, repository ID `1110267669`, owner ID `225190663`. Candidate commit Q must have sole parent `640549e62fb3ca001499e71d4cf935aa8c0a0192`, whose tree is `2d27c800651b3e1b30d46078594a61937410f4cc`. Core dev C is not this parent. The preparation branch is `codex/dev786-linux-qualification-operator-02`. Later publication creates only the absent `refs/heads/codex/dev786-linux-qualification-20261027-02`, after fresh main and destination checks, with exact readback afterward. Drift or uncertain creation stops without retry or overwrite.

Q admits unchanged reviewed diagnostic sources and five operator files. These are this SPEC, `test_qualify.py`, derived `inputs.json`, `qualify.py`, and `.github/workflows/dev786-linux-qualification.yml`. Other base bytes remain identical. Inputs derive from the accepted 18-file freeze, including nine fixtures, and ten literal policy pins. An external root receipt binds Q, tree, workflow, actions, and operator without self-referential hashes.

Current accepted source commit `6b56f474c2e07677c4faf333c74be48fc67bb950` has 18 files totaling 501,554 bytes and manifest SHA256 `160dc0682e04d5d3b8db02c2b3dbd8cb7c436fca9d0454a72e5230b763d94eab`. It preserves all 49 methods, the original 45 and four added regressions. Root receipts `operator02-preparation/assembly.json` and `composed-fixture-source-delivery-measurement.json` bind this preparation and inert measurement. Operational payload is 200,932 bytes, SHA256 `ccb184bafb257c6d9e0dd9dd49fe78625edf695f40d727a0d7bfb3edef6a2a4d`, before specialization and 200,958 bytes, SHA256 `9a57ec7e7c47fe0f6cdefdda97a36e055fe69c53daebd351486540c59324d377`, after the 26-byte substitution. Tests and policies remain outside the operational decoder's unchanged 262,144-byte ceiling.

The earlier freeze `9bee27a1d6179d434d3b1d62bcf931de2f797b51392728658588a39d03b38183`, preflight sizes 74,244 and 74,270 bytes, and payload 199,983 bytes are historical measurements, not current source identities. Corrections require refreshed identities, method IDs, count, helper manifest, sizes, delivery measurement, cap checks, and independent acceptance. Published Q01 and its failed run remain immutable and consumed. The new Q02 commit is not yet known; prior review and execution do not qualify it.

## One bounded job

Only the exact branch-created push starts the job. Require expected repository, owner, ref, workflow, zero previous SHA, non-deletion, and attempt 1. Exclude dispatch, matrix, rerun, and reusable entry. Review all base triggers before publication.

Use Ubuntu 24.04 x86_64 and `contents: read`. Checkout exact `github.sha`, detached, depth 2, without LFS, submodules, or persisted credentials. Review actual checkout `df4cb1c069e1874edd31b4311f1884172cec0e10`, upload `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a`, and their inputs. Require existing `/usr/bin/python3` reporting 3.12, `/usr/bin/strace`, and `/bin/sh`. Install nothing. Record full bounded versions, strace help, before-and-after binary hashes, Git version, kernel, architecture, ImageOS, and ImageVersion. Mutable labels prove no immutable image identity.

The operator's clean environment admits only fixed paths, locale, input location, and metadata for repository, owner, ref, SHA, workflow, event, run ID, attempt, and image labels. Event admission checks creation and deletion fields. The suite receives only private mode-0700 HOME and TMPDIR, PATH `/usr/bin:/bin`, LC_ALL `C.UTF-8`, and absolute DEV786_PREFLIGHT_INPUTS pointing to SOURCE. Its cwd is private. No GH_TOKEN, secrets mapping, ambient credentials, or environment dump is allowed. Stdin is DEVNULL, descriptors are closed, passed descriptors are empty, and the child starts a new session.

Run exactly `/usr/bin/python3 -I -S -B -m unittest discover -s SOURCE -p test_*.py -v`. SOURCE preserves sibling helpers, tests, and policy layout. Exclude generated materialization YAML, preflight main, and acquisition.

| Boundary | Maximum |
| --- | --- |
| Job; checkout; diagnostic; upload; finalization | 1200; 180; 840; 120; 30 seconds |
| Probes within diagnostic | 30 seconds combined, 5 each, 64 KiB per stream |
| Suite; failure cleanup; evidence work | 600; 5+5+5; 90 seconds within diagnostic |
| Suite stdout and stderr | 1 MiB each |
| Tracked checkout; operator additions; Git storage | 64 regular files and 2 MiB; 128 KiB; 32 MiB post-check |

Steps total 1170 seconds. Git storage is a post-check, not an atomic quota. Reject symlinks, gitlinks, unknown deltas, and tree, index, source, or tool drift.

Preserve the 330-second controls child, 300-second combined controls, two untraced gaps of at least 61 seconds, 30-second traced children, and existing cleanup envelopes. Preserve CPU 240 seconds, address space 2 GiB, file size 256 MiB, NPROC 128, core zero, and all source, read, count, retention, receipt, export, and clock caps. No renewal or clock substitution is allowed.

## Complete evidence and truthful outcomes

Discover exactly one real `dev786-capture-tests-[A-Za-z0-9_-]{1,32}` root through at most 64 immediate TMPDIR entries. Examine at most 512 class-root entries and require one `[0-9]{3}-actual-controls` directory. Never follow stderr paths. Derive closed case names and membership inertly from reviewed source.

The complete attempt has exactly five fixed members, `home`, `tmp`, `stdout`, `stderr`, and `owned`. Enumerate within six local iterator slots, including the closing probe. The parent opens both streams and creates mode-0700 `home` and `tmp`; the child creates `owned` only when reached. Validate present `home` and `tmp` as real directories using anchored, no-follow metadata only. Never traverse them, open or read their payloads, or export their names, contents, or derived data. Unknown attempt siblings, links, and wrong member types prevent qualification. These six local slots do not expand any global cap.

A failed child may leave partial or missing members, including absent `owned`. Retain every available safe bounded actual stdout and stderr, including empty streams and nonempty failure stderr, without requiring complete positive evidence. Missing required members, including `home` or `tmp`, or partial evidence remains INCOMPLETE and nonzero, even if suite output claims success. A complete five-member layout alone cannot qualify failed controls or substitute for both real gaps.

Retain `meta/{source-before,source-after,checkout,tools-before,tools-after,context,selection,result,cleanup,files}.json`, suite and actual-control stdout and stderr, bounded probe output, and exact `control_child.py`. Twelve fixed control directories admit only `control.sh`, `pid`, `stdout`, `stderr`, the source-defined harmless marker replacing stdout for withhold-name, and decimal `trace.<pid>`. Both fixed `read-gap-before-evidence` and `read-gap-after-evidence` roots admit only `commands.jsonl`, `raw-output.bin`, `manifest.json`, and `environments.json`. Preserve empty files. Exclude loader copies, source copies, homes, and unrelated temporary trees.

| Evidence class | Per-file maximum |
| --- | --- |
| Metadata; file inventory | 64 KiB; 128 KiB |
| Raw streams; probe streams; control child | 1 MiB; 64 KiB; 16 KiB |
| Control script; PID; numeric trace | 4 KiB; 64 bytes; 2 MiB |
| Clock manifest; environments | 512 KiB; 64 KiB |

Clock commands and raw output together permit at most 2 MiB per evidence root. Require at most 32 entries per control directory and 16 numeric traces per case. Global export and root extraction limits dominate every class allowance. Both permit at most 128 regular files, 64 MiB, and 320 directory entries. ZIP is at most 68 MiB, logs 8 MiB, and API evidence 2 MiB across 20 files. Unknown, missing, changing, linked, special, or over-cap files prevent success. Use anchored no-follow opens, single-link regular files, stable descriptor and path metadata, and complete bounded hash-copy verification.

Upload only the private export as `dev786-linux-qualification-RUN_ID-1`, with seven-day retention, including available bounded failure evidence. Missing export, partial bytes, or truncated logs cannot pass. Reap only the verified owned suite child. Retain OS-backed ownership until the last signal or refuse signaling and report INCOMPLETE. Nested new sessions remain the existing tests' and runtime's responsibility. Outer termination means INCOMPLETE. Hosted teardown supplies containment, never cleanup proof.

REFUSED means admission stopped before tests. FAILED means test or operational failure, always nonzero. INCOMPLETE means required evidence or cleanup is unproved, always nonzero. QUALIFIED_PENDING_REVIEW requires every derived test ID, zero failures, errors, and skips, one shared actual attempt, both real gaps, unchanged identities, complete raw evidence, and cleanup receipts. Root independently rereads remote Q and its full closure, authenticates workflow, run, attempt, actor, job, artifact ID, size, available digest, downloaded ZIP, and file hashes, then reads all raw evidence. An absent API digest remains absent.

## Required future test matrix and gates

| Test family | Required observable proof |
| --- | --- |
| Admission | Wrong context, repository, ref, attempt, non-creation, hash, file type, drift, or cap refuses before suite launch. |
| Child lifetime | Real bounded owned children prove output and deadline failure, reaping, failure evidence, and honest nested-session uncertainty. |
| Identity | Before-and-after source and tool changes prevent success. |
| Export | A faithful five-member attempt preserves the closed export. Private home/tmp sentinels are never traversed, opened, read, or exported. Unknown siblings, home/tmp links or wrong types, and missing, unstable, or over-cap evidence prevent qualification. Failed partial or absent owned evidence still retains bounded actual streams. Arbitrary stderr paths cannot select files. |
| Suite and retrieval | Derived IDs include all current regressions. The shared attempt, two real gaps, and authenticated root readback remain mandatory. |

Synthetic fixtures and safe OS-boundary adapters grant no CI provenance. Spec-first tests must explicitly assert missing NEW functionality. ImportError, skips, or expected failure cannot substitute. Code and types follow separately.

RUNTIME01, RUNTIME02, and RUNTIME04 need independent acceptance. RUNTIME03 has no Linux failing-before proof. Darwin's resource refusal reached no gap and proves no timer failure. After the other corrections pass review, a proposed first whole-suite Linux job may collect the clock failure through this same entry. Its nonzero result remains FAILED. Exact source, workflow, action, ordinary publication, authorization, and safety review remain prerequisites. Full qualification requires the subsequent clock correction and fresh complete green evidence.

Ordinary auxiliary authority grants no protected adoption, release-signature credit, signing override, or consumed-intent reuse. Applied verified-commit rules require concrete reviewed CI mechanics. Protected workflow, origin, index, caller, and consumer adoption remain separate owner decisions. No force push, canonical R change, merge, package publication, waiver, or exception follows.

Confidence is High in the boundaries and Medium in unmeasured Linux fit. Layout or permission changes require review. Tool mismatch, overflow, and uncertain cleanup fail closed. One job takes at least 122 seconds plus work and at most 20 minutes. Billing is unknown. Rollback concerns verified task-owned branch, run, and artifact identities after evidence retention. Root reviews this SPEC next. Tests, runtime, publication, execution, and final acceptance remain closed.
