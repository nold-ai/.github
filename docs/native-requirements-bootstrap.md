# Native Requirements bootstrap contract

TL;DR. This unit validates one RED operation context and verifies five local tool files. Its fixtures, receipts, and unit-test passes establish neither protected deployment nor native evidence acceptance.

Recorded on 2026-10-26 Europe/Berlin. The selected design separates the proof tools from the subject dependency graph. It retains the existing native planner, executor, reconciliation, and provenance algorithms. This document specifies that design and the smaller first implementation unit. Preparation authority does not authorize protected deployment.

## Identities and fixed scope

The private frozen `Scope` owns the following values. Inputs cannot replace them.

| Role | Fixed value |
| --- | --- |
| Core repository and numeric ID | `nold-ai/specfact-cli`, `1085706003` |
| Policy repository and numeric ID | `nold-ai/.github`, `1110267669` |
| Repository owner and numeric ID | `nold-ai`, `225190663` |
| Pull request, base, and subject branch | `786`, `dev`, `codex/security-dependencies-0-55-11-dev` |
| Proof base C | `9b5ad1e78430cc0b061cb16de42f73de96f4f312` |
| Unchanged core main | `5262efb0881e4fac7697d629b0530250342bc656` |
| Immutable RED subject R and tree | `4ae6175a4d337296d0347e73b66c9da1f0e43f7f`, `baeb88acf0d2a5015810ad12dbfccfa7fdf9a21e` |
| Module M and tree | `69f075819be5e1ceca1446b026b0417f19e584ca`, `5d0b8e66c6cd467e6b1ad9d582e24c66b907e205` |
| Original fifteen-case mapping SHA256 | `7025a000601cc44c1a1e6168367f2188681471d68ea5f044cfc81a94b734f8ff` |
| Original plan SHA256 | `dc90453d191b282ba5e47127bf067ee23b475072d7e94a0859c7c6a26677ce3a` |
| Approved operator and numeric ID | `djm81`, `39115308` |
| Auxiliary caller branch | `codex/security-dev-native-red` |
| Caller workflow path | `.github/workflows/specfact.yml` |
| Reusable workflow path | `.github/workflows/native-requirements-bootstrap.yml` |
| Exclusive expiry | `2026-11-04T23:00:00Z`, equivalent to 2026-11-05 00:00 Europe/Berlin |

E identifies the immutable auxiliary caller commit in core. P identifies the immutable reusable workflow and tool revision in policy. Both are full lowercase hexadecimal Git SHAs and remain distinct from C and R and from each other. F is a future final subject and must be a strict descendant of R. F is outside this unit. Neither E nor P belongs in the C-to-R-to-F subject ancestry. The fixture E, P, and run ID are synthetic context-unit data.

## First-unit interfaces

```python
authorize_red_context(expected_policy: str, snapshot: Mapping[str, object], now: datetime) -> AuthorizedRedContext
verify_tool_files(directory: Path, expected_manifest_sha256: str) -> VerifiedToolFiles
```

Both functions refuse with `ValueError` when their contract is violated. Unexpected objects, missing required values, and malformed nested structures also refuse. No partially authorized result is returned. Test-first commit `8a638e1d0f30f58e7ec9c408b352fa8b6e9e07cf` declared both boundaries and the private canonical caller generator with `NotImplementedError` bodies. Independent contract acceptance and 447 observed scaffold failures preceded the validation implementation.

`AuthorizedRedContext` is a frozen record containing the fixed repository names and IDs, owner ID, PR, base ref, subject branch, C, unchanged main, R and tree, M and tree, mapping and plan digests, E, P, run ID, attempt, operator name and ID, and expiry. Its `policy_commit` names the independently selected P declared by the caller bytes, not an authenticated executing reusable job or signer. It contains only immutable values. `VerifiedToolFiles` is a frozen record containing the resolved directory, raw manifest SHA256, and a filename-sorted tuple of four `(name, sha256)` pairs. It grants no tool-deployment authority and contains no install command or source override.

### Context snapshot

The snapshot has exactly these top-level keys. Raw GitHub response objects may contain extra API fields. Their required fields below retain GitHub's actual structure and types.

| Key | Required content |
| --- | --- |
| `runtime` | The exact runtime mapping below. |
| `repository` | Core repository API object. `id`, `name`, `full_name`, and `owner.login`, `owner.id`, `owner.type` bind the fixed core identity and organization owner. |
| `policy_repository` | The corresponding fixed policy repository API object with `default_branch` equal to `main`. |
| `pull_request` | `number=786`, `state=open`, `merged=false`, `merged_at=null`. `base.ref=dev`, `base.sha=C`, `head.ref` equals the subject branch, and `head.sha=R`. Both `base.repo` and `head.repo` bind the complete core repository identity. |
| `red_commit` | Git commit object with `sha=R`, `tree.sha` equal to the RED tree, and `parents` containing exactly one object with `sha=C`. `verification.verified=true`, `verification.reason=valid`, and nonblank string `signature` and `payload` are required. |
| `dev_ref`, `main_ref` | Git ref objects. `ref` is respectively `refs/heads/dev` or `refs/heads/main`. `object.type=commit` and `object.sha` equals C or the fixed unchanged main. |
| `caller_run` | Workflow-run API object with strict positive integer `id`, `run_attempt=1`, one of the exact `path` forms below, `event=workflow_dispatch`, auxiliary `head_branch`, `head_sha=E`, and `status=in_progress`. `repository` and `head_repository` bind core. `actor` and `triggering_actor` each bind `login=djm81`, `id=39115308`, and `type=User`. |
| `caller_workflow_bytes` | Bytes equal to the canonical caller below, including its final LF. Text strings, alternate serialization, and extra workflow content refuse. |
| `policy_compare` | Comparison API object fetched for P against protected policy `main`. `base_commit.sha=P`, `merge_base_commit.sha=P`, and `status` is `identical` or `ahead`. A declared `deployed` flag is insufficient. |
| `actor_permission` | Live collaborator-permission API object. `permission` is `write` or `admin`. `user` binds the same fixed login, numeric ID, and `type=User`. |

`runtime` contains exactly `GITHUB_ACTIONS` and the following GitHub context fields. Every value is a string. `GITHUB_ACTIONS` is `true`. `event_name` is `workflow_dispatch`. `repository`, `repository_id`, `repository_owner`, and `repository_owner_id` bind core and its owner. `sha` is E. `ref` is `refs/heads/codex/security-dev-native-red`. `workflow_ref` is `nold-ai/specfact-cli/.github/workflows/specfact.yml@refs/heads/codex/security-dev-native-red`. `workflow_sha` is E. `run_id` is the canonical decimal form of the API run ID. `run_attempt` is `1`. `actor`, `triggering_actor`, and `actor_id` bind `djm81`, `djm81`, and `39115308`. The triggering actor's numeric ID comes from `caller_run.triggering_actor.id`; no invented triggering-actor-ID context is used.

`job_workflow_ref` and `job_workflow_sha` are OIDC claims, not GitHub context properties. Neither belongs in this closed runtime mapping; either supplied as an extra key refuses. This unit neither requests OIDC nor synthesizes job claims from caller bytes. Actual reusable-job P and signer authentication remain a separate unmet signed-origin gate.

Raw `caller_run.path` accepts exactly `.github/workflows/specfact.yml`, `.github/workflows/specfact.yml@codex/security-dev-native-red`, or `.github/workflows/specfact.yml@refs/heads/codex/security-dev-native-red`. All three bind the same fixed auxiliary branch through the other run and runtime fields. Other workflows or branches, `@main`, empty or double suffixes, and malformed ref suffixes refuse; arbitrary `@` stripping is forbidden. The eventual dispatch transport still requires authenticated integration evidence. Root's recorded run `40249047542` supplies bare-path evidence only, not dispatch or reusable-execution proof.

API integer fields reject booleans, floats, and strings. Boolean fields require actual booleans. SHA fields require exactly forty lowercase hexadecimal characters before equality checks. Runtime numeric strings use canonical positive decimal syntax and must equal their API counterparts. `now` must be a timezone-aware `datetime` and strictly earlier than the fixed expiry. The exact expiry and any later time refuse. An equivalent timezone-aware instant accepts.

This pure context boundary assumes an eventual protected adapter obtains fresh authenticated GitHub responses from fixed core and policy endpoints. It does not prove that user-provided Python mappings came from GitHub. The adapter must obtain `expected_policy` from authenticated protected policy selection, fetch `compare/P...main` from the fixed policy repository, and fetch the exact canonical caller bytes from the fixed workflow path at E. P must be a deployed ancestor and equal the P declared by those bytes. A caller-supplied P and fabricated comparison are not deployment proof. That acquisition, replay/freshness protection, and protected selection remain future acceptance work.

### Canonical caller bytes

One private generator owns this exact UTF-8 template and later caller generation. Only P is substituted. R and the workflow identity remain fixed. The caller grants the minimal read permissions for this context unit. Future OIDC or attestation permissions require separate review and integration proof.

```yaml
name: Native Requirements RED
on:
  workflow_dispatch:
permissions:
  contents: read
  actions: read
jobs:
  native-red:
    uses: nold-ai/.github/.github/workflows/native-requirements-bootstrap.yml@P
    with:
      red_commit: 4ae6175a4d337296d0347e73b66c9da1f0e43f7f
```

The caller has no additional jobs, steps, secrets, environment, mutable workflow ref, or arbitrary subject argument. E identifies the commit containing these bytes, independently of P. Neither commit SHA is calculated as a self-referential hash of its own value embedded in the caller.

### Tool files

The directory itself must be an existing directory rather than a symlink. Its exact entries are regular nonsymlink files `requirements.in`, `locked.txt`, `build-requirements.in`, `build-locked.txt`, and `tool-files.json`. No directories, additional entries, or special files are allowed. Each input contains 1 through 4,194,304 bytes. The manifest contains 1 through 16,384 bytes. Regular-file type and inclusive size limits must be checked before opening either boundary file for reading. FIFOs, including a no-writer FIFO, and other nonregular files refuse before reading. Oversized regular inputs and manifests refuse without opening their content.

`expected_manifest_sha256` is an independently supplied lowercase hexadecimal SHA256 digest. The verifier hashes the raw manifest bytes and compares them before JSON interpretation. A digest mismatch reports `tool files rejected: manifest digest mismatch`, including when the unauthenticated bytes are invalid JSON. The UTF-8 JSON object has exactly `schema_version` and `files`. `schema_version` is integer 1 and rejects a boolean. `files` has exactly the four input filenames and one lowercase hexadecimal SHA256 digest per file. Duplicate keys at either object level, malformed JSON or UTF-8, unknown keys, wrong types, missing or extra names, absolute paths, and path traversal refuse. Every file must match its recorded digest. Alternate manifest whitespace is permitted only when its exact raw digest was independently supplied.

The eventual expected manifest digest must come from authenticated protected P. It must never come from candidate content or the manifest itself. This unit neither parses lock requirements nor installs packages. Success binds bytes observed during verification; it does not make directory paths immutable. Future materialization must consume authenticated bytes without a check-to-use substitution and must not treat this receipt as permanent path authority.

## Remaining acceptance gates

The complete selected design uses a core-hosted create-only auxiliary caller E and an immutable organization reusable workflow P. Runs and artifacts remain in core. One protected tool owner supplies the reviewed closure and sources from C and M. The existing executor uses that environment's interpreter. No new planner, executor, reconciler, or provenance algorithm is introduced.

This unit deliberately leaves these gates unimplemented.

1. Derive, compile, hash-pin, audit, and license the complete runtime and isolated build closures. Preserve the actual failed wheel-only resolution for `commentjson 0.9.0`. Exercise the actual C/M CLI, signature verification, planner, executor, reconciliation, and provenance in clean environments. Local integration does not establish protected deployment or native CI origin.
2. Implement the protected adapter for fresh runtime and API acquisition, exact source and closure selection, and immutable source verification. Independently review the helper, workflow, caller, and all closure bytes. Run ordinary policy hooks and required CI. No new credentials or repository access follow from this design.
3. Present the exact reviewed policy revision, workflow and script bytes, manifest and closure hashes, C/M/R scope, origin and adoption delta, and expiry for a separate protected-deployment owner decision. Existing ordinary authority comments, previous grants, successful unit tests, and immutable SHAs do not grant this authority.
4. After legitimate deployment, execute R through unchanged C/M native semantics. Require all original fifteen selectors to fail as assertions, with no errors, skips, collection failures, passes, or missing cases. Retain original native report, plan, JUnit, provenance, and signed CI origin. Preserve the intentional failed RED job status. Authenticate actual artifact bytes, repository, ID, digest, run, attempt, E, P, and R independently. Context authorization alone accepts none of these artifacts.
5. Validate the exact core adoption against the active security change's explicit bootstrap dependency before editing core. Preserve the original mapping and plan and the single changed active core change root. Independently authenticate the new explicit dispatch source in producer, fresh execution, and final consumer while preserving ordinary PR source authentication. E remains the run head and R remains the proof subject.
6. Only after accepted genuine RED, append the approved security production changes and corrected companion graph test with CI signing. Require C-to-R-to-F ancestry, unchanged tests and imports, exact final head authority, module and Git signatures, plugin isolation, and all three strict final subject audits. Run fresh execution and final native reconciliation using the same fifteen-case plan and authenticated prior RED. No merge is authorized by this unit.

Ordinary authority, original native provenance and history guards, final subject trust checks, and the official core 0.55.11 graph remain separate requirements. MCP and OpenTelemetry limits remain inclusive through 2026-11-04. No missing-RED admission, waiver, exception renewal, bypass, local signing, publication, or deployment is proposed here.

## Evidence and limits

The tests specify exact frozen positive outputs, all three permitted run-path forms, permitted raw API extras, and bounded negative mutations of identities, permissions, ancestor comparison, expiry, canonical workflow bytes, and file boundaries. Equal-valued float and string controls cover every API numeric identity. Coordinated malformed P values must refuse even when the selected value, comparison, and canonical caller bytes agree. No-writer FIFO controls use bounded child-process termination and require explicit `ValueError` refusal. Oversized-file controls install a child-local audit hook that refuses opening the oversized path, making pre-read refusal observable without importing a private validator helper. These child processes execute only this local file boundary.

Local verification of this first unit on 2026-10-26 recorded 447 passing contract cases after implementation. The complete policy suite at that checkpoint recorded 711 passes, zero failures, zero errors, and zero skips in the existing five-package hashed test environment on local CPython 3.12.13. Independent runtime review accepted the bounded implementation. These local unit results do not establish native RED, GREEN, authenticated CI origin, source adoption, or deployment.

Design inputs were read locally on 2026-10-26 Europe/Berlin. They are the coordinator's `native-prerequisite-synthesis.md`, the independent `native-prerequisite-judge.md`, all three candidate reports, `how-synthesis.md`, and `admission-flow/findings.md`. This unit does not refresh their live-state claims. GitHub's documented [reusable workflow permissions](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations), [reusable OIDC identity](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-with-reusable-workflows), and [contexts](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts) were verified by the coordinator on 2026-10-26, rather than independently fetched for this unit.

Confidence is High in this bounded contract's recorded identities and Medium in the future route pending closure, protected deployment, and origin integration proof. Assumptions that could change the route are unchanged dev and main, unchanged live PR and operator permissions, and effective caller permissions for the eventual origin mechanism. Incomplete closure can cause setup errors, so clean native entry-point execution is mandatory. Confused E/P/R identities can accept foreign evidence, so each role needs independent mutation and integration tests. Scope expansion can change the proof obligation, so mapping, plan, and core adoption require separate review. Preparation effort is medium with no elapsed-time claim. Before deployment, rollback is abandonment of the unmerged candidate with evidence retained. After separately authorized deployment, rollback requires an ordinary reviewed policy revert and invalidation of affected proof.

The next work is authenticated acquisition, immutable source and tool materialization, the workflow and origin route, and consumer integration. Required policy CI and independent review must cover that concrete candidate before a separate protected-deployment decision. Protected deployment and native acceptance remain closed.
