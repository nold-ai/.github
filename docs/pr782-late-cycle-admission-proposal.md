# Proposed PR782 late-cycle admission contract, inactive

TL;DR. This documentation proposal issues zero admissions. Core Requirements remains red and PR782 is not deployment ready. Approval of this proposal or its PR does not activate the capability or approve a provenance exception.

Recorded on 2026-10-21, Europe/Berlin. This is a proposed contract for later review, not executable policy. The current PR782 decision remains `REFUSED` because distinct late-cycle approval, protected activation, and core integration are absent.

## Scope and current evidence

The proposed exception covers only `native-failing-first-provenance` for `nold-ai/specfact-cli`, issue 780, PR782, change `isolate-semgrep-security-runtime`, targeting `dev`. It covers the exact subject, official-package evidence, and eleven selectors below. No other requirement, PR, dependency exception, or future head inherits it. The Semgrep fork remains rejected.

The evidence snapshot is `policy-current-evidence.json`, inspected on 2026-10-21. The table records exact bindings, not an admission. Future trusted collection must independently verify these values against GitHub metadata and downloaded artifact bytes.

| Binding | Exact value |
| --- | --- |
| Head branch | `hotfix/isolate-semgrep-security-runtime` |
| Head commit | `0262dbe5c0c18a7bd0777c5980d6b3539153c1e8` |
| Head tree | `94c45ef0bd78dd72d20ed2f4c8aec95c013fc14f` |
| Native run ID | `39573899378` |
| Native run attempt | `1` |
| Workflow path | `.github/workflows/requirements-evidence.yml` |
| Artifact ID | `12333845639` |
| Artifact ZIP SHA-256 | `sha256:e9089bd9cec01095c5a9dab7bb181d1bc77c70848e01937ba090165456187de3` |
| Source mapping SHA-256 | `sha256:9be3a10b220655e55c299b9b3d69c2be0c0b029b1db1c0942abfea1ea6c4f86d` |
| Aggregate mapping SHA-256 | `sha256:78c37231304235071346e3149c8411d95b975490d9e5fc11fc5cae0993652a6a` |
| Plan SHA-256 | `sha256:442b1a680db260844eac64620c380480d161ed8c60363d1a3925c64c1577161a` |
| requirements-evidence.json SHA-256 | `sha256:1876cf2ccf08c9e1fac7b0d24bedd4e7bc6dec9de8e04c3f62ae0844e6246842` |
| requirements-evidence-plan.json SHA-256 | `sha256:32d0e326c760f64eaf4cda3b0a56318b27a0d874ba0e38b243302ab8b4cc3225` |
| requirements-proof.xml SHA-256 | `sha256:227d2420449346d96332ae760d566304adc470d8940db339527f52dd947ac2be` |

The native test inventory has eleven PASS results. The raw report still records `verdict=failed`, `gate_decision=fail`, `delivery_status=incomplete`, `observed_maturity=incomplete`, and `implementation_evidence=not-available`. Its sole finding is `prior-red-proof-invalid`. A passing selector, local RED log, or failed provenance assessment cannot become native failing-first evidence. No original report or verdict is rewritten.

| Bound native selector | Observed result |
| --- | --- |
| `tests/unit/scripts/test_security_audit_gate.py::test_committed_mcp_exception_is_exact_and_time_bounded[exact-cve]` | PASS |
| `tests/unit/scripts/test_security_audit_gate.py::test_committed_mcp_exception_is_exact_and_time_bounded[exact-ghsa]` | PASS |
| `tests/unit/scripts/test_security_audit_gate.py::test_committed_mcp_exception_is_exact_and_time_bounded[expired]` | PASS |
| `tests/unit/scripts/test_security_audit_gate.py::test_committed_mcp_exception_is_exact_and_time_bounded[expiry-day]` | PASS |
| `tests/unit/scripts/test_security_audit_gate.py::test_committed_mcp_exception_is_exact_and_time_bounded[future-review]` | PASS |
| `tests/unit/scripts/test_security_audit_gate.py::test_committed_mcp_exception_is_exact_and_time_bounded[mixed-advisories]` | PASS |
| `tests/unit/security/test_release_promotion_security_gates.py::test_frozen_graph_uses_official_semgrep_with_bounded_mcp_exception` | PASS |
| `tests/unit/scripts/test_security_audit_gate.py::test_committed_mcp_exception_is_exact_and_time_bounded[other-version]` | PASS |
| `tests/unit/scripts/test_security_audit_gate.py::test_committed_mcp_exception_is_exact_and_time_bounded[skipped]` | PASS |
| `tests/unit/scripts/test_security_audit_gate.py::test_committed_mcp_exception_is_exact_and_time_bounded[unrelated-advisory]` | PASS |
| `tests/unit/security/test_frozen_dependency_artifacts.py::test_frozen_certifi_bundle_excludes_compromised_root` | PASS |

Generic exact-head authority has separate approval, canonical comment [6312284782](https://github.com/nold-ai/specfact-cli/pull/782#issuecomment-6312284782), and a successful required check. That authority grants no late-cycle provenance exception. The MCP advisory exception also grants no provenance exception.

## Proposed separate capability

The capability name is `late-cycle-provenance-admission`. Its distinct canonical approval header is `SPECFACT_LATE_CYCLE_PROVENANCE_ADMISSION_V1`. Both names are proposed and inactive.

A later protected consumer may distinguish three outcomes. `NativeProvenance` requires actual valid native failing-first proof. `HumanApprovedLateCycle` records an explicitly approved absence of that proof. `Refused` leaves the requirement unsatisfied. `HumanApprovedLateCycle` must never report `failing-first-proven`, native RED, or successful native provenance.

The future authority evaluates one canonical request against independently authenticated observations. A local JSON document, copied receipt, proposal approval, or generic authority result cannot establish admission. Unknown, duplicate, malformed, incomplete, or noncanonical request fields cause refusal. Input bounds and the canonical encoding must be specified before implementation.

The signable request must bind all of these fields:

- Repository, issue, PR, change ID, base ref, head branch, full head commit, and full tree ID.
- The single provenance obligation and the complete eleven-selector inventory above.
- Exact immutable policy revision and producer workflow identity and revision.
- Native run ID and attempt, artifact ID, ZIP digest, raw report digest, raw plan digest, and JUnit digest.
- Source mapping, aggregate mapping, and plan digests, including their distinct meanings in the evidence table.
- `missing_native_red=true`, issuance time, and expiry time in UTC.

The table records the live API branch, run attempt, and workflow path. It does not establish the exact executed producer workflow revision or authenticated receipt format. Those unresolved bindings prevent this document from being a signable request. No placeholder or abbreviated object ID is acceptable at issuance.

The human must separately approve the final canonical request digest after the complete request and contract are reviewable. The approval must expressly acknowledge missing valid native failing-first proof. The immutable collector must verify an unedited canonical comment, matching author, exactly one applicable approval, and live write or admin permission. Deleted, edited, ambiguous, expired, or unverifiable approval causes refusal.

The approval and request expire no later than the existing seven-day limit from comment creation. The effective expiry is the earlier bound. Admission requires the exact approved head and tree and valid expiry at evaluation and consumption. This proposal invents no separate maximum test age. Any additional age limit requires explicit policy review before activation.

The protected collector must independently verify repository and PR association, workflow identity and revision, run attempt, artifact identity, digests, and correspondence to the exact approved head and tree. Historical runs remain historical context. Fresh evidence must cover every bound selector with no skipped or missing tests. Any failure beyond the named provenance obligation causes refusal. A failed aggregate run caused solely by missing native RED remains recorded as failed.

## Ownership and activation dependencies

This preparatory PR contains this file only. It changes no workflow, Python module, core consumer, check name, required gate, or active receipt. It claims no implementation, executable fixture coverage, or TDD evidence.

A later protected policy implementation owns canonical parsing, authenticated GitHub collection, exact evidence matching, human approval validation, expiry, and protected publication. One proposed stdlib module, `.github/scripts/late_cycle_provenance_admission.py`, owns that domain. A thin immutable workflow adapter owns invocation and publication. The existing generic authority retains its present capability and semantics.

Core Requirements owns consumption and presentation of `HumanApprovedLateCycle`. Core must verify protected origin, exact subject and evidence, policy revision, expiry, and the distinct capability before admission. PR-controlled code or evidence cannot issue a trusted receipt. No caller-provided URL, arbitrary host, shell command, or import path belongs in the request. Protected execution must not execute PR content.

Activation requires later explicit authorization, reviewed protected implementation, authenticated evidence transport, a complete signable request, a distinct human approval, and reviewed core integration. The transport and receipt authentication format remain unresolved. A policy-only merge cannot make the current core result green.

## Proposed conformance matrix

These are design-only cases. They are not executable fixtures, test results, or admissions.

| Case | Proposed result |
| --- | --- |
| Synthetic exact request, complete trusted evidence, distinct unedited approval, live permission, valid expiry, activated policy, integrated consumer | `HumanApprovedLateCycle`, never `failing-first-proven` |
| Valid actual native failing-first evidence | Existing `NativeProvenance` path |
| Identical authenticated inputs and evaluation time | Identical assessment |
| Actual PR782 evidence and generic authority, with no distinct approval, activation, or integration | `REFUSED` |
| Generic authority or MCP advisory approval alone | Refuse |
| Local RED, historical-only passing tests, or all-PASS report presented as native RED | Refuse |
| Changed repository, issue, PR, change, base, branch, head, tree, obligation, selector set, or policy revision | Refuse |
| Changed run attempt, workflow identity, producer revision, artifact ID, or any bound digest | Refuse |
| Artifact substitution, copied local receipt, untrusted workflow, or unverified source-to-head correspondence | Refuse |
| Missing or skipped selector, or another failed obligation | Refuse |
| Missing, edited, deleted, ambiguous, expired, or signer-mismatched approval | Refuse |
| Revoked permission, read-only signer, future issuance, or unverifiable live permission | Refuse |
| Unknown or duplicate fields, invalid types, noncanonical bytes, incomplete IDs, or oversized input | Refuse |
| Redirected API host, arbitrary URL, PR code execution request, or unavailable authentication | Refuse |
| Missing protected activation or core consumer integration | Refuse |

Later behavior implementation needs genuine failing and passing evidence for this new capability. That evidence cannot retroactively establish the historical native failing-first proof absent from PR782.

## Risks, rollback, and next review

A reviewer may mistake proposal acceptance for an issued exception. The inactive status, zero admissions, and actual refused case must remain explicit. A consumer may collapse admission into native RED. Distinct outcomes and negative conformance cases must prevent that conversion. Digests may identify attacker-controlled bytes without authenticating their origin. Protected collection and receipt authentication must establish trust separately.

Published checks are snapshots. Permission revocation and expiry require re-evaluation at consumption. Any stronger merge-time enforcement remains a deployment dependency rather than an asserted property of this draft.

This is a one-file documentation change with no runtime cost. Runtime follow-up crosses protected policy and core trust boundaries, so its effort is larger and is not estimated here. Reverting this document has no runtime effect. A later activation rollback must revoke the capability, preserve required gates, and make dependent consumers refuse admission.

Confidence is high that this proposal grants nothing and cannot green core by itself. Future feasibility depends on authenticated transport and explicit consumer integration. Discovery of an existing trusted transport or consumer could change the implementation plan, but cannot substitute for separate human approval.

Next review covers this contract only. Distinct approval, implementation, activation, and deployment require later explicit authorization. PR782 remains `REFUSED`, core remains red, and deployment readiness remains false.
