# Protected Requirements red evidence for core PR #799

The Requirements verifier needs a failing execution from the signed tests-only source before it can reconcile the final implementation. Core PR #799’s original tests-only run stopped before pytest because the dependency trust record on its protected base had expired. Replacing that record on the tests-only tree would change governed production inputs and invalidate before-fix evidence.

The protected action is bound to same-repository PR #799 against the exact protected `dev` base and a single signed tests-only commit. It takes its test source and approved plan from that tree. It installs the proof environment from the separately pinned, audited core dependency graph and unchanged module fixture. It reuses the native planner, executor, JUnit reconciliation and Git provenance binder. The child receives the native allowlisted environment. A collection error, unexpected pass, changed plan or source mismatch prevents artifact publication.

The calling Requirements workflow pins the organization action by full Git SHA. Its three reconciliation lanes consume the proof from the current run by immutable artifact ID and apply the existing provenance verifier. Normal previous-run retention still serves every other PR. The organization’s existing authority workflow separately approves the exact final tree. Dependency trust, security audit, signed commits and ordinary merge checks still apply.

A change to the base, approved plan, fixture, or permitted subject requires a new reviewed policy revision. The scoped action and its consumer can be reverted together after the PR no longer needs the proof lane. Its artifact has a 14-day retention period.
