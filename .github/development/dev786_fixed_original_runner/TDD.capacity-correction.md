# Approved verifier capacity correction

29 October 2026. The owner approved work256to512MiB and metadata64000to128000, with independent rawread255MiB and all other caps unchanged.

Before changing preflight.py from f8981c33e588ff1319499a574e281d979d01a698, the revised independent owned-file threshold tests failed (one assertion and four positive-boundary refusals). Revised metadata controls produced three intended assertion failures against the unchanged 64000 limit. Twelve exact read-boundary source slices also failed their maximum-admission and lost-result accounting assertions. These are local Synthetic/real-file boundary results, not original native RED. Initial nonisolated import errors and an omitted script argument were command setup errors and provide no behavior evidence. Exact logs are retained in the local after28-operation packet.

Runtime, passing checks, independent review and the one new immutable CI attempt remain pending.
