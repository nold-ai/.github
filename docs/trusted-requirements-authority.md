# Trusted Requirements authority

The `Trusted Requirements Authority` ruleset workflow is the immutable approval
boundary for Requirements evidence in `nold-ai/specfact-cli`.

The workflow must never check out, import, install, or execute pull-request
content. It treats the pull-request event and GitHub API responses only as data.
It succeeds only when an unedited repository `OWNER`, `MEMBER`, or
`COLLABORATOR` comment on the pull request binds the current repository, pull
request, base branch, head branch, head commit, complete Git tree, signer, and a
short expiry. A push changes the commit and tree and therefore invalidates the
authority automatically.

The canonical comment has this form, with the JSON object serialized on one
line using sorted keys and no extra whitespace:

```text
SPECFACT_TRUSTED_REQUIREMENTS_AUTHORITY_V1
{"authority_version":1,"base_ref":"dev","capability":"trusted-requirements-authority","expires_at":"2026-09-08T12:00:00Z","head_branch":"bugfix/example","head_commit":"0123456789abcdef0123456789abcdef01234567","head_tree":"89abcdef0123456789abcdef0123456789abcdef","pull_request":123,"repository":"nold-ai/specfact-cli","signer_login":"reviewer"}
```

The expiry must be after validation time and no later than seven days after the
comment was created. The comment author must match `signer_login`, and edited
comments are rejected. The workflow also revalidates the signer's current
effective repository permission through GitHub's read-only collaborator API;
only `write` or `admin` is accepted. Historical comment association is not
sufficient after access is removed.

This is a one-shot capability: expiry, edit state, and live permission are
checked when the required workflow consumes the comment and publishes an
attestation for that exact head commit and tree. GitHub check conclusions are
immutable snapshots; deleting or editing the comment, removing access, or
reaching `expires_at` after a successful run does not retroactively revoke that
attestation. Any push creates a different head and requires a new authority.
Continuous post-success revocation is deliberately out of scope because it
requires an organization-owned GitHub App (or an equivalent merge-time policy
service) able to publish a newer failing check for the unchanged head.

The verifier's API transport connects only to `api.github.com` over TLS and
does not follow redirects. Candidate values are encoded only into relative API
paths and are never accepted as hosts or URL schemes.

This workflow is intended to be selected by an organization branch ruleset's
"Require workflows to pass before merging" rule for `dev` and `main`. The
ordinary repository Requirements job remains responsible for producing and
checking evidence; this external workflow prevents PR-controlled evidence
producer bytes from self-authorizing.

Native GitHub stacks may use a repository-local parent PR branch as their base.
That base is accepted only after the immutable verifier independently authenticates
live GitHub native stack metadata: repository identities, stack ID/number/size,
consecutive positions, exact parent branch/head, ancestry, and a protected dev/main
root. Ambiguous parents, forked repositories, stale events and unrelated commits
fail closed. The member capability still binds the immediate base and exact child
head/tree; ancestry is not approval and cannot replace the member comment.

This change is a prerequisite for stack #757. Its regression must fail against the
unchanged protected-base-only verifier before implementation. The policy keeps all
existing expiry, canonical encoding, edit-state and live permission controls.

Rollback is a normally reviewed revert of the policy implementation while retaining
the required-workflow rule. Downstream PRs then fail closed until restacked onto a
protected base or a repaired policy is reviewed. Do not disable required gates.

Validation on 2026-10-11: the original policy failed the valid stack regression
(1 failed, 25 passed). The implementation passes all 26 tests. The copied adapter
is byte-identical to the core prerequisite and uses only the Python standard
library. CI installs its test runner from an independent hash-protected lock;
the protected authority workflow still installs no dependencies and executes
only the immutable organization checkout.

Additional ref compatibility review on 2026-10-11: the initial adapter rejects
valid Git branch characters and accepts hidden/lock-suffix components. The
31 literal branch controls compare its data-only syntax checks with Git; 11
fail before repair. All 57 policy controls pass after repair, retaining the
original 26 authorization and stack controls. The copied core/organization
adapter remains identical. Git ref rules are documented at
https://git-scm.com/docs/git-check-ref-format (accessed 2026-10-11).


Ordinary non-stacked forks targeting a protected branch retain their own proof
boundary. The adapter binds the fork repository ID/name to live API data and
still rejects native fork parents, foreign bases and stale event identities.
Regression evidence: one failed/three passed before repair; all 61 policy
controls pass after repair. Exact-head capability and member checks are unchanged.


Proof-context CLI validation derives the unique root merge base from the exact
authenticated Git objects when the protected branch has advanced. The authority
imports only the data resolver, with no Git execution. Two genuine Git-history
regressions fail before repair; all 63 policy controls pass after repair.
