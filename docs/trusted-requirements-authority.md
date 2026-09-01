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
comments are rejected.

This workflow is intended to be selected by an organization branch ruleset's
"Require workflows to pass before merging" rule for `dev` and `main`. The
ordinary repository Requirements job remains responsible for producing and
checking evidence; this external workflow prevents PR-controlled evidence
producer bytes from self-authorizing.

Rollback is to disable the organization required-workflow rule and revert the
policy workflow commit. Do not replace it with a PR-controlled status check.
