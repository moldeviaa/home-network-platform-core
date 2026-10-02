# Independent public deliveries

Implement generic work here first. Private deployment code owns site bindings,
authorization decisions, operations and secret references. Do not import private
Git history, snapshots, receipts, domains, tenant/operator IDs or credentials.
Examples use `example.invalid` and visibly synthetic UUIDs.

A complete, useful correction or feature gets its own short-lived PR and release
without waiting for a private deployment or unrelated maintenance. Prefer a small
release on each independently validated increment; there is no timer that makes
empty commits. Security and correctness fixes take priority. Record behavior,
compatibility, actual checks and limits in CHANGELOG.md and the GitHub release.

Before merging, review the exact head and current main, run
`python3 -m unittest discover -s tests`, build/install the wheel in an isolated
directory and scan both the source and reachable public history with a redacting
secret scanner. Auth tests require the locked dependencies. Tests use synthetic
inputs and loopback only; no household credentials or deployment hooks belong in
CI. Keep the existing site workflows disabled.

Tag a reviewed main commit using an explicit semantic version. Existing recovery
imports and the `home-net-recovery` console entrypoint remain supported. Breaking
public interfaces require a documented migration and major version change.
Consumers advance their exact commit/file hash lock in a separate PR, verify the
inventory and their signed-token/session/build contracts, and deploy separately.
The private consumer keeps a reviewed source snapshot for offline builds; it is
not a second editable implementation. Change it only from a verified core release.

Generated distributions, caches, reports, plans and abandoned designs stay outside
the source tree. Git history and immutable PR links provide provenance. Delete
merged branches after checking ownership, unmerged work and recovery references.
