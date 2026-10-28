# Bounded collection sets for issue 161

The web execution succeeds, but the existing single collector rejects a source
total above 100. Retained lab metadata confirms this boundary; it does not prove
detection. Repair collection without changing scenario ground truth, approved
scope, authority, parser meanings, or completeness declarations.

Use the existing adaptive half-open time splitting, only on `record_limit`.
Each successful leaf retains its own scroll snapshot and at most 100 records.
Keep unsuccessful parent attempts as INCOMPLETE. Namespace source references
before canonical parsing, and reject duplicate native source identities across
successful leaves. Preserve the existing single-collection API defaults.

A collection set has at most 63 attempts and 32 successful leaves. Apply a shared
16 MiB response budget and a 600-second deadline across attempts (including failed
overflow parents); cleanup remains bounded and must not be hidden by splitting.
No truncation, source filtering to desired alerts, or automatic completeness claim.
Dense minimum windows and exhausted budgets fail closed.

Network response reads use an absolute request deadline, not just socket inactivity
timeouts. The collection work deadline is shared; scroll cleanup has a separate
bounded allowance so an exhausted collection can still release its cursor.
Each request, including cleanup, has at most 30 seconds for owned network work.
Synchronous operating-system DNS resolution cannot be cancelled by this reader;
after it returns, an expired deadline prevents socket or HTTP activity. This is
an explicit limitation, not a claim of hard wall-clock DNS cancellation.

Load all successful leaves atomically with shared intake limits: 32 MiB per file,
64 MiB total evidence, 20,000 physical lines, 10,000 canonical events. Source refs
and physical files must be unique across the set. Qualify inventory paths by leaf.
Keep the existing 100-entry manifest limit per leaf. Validate batch/collection
hashes, counts, scope, exact gap-free/non-overlapping half-open coverage, absence
of INCOMPLETE, and clean scroll cleanup. Retain empty leaves as scope metadata.

Evaluate the combined canonical tuple once with the unchanged engine and pinned
scenario/profile/context. Bind report input fingerprints to batch and ordered
leaf manifests. Cross-leaf witnesses must work. Missing alerts retain unknown
assurance and cannot become false negatives by inference. The batch explicitly
uses per-collection snapshots, not one global Indexer snapshot; never require
leaf counts to equal an earlier overflow response from another snapshot.

Manager changes use this set route; no schema, dependency, agent, rule, key,
grant, binding revision, or execution change. Preserve the failed native job and
its files. Any native retry uses audited reconciliation after evidence retention
and a newly approved job, never rewriting the failed job or reusing its output.

Required CI gates must count decorator-based skips even when the Python unittest
version does not call `startTest` for them. A skip is never counted as execution,
and a skipped required role fails the gate even alongside successful role tests.
