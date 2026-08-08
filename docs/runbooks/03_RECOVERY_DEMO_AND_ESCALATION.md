# Runbook 3: Backup/Restore, Deterministic Demo, Failure Recovery, and Escalation

Classification: synthetic lab procedure
Review model: simulated Analyst and Reviewer roles in an isolated lab

## Trigger

Use this runbook to reproduce the fixture workflow, validate a disposable SQLite or
evidence restore, or respond to a failed integrity/count/privacy gate.

## Prerequisites

- exact source commit and locked Python 3.12 dependencies;
- a new disposable clone with no remote and no ignored/private state;
- a new disposable SQLite target;
- for private recovery only, an integrity-checked backup or evidence copy in an
  ignored private location.

## Bounded deterministic demo

1. Create a local disposable clone from the exact commit without contacting a
   remote. Remove its local origin.
2. Set a new disposable `APP_DATABASE_URL`; migrate it to Alembic `0004`.
3. Seed the two assets.
4. Import Linux main, Suricata main, and Linux malformed tracked fixtures.
5. Run telemetry summary, evaluate detections twice, then run detection summary.
6. Compare results to the tracked manifests: 1,201 events, two parser errors, five
   loaded rules, 665 alerts, 1,555 links, and replay `0 created / 665 duplicates`.

## Bounded recovery

1. Copy, never move, an approved private backup to one new disposable target.
2. Record source/target sizes and SHA-256.
3. Require `PRAGMA integrity_check = ok`, Alembic `0004`, and accepted aggregate
   counts before read-only application inspection.
4. Copy accepted evidence and trusted manifest metadata to one new ignored target.
5. Run the committed verifier; require exactly eight allowlisted artifacts and the
   accepted aggregate limit.

## Expected checks and evidence

- deterministic demo record matches tracked fixture/rule manifests;
- repeated evaluation creates no new alert;
- restored bytes match their recorded source digest;
- corruption, wrong target, path ambiguity, extra files, and size violations fail
  closed.

Evidence: deterministic demo record, artifact 05, private restore
proof, and the tracked testing/recovery guide.

## Decisions and escalation

- on any digest, identity, count, privacy, migration, or verifier mismatch: stop,
  preserve the disposable target and compact log, and escalate;
- never migrate/import/evaluate the protected reference database during recovery proof;
- never copy private evidence, keys, DBs, caches, VM files, or absolute operator paths
  into Git.

## Rollback and recovery

Discard only a precisely identified disposable target after review. Restore no
development exception silently. Retained evidence follows a local,
access-controlled retention policy.

## Limitations

Offline means no network is needed after exact dependencies are locally available.
The proof covers deterministic lab reproducibility and recovery readiness, not cold
package acquisition, concurrent load, enterprise databases, distributed recovery,
production SLA, or legal evidence handling.

## Validation notes

- Steps 2–6 are reproducible with a new disposable database and tracked fixtures.
- Recovery validation leaves the protected reference database and retained evidence
  unchanged.
