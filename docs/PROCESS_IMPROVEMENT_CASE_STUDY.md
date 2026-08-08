# Measured alert-deduplication process improvement

## Problem and locked hypothesis

The accepted evaluator resolved each candidate alert identity with a separate SQL
statement. The locked hypothesis was that deterministic, bounded bulk resolution
would reduce those statements while preserving all evaluator outputs, identities,
links, provenance, history, and evidence behavior.

The primary metric was the number of executed SQL statements that resolve existing
alert stable identities. Total SQL statements, wall time, and process time were
secondary measurements. SQLAlchemy connection events counted actual statements; the
measurement harness classified identity lookups separately from unrelated Alert
queries and passed its built-in positive and negative self-test.

## Fixed protocol

- The aggregate-only harness was frozen before baseline.
- One integrity-checked accepted SQLite snapshot produced three byte-identical,
  disposable working copies.
- The baseline ran exactly once on the pre-change evaluator.
- The improved run and one confirmation ran exactly once each on the optimized
  evaluator.
- Every run used the same harness, rules, fixtures, VM resources, container hardening,
  candidate population, and measurement method.
- Measurement occurred only on disposable copies; the protected reference database was not
  used for timing or query-count measurements.

The locked population contained 1,201 normalized events, five immutable rule versions,
666 existing alerts, and 1,555 alert-event links. Existing alerts were distributed as
AUTH-001 404, AUTH-002 41, EVID-001 1, NET-001 100, and PRIV-001 120.

## Bounded change

The evaluator now computes the complete bounded set of candidate stable identities and
resolves existing identities with deterministic ordered `IN` queries. Query chunks are
limited to 900 identities and the evaluator rejects populations above 10,000 candidates.
Newly created identities are added to the in-memory set so same-run duplicate semantics
remain unchanged.

No rule, fixture, schema, label, index, dependency, event, alert, evidence, case,
collection, endpoint, collector, firewall, adapter, or forwarding behavior changed.

## Immutable aggregate results

| Run | Identity lookup SQL | Total SQL | Wall seconds | Process seconds | Created | Duplicates |
|---|---:|---:|---:|---:|---:|---:|
| Baseline | 666 | 674 | 0.235733 | 0.233877 | 0 | 666 |
| Improved | 1 | 9 | 0.059567 | 0.058258 | 0 | 666 |
| Confirmation | 1 | 9 | 0.068088 | 0.067134 | 0 | 666 |

The primary metric fell from 666 to 1 statement, a 99.85% reduction, and the
confirmation reproduced 1. Total SQL statements fell from 674 to 9, a 98.66%
reduction. Wall time was 74.73% lower in the improved run and 71.12% lower in the
confirmation. Process time was 75.09% and 71.30% lower, respectively.

## Correctness and acceptance

All three runs reported five rules, 666 candidates, zero created alerts, and 666
duplicates. Across the runs:

- the stable-identity set digest was unchanged;
- rule and fixture digests were unchanged;
- alert distribution and all 1,555 links were unchanged;
- required alert-field completeness remained 100%;
- accepted case, collection, evidence, verification, and triage/history records were
  unchanged;
- SQLite integrity remained `ok`;
- the improved and confirmation query counts matched exactly.

Regression coverage includes empty, one, 666, chunk-boundary, over-bound, equivalence,
replay, and rollback/error cases. The full suite collected 96 tests: 95 passed, one
Windows platform symlink test skipped because that environment could not create the
link, zero failed, and zero errored. A Linux runtime check covers the corresponding
symlink rejection. Ruff, strict mypy, and Bandit passed. The application was
validated in a healthy, read-only-root,
non-root, capability-dropped, no-new-privileges container bound only to
`127.0.0.1:8000`. One normal live replay produced zero alerts and 666 duplicates.

The locked hypothesis is accepted for this lab experiment.

## Limitations

This is a synthetic fixture on one small SQLite laboratory database, in one VM and one
container environment, with one baseline and two post-change observations. Timing is
noisy, the population is small, and the result does not establish behavior for
concurrent workloads, other database engines, larger datasets, distributed systems, or
enterprise production environments.

## Rollback

The pre-change source and canonical database snapshot are retained privately for
rollback. A correctness, identity, integrity, isolation, or reproducibility failure
would require restoring the baseline evaluator and rejecting the optimization.

Because the bounded change passed the locked protocol, the recommendation is to
retain it. Any broader optimization should use a new fixed protocol and measurement.
