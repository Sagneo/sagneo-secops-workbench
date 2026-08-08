# Deterministic Fixture Demo Record

Classification: synthetic aggregate record
Network: no dependency download or remote access required after dependencies exist

## Procedure used

The validation follows Runbook 3 with a new disposable SQLite database:

1. Alembic upgrade to `0004`;
2. seed two assets;
3. import Linux main, Suricata main, and Linux malformed fixtures;
4. summarize telemetry;
5. evaluate detections twice;
6. summarize detections and compare tracked manifests.

## Expected and recorded result

Recorded bounded validation:

- assets: 2;
- batches: 3;
- accepted events: 1,201;
- parser errors: 2, isolated in the Linux malformed fixture;
- loaded rule versions: 5;
- first evaluation: 665 created, 0 duplicates;
- replay: 0 created, 665 duplicates;
- distribution: `AUTH-001 404 / AUTH-002 41 / NET-001 100 / PRIV-001 120 /
  EVID-001 0`;
- alert-event links: 1,555;
- disposable DB integrity: `ok`;
- Alembic revision: `0004`;
- source health during validation: Linux `ERROR` because of the intentional
  malformed fixture; Suricata `STALE` because the fixed synthetic timestamps had
  aged beyond the lab freshness threshold.

No protected reference database, private evidence, VM, or remote is used by this record.
