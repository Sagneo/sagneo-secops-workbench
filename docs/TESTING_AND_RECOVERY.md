# Testing, Offline Demo, and Recovery

This runbook is for the fixture-mode distribution. All examples use disposable
targets. They must never point at the protected reference database or retained evidence.

## Prerequisites

- Git and Python 3.12;
- dependencies installed from `requirements-dev.txt` with `--require-hashes`;
- either network access for the initial install or an already prepared local wheel
  cache/environment containing the exact locked dependencies;
- no VMware, Suricata process, raw PCAP, private key, or private evidence is required
  for the fixture demo.

The offline claim begins after dependencies are available. It does not claim that a
cold package installation can contact an index while offline.

## Broad local gate

From the repository root, using the locked development environment:

```text
python -m pytest --junitxml=<private-disposable-path>/pytest.xml
python -m ruff check .
python -m mypy app
python -m bandit -q -r app
python -m pip check
alembic upgrade head
```

Record exact collected, passed, skipped, failed, and error counts. A collected or
skipped test is not a passed test. Dependency advisory status must identify the
advisory source and freshness; no external refresh is implied when the gate is
offline.

## Clean-clone offline fixture demo

Create a disposable clone from the exact source commit without contacting a
remote. Do not copy `.venv`, `data`, `evidence/private`, keys, databases, caches,
or VM files into it.

Set `APP_DATABASE_URL` before starting Python so every module uses a new disposable
SQLite file inside the clone. Upgrade that database to Alembic `0004`, then run:

```text
python -m app.telemetry seed-assets
python -m app.telemetry import --source LINUX_AUTH --path fixtures/linux/auth.log
python -m app.telemetry import --source SURICATA_EVE --path fixtures/suricata/eve.jsonl
python -m app.telemetry import --source LINUX_AUTH --path fixtures/linux/auth-malformed.log
python -m app.telemetry summary
python -m app.detections evaluate
python -m app.detections evaluate
python -m app.detections summary
```

Expected deterministic fixture-mode results:

- two assets, 1,201 accepted events, and two bounded Linux parser errors;
- five loaded immutable rule versions, with 665 fixture alerts produced by the four
  telemetry rules in distribution `404/41/100/120`; `EVID-001` produces zero because
  no private verification failure exists in the clean clone;
- 1,555 alert-event links;
- first evaluation creates 665 alerts; replay creates zero and reports 665
  duplicates;
- fixture digests match `fixtures/expected/telemetry-manifest.json` and rule/count
  expectations match `fixtures/expected/detection-alert-manifest.json`.

`EVID-001` is intentionally absent in a public clean clone because it requires a
private evidence verification failure. The accepted private runtime has five rules
and 666 alerts only because its preserved evidence record exists.

## Disposable SQLite restore

Use an integrity-checked private backup, never the protected reference database, as the
source. Copy it to one new private disposable path and record source and restored
byte sizes plus SHA-256 digests. On both files run read-only SQLite checks:

```text
PRAGMA integrity_check;
SELECT version_num FROM alembic_version;
```

Verify the accepted aggregate counts, rule distribution, 1,555 links, closed case,
two requests, one accepted bundle, two verification runs, and protected detection,
case, and evidence
records. Open only the restored copy for normal read-only application inspection.
Wrong-target or corrupt input must stop the procedure; never migrate, import, replay,
or evaluate against the protected reference database during recovery proof.

## Disposable private-evidence restore

Copy the accepted bundle and its required manifest metadata to one new ignored
private directory. Verify the copy with the committed verifier and the trusted
manifest SHA-256. PASS requires exactly eight allowlisted regular artifacts and the
existing per-artifact/aggregate limits.

Missing, extra, modified, traversal, link ambiguity, and oversize cases are verifier
security tests; they do not authorize modifying the retained accepted bundle or
creating a new application verification row, request, case, or EVID alert.

## Privacy, rollback, and retention

- Scan the tracked tree, history, and a source archive before release.
- Keep databases, keys, raw evidence, private reports, absolute operator paths, caches,
  VM files, and generated output outside Git.
- On any integrity, privacy, identity, or count mismatch, stop and preserve the
  disposable target and bounded log; do not overwrite the accepted source.
- The final state removes development NAT, revokes lab automation sudo, and revokes the
  collector account/key/wrapper/sudoers access. Cold-start checks retained only
  VMnet2 `.10/.20`, blocked lateral SSH/8000, and confirmed loopback-only health
  through the intended host tunnel.
- Retained private evidence follows a local access-controlled retention policy;
  deletion requires explicit maintainer approval.

The operational decision paths are consolidated in:

- [`runbooks/01_SOURCE_MONITORING_AND_TRIAGE.md`](runbooks/01_SOURCE_MONITORING_AND_TRIAGE.md);
- [`runbooks/02_INCIDENT_CASE_AND_EVIDENCE.md`](runbooks/02_INCIDENT_CASE_AND_EVIDENCE.md);
- [`runbooks/03_RECOVERY_DEMO_AND_ESCALATION.md`](runbooks/03_RECOVERY_DEMO_AND_ESCALATION.md).

The compact deterministic validation result is recorded in
[`DETERMINISTIC_DEMO_RECORD.md`](DETERMINISTIC_DEMO_RECORD.md).
