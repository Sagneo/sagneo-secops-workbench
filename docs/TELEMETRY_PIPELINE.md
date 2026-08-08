# Telemetry intake pipeline

The pipeline accepts exactly two reviewed synthetic source types:

- `LINUX_AUTH`: bounded Linux SSH authentication and sudo records;
- `SURICATA_EVE`: bounded Suricata EVE JSON records.

The committed fixtures are deterministic public-synthetic candidates. Their expected
counts and SHA-256 digests are in `fixtures/expected/telemetry-manifest.json`. Imports are
explicit, transactional, idempotent, and limited to UTF-8 `.log` or `.jsonl` input.
Every accepted event has a stable SHA-256 identity, normalized UTC timestamp, one of
two seeded lab assets, a source batch, normalized fields, and a repository-relative
line reference. Raw payloads and absolute operator paths are not stored.

## Explicit fixture operation

After `alembic upgrade head`:

```text
python -m app.telemetry seed-assets
python -m app.telemetry import --source LINUX_AUTH --path fixtures/linux/auth.log
python -m app.telemetry import --source SURICATA_EVE --path fixtures/suricata/eve.jsonl
```

An identical command is a batch replay and creates zero new batches or events.
Malformed-record fixtures demonstrate bounded per-record isolation:

```text
python -m app.telemetry import --source LINUX_AUTH --path fixtures/linux/auth-malformed.log
python -m app.telemetry import --source SURICATA_EVE --path fixtures/suricata/eve-malformed.jsonl
```

## Disposable reset

Reset is intentionally restricted to exactly `data/disposable/telemetry-demo.db` and
requires the literal confirmation `RESET-DISPOSABLE`. It refuses the active
database and every other target.

```text
python -m app.telemetry reset-disposable --database-url sqlite:///data/disposable/telemetry-demo.db --confirm RESET-DISPOSABLE
```

## Optional EVE regeneration

Normal tests, imports, and clean clones do not require Suricata, VMware, a raw PCAP,
or network access. `scripts/regenerate_eve_offline.sh` is an optional one-shot
contract: it refuses any image not selected by immutable SHA-256 digest and runs with
no network, read-only PCAP/config inputs, no capabilities, no new privileges, bounded
CPU/RAM/PIDs/time, and private bounded output. The normal demo does not execute an image
or commit a PCAP. A future regeneration must first record authoritative image
provenance and review the private PCAP license/privacy.
