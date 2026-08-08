# Report 01: Source Health

Classification: synthetic / sanitized
Source: deterministic telemetry manifest and runtime validation

| Source | Accepted events | Parser errors | Lab interpretation |
|---|---:|---:|---|
| `LINUX_AUTH` | 601 | 2 | ERROR because the reviewed malformed fixture demonstrates bounded error isolation |
| `SURICATA_EVE` | 600 | 0 | FRESH at the initial observation; STALE in a later rehearsal as fixture time aged |

The source view exposes batch digest, parser version, last success, accepted/error
counts, and two declared assets. Total normalized events are 1,201. Safe references
point only to tracked fixture lines; raw payloads and operator paths are not persisted.

What this proves: deterministic source monitoring, provenance, and parser-error
visibility for two synthetic source types.

What this does not prove: live sensor operation, uptime, SLA, continuous production
monitoring, or enterprise scale.
