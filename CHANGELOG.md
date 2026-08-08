# Changelog

## 1.0.0

### Added

- Authenticated FastAPI/Jinja application with Analyst and Reviewer roles.
- Deterministic Linux authentication and Suricata EVE telemetry intake.
- Provenance, source health, parser isolation, UTC normalization, and replay
  deduplication.
- Five versioned detection rules, alert triage, and case timelines.
- Reviewer-gated fixed-profile collection with bounded streaming and strict
  manifest verification.
- SHA-256 evidence integrity checks and tamper detection.
- Measured bulk alert-identity lookup improvement.
- Offline fixture demo, SQLite recovery procedure, operational runbooks, incident
  report, and six synthetic/sanitized evidence artifacts.
- Repository-local responsive interface styling and a fully synthetic UI gallery.
- Browser response hardening with a self-only CSP, anti-framing, no-sniff,
  no-referrer, and no-store controls.

### Verification

- Unit, integration, release-readiness, static-analysis, dependency, recovery, and
  privacy checks are documented in
  [Testing, Offline Demo, and Recovery](docs/TESTING_AND_RECOVERY.md).
- Runtime isolation and remaining limitations are documented in
  [Security](SECURITY.md) and [Limitations](LIMITATIONS.md).
