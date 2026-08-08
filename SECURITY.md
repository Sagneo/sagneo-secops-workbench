# Security

- Runtime is private, host-only, and accessed through an SSH tunnel.
- The application port is published only on guest loopback.
- Secrets, runtime databases, VM files, installation media, and private evidence are ignored.
- State-changing forms require CSRF validation; roles are checked server-side.
- Session cookies contain opaque random values; only SHA-256 digests are persisted.
- The lab's loopback HTTP profile sets `APP_SECURE_COOKIE=false`; set
  `APP_SECURE_COOKIE=true` when terminating TLS in front of the application.
- HTML responses use a self-only CSP, anti-framing, no-sniff, no-referrer, and
  no-store controls; the interface uses one repository-local stylesheet.
- Report a suspected secret or private-data exposure before pushing or publishing.

The tracked project contains no production, customer, third-party, personal,
email, badge, or cloud data.

Telemetry accepts only reviewed UTF-8 synthetic fixtures of the two declared types. File and
line sizes, timestamps, event types, required fields, source references, and lab-asset
correlation are bounded. Raw payloads and absolute paths are not persisted. Optional
Suricata regeneration has no network and requires a digest-pinned image; raw PCAP
input and generated output remain private and ignored.

Collection is case-bound and Reviewer-gated. The only lab profile is
`linux-ir-lite-v1`, executed through a dedicated forced-command SSH key and a
root-owned fixed wrapper. Client, wrapper, and verifier enforce streaming limits.
Manifest schema, paths, duplicate keys, links, file identity, per-artifact size, and
aggregate size are validated before or during bounded access.

Private SQLite backups and evidence bundles remain ignored and access-controlled
under a local retention policy. The final state removes development NAT, automation
sudoers entries, and collector key/account access, fixed wrapper, and sudoers entry.
Normal key-only administrative SSH and authenticated sudo remain; root, password,
and keyboard-interactive SSH remain prohibited.

Only the six reviewed files under `docs/evidence/reports/` are distributable
evidence. They contain synthetic/sanitized aggregates and no raw bundle,
database, key, account identifier, private path, or VM material. Report 06 records
reproducible CI and merge verification.

The runtime, databases, keys, VM files, and retained evidence are not distributed
with the source tree. The repository does not provide a public runtime.

Suspected release defects or exposure are handled through the
[release integrity response procedure](docs/RELEASE_INTEGRITY_RESPONSE.md).
That procedure is fail-closed and separates diagnosis from release mutation.
