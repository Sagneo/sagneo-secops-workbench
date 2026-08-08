# Limitations

- Greenfield lab scale; no production-readiness claim.
- Two roles and one lab instance; no registration, reset, SSO, or user administration.
- SQLite is selected for bounded single-instance fixture scale.
- Application audit events are append-only through supported application behavior, not
  tamper-proof against the database owner.
- Telemetry is deterministic synthetic fixture intake, not a live sensor,
  production monitor, SIEM, or enterprise-scale benchmark.
- The recorded lab collection demonstrates one bounded fixed-profile run against the
  disposable endpoint; it is not general forensic acquisition, legal chain of
  custody, or production incident response.
- SHA-256 verification proves byte agreement with the trusted manifest presented to
  the verifier, not original authenticity or completeness before hashing.
- Source freshness is a deterministic lab threshold, not an uptime/SLA assertion.
- Analyst and Reviewer roles are simulated lab controls, not real professional
  supervision.
- The application is an educational lab workbench, not a production SOC platform.
- The default interface is served over guest loopback and reached through an SSH
  tunnel, so the lab profile does not provide TLS or HSTS. Deployments behind TLS
  must set `APP_SECURE_COOKIE=true`.
- Authentication has bounded sessions and Argon2 password hashing but no account
  lockout, login throttling, SSO, or identity lifecycle workflow.
- The query reduction was measured on one small synthetic SQLite fixture and does
  not generalize to concurrent, distributed, enterprise, or production workloads.
- One Windows-only symlink test is skipped where the platform cannot create a
  symlink; accepted real-Linux validation covers the corresponding runtime behavior.
- Exactly six synthetic/sanitized evidence artifacts are included. Report 06 records
  reproducible CI and merge verification.
- The container base is version-pinned rather than digest-pinned; release validation
  therefore includes dependency auditing but does not claim a complete software
  supply-chain attestation.
- Apache-2.0 licensing and source availability do not make the runtime,
  databases, VM files, keys, or retained evidence public.
- The source tree contains code and six synthetic/sanitized evidence artifacts
  only. It provides no public runtime or production service.
