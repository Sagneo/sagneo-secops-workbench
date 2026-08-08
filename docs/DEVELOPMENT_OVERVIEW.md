# Development Overview

Sagneo SecOps Workbench was developed as an educational, isolated security
operations laboratory. The development sequence was organized around verifiable
capabilities rather than calendar milestones.

## Phase 1 — Lab foundation

- defined the two-VM host-only architecture;
- established loopback-only application access through an SSH tunnel;
- implemented authentication, session handling, CSRF protection, and Analyst /
  Reviewer authorization;
- created the database migration baseline and hardened container profile.

## Phase 2 — Telemetry pipeline

- added deterministic Linux authentication and Suricata EVE fixtures;
- implemented bounded parsing, UTC normalization, provenance, stable identities,
  replay deduplication, parser-error isolation, and source health;
- locked expected counts and fixture digests in machine-readable manifests.

## Phase 3 — Detection and triage

- introduced versioned YAML detection rules;
- linked alerts to normalized events;
- added filtering, pagination, required analyst fields, supported transitions,
  and append-only triage history;
- validated deterministic evaluation and replay behavior.

## Phase 4 — Case and evidence workflow

- implemented case timelines and role-separated review;
- defined one fixed `linux-ir-lite-v1` collection profile;
- added bounded streaming, strict manifest validation, SHA-256 verification, and
  tamper-failure preservation;
- documented the limits of hashing and simulated review.

## Phase 5 — Measured process improvement

- identified per-alert identity lookups as a bounded efficiency problem;
- compared a fixed baseline with deterministic bulk resolution;
- preserved alert identities, rule distribution, links, and replay semantics;
- recorded the measured reduction and its fixture-scale limitations.

## Phase 6 — Hardening and reproducibility

- consolidated operational runbooks and recovery procedures;
- verified disposable database restoration and offline fixture replay;
- added release-readiness, privacy, static-analysis, and security checks;
- removed development-only network and automation access from the final lab state.

## Engineering principles

- deterministic inputs and explicit expected outputs;
- least privilege and network isolation;
- fail-closed parsing, collection, verification, and release controls;
- immutable application history for supported state transitions;
- preservation of failed attempts as diagnostic evidence;
- clear separation between synthetic laboratory results and production claims;
- documented rollback and recovery boundaries.

## Development tooling

Python, Git, pytest, Ruff, mypy, Bandit, Docker Compose, and VMware Workstation
were used during implementation and review. The repository remains the
authoritative description of shipped behavior, verification coverage, and known
limitations.
