# Runbook 1: Source Monitoring, Alert Analysis, and Initial Triage

Classification: synthetic lab procedure
Review model: simulated Analyst and Reviewer roles in an isolated lab

## Trigger

Use this runbook when a source is stale or reports parser errors, or when a new
deterministic alert requires initial analysis.

## Prerequisites

- authenticated Analyst session through the loopback SSH tunnel;
- frozen synthetic fixture dataset and five immutable rule versions;
- no need for NAT, live sensors, production logs, or a collection account.

## Bounded steps

1. Open **Sources** and inspect each source's status, last successful event,
   accepted/error counts, parser version, and batch digest.
2. Select one Linux and one Suricata event. Relate the safe fixture line reference
   to normalized UTC, asset, actor/source, category/action/outcome, severity, and
   normalized fields.
3. Open **Alerts**, select a NEW alert, and inspect immutable rule ID/version/digest,
   linked events, asset, actor/source, trigger, severity, confidence, and stated
   false-positive context.
4. Record scope/impact, false-positive context, disposition reason, recommended
   action, and analyst notes.
5. Transition only through an allowed path:
   `NEW -> IN_TRIAGE -> BENIGN -> CLOSED` or
   `NEW -> IN_TRIAGE -> ESCALATED -> CLOSED`.
6. If escalated, continue with Runbook 2. Never edit the database directly.

## Expected checks and evidence

- two sources and two lab assets are visible;
- fixture mode has 1,201 accepted events: 601 Linux and 600 Suricata;
- the malformed Linux fixture yields two isolated parser errors without losing its
  one valid event;
- four telemetry rules produce 665 alerts and 1,555 links in a clean fixture run;
- alert detail retains append-only supported-workflow history.

Evidence: artifacts 01 and 02, fixture manifests, and recorded telemetry/detection
validation.

## Decisions and escalation

- `FRESH` means the deterministic timestamp is within the lab threshold; it is not
  an uptime or SLA claim.
- `ERROR` means bounded parser failures are present; inspect the error count and
  accepted records before escalating.
- Escalate when impact or intent cannot be resolved from normalized and linked
  evidence. Mark BENIGN only with a specific, evidence-backed reason.

## Rollback and recovery

If a transition is wrong, stop; do not rewrite history. Use a new supported
transition or document the error privately. For fixture corruption, use Runbook 3
with a disposable database. Never reset the protected reference database.

## Limitations

Synthetic fixtures are not continuous monitoring. Reviewer behavior is simulated.
SQLite, two assets, and deterministic timestamps do not establish enterprise scale,
production incident handling, or professional supervision.

## Validation notes

- Source/error interpretation, raw-reference-to-normalized trace, rule provenance,
  and triage-decision checks are covered by deterministic fixtures and tests.
- Steps 1–5 define the supported UI sequence; environment-specific observations
  remain outside the source distribution.
