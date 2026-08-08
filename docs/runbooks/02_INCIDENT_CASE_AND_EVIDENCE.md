# Runbook 2: Incident Case, Reviewer-Gated Collection, and Evidence Integrity

Classification: synthetic lab procedure
Review model: simulated Analyst and Reviewer roles in an isolated lab

## Trigger

Use this runbook after an alert is escalated and a bounded case/timeline decision or
review of the existing collection/evidence record is required.

## Prerequisites

- an ESCALATED alert and an Analyst session;
- an existing case for the recorded simulated review;
- Reviewer session for the approval record;
- fixed `linux-ir-lite-v1` profile and exact lab target;
- no unplanned live collection during review.

## Bounded steps

1. Open the case linked to the escalated alert and review status, alert link, asset,
   timeline, and decision rationale.
2. Confirm the case moved through `OPEN -> INVESTIGATING -> RESOLVED -> CLOSED`
   using supported transitions.
3. Review the original immutable FAILED request and the accepted replacement
   SUCCEEDED request. Do not retry or create another request.
4. As Reviewer, inspect the accepted request's target, profile version/digest,
   allowlisted artifact types, per-artifact/aggregate limits, and approval history.
5. As Analyst, explain the existing execution record and why approval preceded the
   successful run.
6. Review the sanitized manifest summary: exactly eight regular allowlisted
   artifacts and 61,910 aggregate bytes.
7. Relate the independent PASS verification to the trusted manifest and the
   preserved tamper-failure record.

## Expected checks and evidence

- one CLOSED case with 11 timeline entries;
- two immutable requests: original FAILED and replacement SUCCEEDED;
- one accepted bundle, exactly eight artifacts, 61,910 bytes;
- two verification records and one EVID-001 alert/link;
- SHA-256 PASS means current bytes agree with the trusted manifest.

Evidence: reports 03 and 04, the tracked collection profile, and environment-specific
validation records. Raw evidence and private identifiers remain untracked.

## Decisions and escalation

- reject a request if target, profile, digest, limits, or role is wrong;
- fail closed on missing/extra/modified/oversize/unsafe-path/link ambiguity;
- preserve FAILED requests and verification history; never rewrite evidence state;
- escalate any manifest trust ambiguity because SHA-256 alone does not establish
  pre-hash authenticity or completeness.

## Rollback and recovery

Do not rerun collection to repair a documentation or UI mistake. Preserve the
immutable failure and use only an explicitly supported replacement request under
separate authority. Restore evidence only to an ignored disposable path and verify
with the committed verifier.

## Limitations

The fixed profile is basic read-only lab collection, not disk imaging, memory
acquisition, legal chain of custody, or production forensics. The Reviewer is a
simulated role, not independent professional supervision.

## Validation notes

- Case, request, timeline, manifest, and tamper-state facts can be reconciled from
  the synthetic records without executing collection.
- Steps 1–7 define the supported review sequence; documentation inspection does
  not authorize a live collection.
