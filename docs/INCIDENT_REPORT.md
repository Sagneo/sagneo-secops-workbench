# Sanitized Incident Report: Synthetic Privilege Alert

Classification: synthetic / sanitized
Review boundary: simulated lab Reviewer role
Status: CLOSED

## Summary

A deterministic synthetic sudo event on `linux-endpoint-01` triggered a
medium-severity privilege alert. The lab workflow preserved triage, escalation,
case decisions, one failed fixed-profile collection request, a separately approved
replacement, evidence verification, resolution, and closure.

## Scope and impact

Scope was limited to one synthetic lab asset and one read-only identity command.
No production, customer, third-party, personal, cloud, or legal-custody data was
involved. The event did not establish malicious intent or system change.

## Timeline

1. Analyst moved the alert from `NEW` to `IN_TRIAGE` and then `ESCALATED`.
2. The linked case moved `OPEN -> INVESTIGATING`.
3. Reviewer approved the fixed target, `linux-ir-lite-v1` profile, and resource
   limits before execution.
4. The first request moved to `FAILED` because the locked collector account could
   not enter the forced-command path; the record was not retried, deleted, or
   rewritten.
5. After a bounded access correction, a new request received separate Reviewer
   approval and moved to `SUCCEEDED`.
6. The accepted bundle verified PASS; a separate modified-copy failure was
   preserved and linked to the evidence-integrity alert.
7. The case moved `INVESTIGATING -> RESOLVED -> CLOSED`.

## Evidence

- one closed case with 11 timeline entries;
- two immutable requests: one `FAILED`, one `SUCCEEDED`;
- one accepted bundle containing exactly eight allowlisted artifacts and 61,910
  aggregate bytes;
- two verification records, including the preserved tamper failure;
- SHA-256 validation against the trusted manifest.

Raw bundle contents, identifiers, credentials, keys, database records, and private
paths are excluded. The sanitized aggregate evidence is indexed under
`docs/evidence/`.

## Decisions and resolution

Failure history was preserved. The original request was not rerun. The smallest
supported collector-access correction retained the locked password, forced key,
fixed wrapper, exact sudo boundary, target pinning, and output/time limits. The
replacement request was independently approved before execution. The final lab
state revokes the dedicated collector access.

## Lessons and improvements

- immutable failures are investigation evidence, not records to erase;
- approval applies to an exact target, profile, digest, and limits;
- replacement requests provide a traceable recovery path;
- manifest verification must reject unsafe paths, links, size overflow, missing,
  extra, and modified artifacts before accepting evidence;
- release documentation must use the implemented lifecycle vocabulary.

## Limitations

This is one synthetic, isolated two-VM lab exercise with simulated Reviewer
control. It is not production incident response, a production SIEM, enterprise
forensic acquisition, an SLA result, legal chain of custody, or evidence of
professional supervision.
