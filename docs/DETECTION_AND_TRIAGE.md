# Detections and initial triage

The detector evaluates the normalized fixture corpus synchronously and
deterministically. It loads exactly four versioned YAML rules with
`yaml.safe_load`, strict keys, bounded file/text/window values, and immutable
rule-version digests.

The accepted full fixture evaluation produces the exact counts recorded in
`fixtures/expected/detection-alert-manifest.json`. Replaying evaluation creates no
new alerts because stable identities include the rule ID, immutable version,
and ordered normalized-event identities.

The authenticated `/alerts` queue and `/alerts/{id}` detail show rule
provenance, UTC sequence, asset/actor/source context, linked events, safe
fixture references, checklist fields, and append-only history. Analyst
mutations enforce CSRF, an optimistic version check, and only these paths:

- `NEW -> IN_TRIAGE -> ESCALATED -> CLOSED`
- `NEW -> IN_TRIAGE -> BENIGN -> CLOSED`

Reviewer access is read-only at the server. Completing a disposition requires
scope/impact, false-positive context, disposition reason, recommended action,
and analyst notes. This layer does not introduce case management, evidence handling,
collection, response automation, external feeds, or any fifth rule.
