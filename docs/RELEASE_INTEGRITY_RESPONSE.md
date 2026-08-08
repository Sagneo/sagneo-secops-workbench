# Release Integrity Response Procedure

This procedure is a fail-closed control for a release. It separates diagnosis,
approval, correction, and verification.

## Triggers

Stop when evidence shows a secret/privacy exposure, wrong commit/tag/license/asset,
broken clean clone, failed required check, material security defect, unsupported
claim, or mismatch between the audited candidate and remote state.

## Required sequence

1. **Stop dissemination.** Do not publish, promote, merge, tag, release, replace,
   hide, or delete further material.
2. **Preserve facts.** Record exact repository/commit/ref, timestamps, checks,
   affected artifacts, observed behavior, and current remote state without copying
   secrets or private evidence into tracked/public records.
3. **Assess impact.** Classify exposure, affected audience/material, integrity and
   confidentiality risk, rollback value, and whether the candidate remains usable.
4. **Set correction state.** Mark readiness or release as blocked; preserve failed
   histories and the incident record.
5. **Obtain maintainer approval.** Record the exact repository, commit/version,
   allowed operations, prohibited operations, and required verification.
6. **Correct narrowly.** Change only the approved defect. Never improvise a force
   push, deletion, visibility change, tag move, asset replacement, or withdrawal.
7. **Reverify independently.** Repeat the exact affected local, privacy, archive,
   clean-clone, CI, and remote checks; record the new immutable audit result.

## Stop conditions

Stop without remote mutation if authority is missing or ambiguous, the exact
candidate cannot be identified, private material might be exposed, checks fail,
history provenance changes, or the required verification cannot be completed.

## Preservation boundary

Private databases, raw evidence, keys, VM files, operator paths, and incident
records stay private. Do not copy them into source history or release assets.
