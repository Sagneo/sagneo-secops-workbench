# Report 06: Reproducibility and CI Controls

Classification: synthetic / sanitized

The repository defines one automated foundation workflow and matching local checks
for:

- Python 3.12 dependency installation from hash-locked requirement files;
- database migration through the current Alembic head;
- unit and integration tests;
- Ruff linting and formatting checks;
- strict mypy analysis;
- Bandit static security analysis;
- release-readiness and privacy regression checks.

The deterministic fixture demo provides an independent functional check:

- 1,201 accepted normalized events and 2 isolated parser errors;
- 665 alerts on first evaluation and 0 new alerts on replay;
- 1,555 alert-event links;
- SQLite integrity result `ok`.

This artifact describes the reproducibility controls and expected bounded results.
The source-hosting platform remains authoritative for the status of any particular
commit or workflow run.

What this proves: the project includes repeatable automated checks and a
deterministic offline functional path.

What this does not prove: production reliability, continuous monitoring, external
audit, or operational SLA performance.
