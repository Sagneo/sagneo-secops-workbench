# Synthetic Lab Evidence Index

Classification: synthetic and sanitized aggregate evidence
Set: exactly six artifact files

| Slot | Artifact | SHA-256 | Bytes | Technical source |
|---:|---|---|---:|---|
| 1 | [`01_SOURCE_HEALTH.md`](reports/01_SOURCE_HEALTH.md) | `32fd83a20bfbd54d491aa060125e9a01fb2febf33a86406363fedea86d6005f0` | 939 | telemetry manifest and runtime validation |
| 2 | [`02_ALERT_TRIAGE.md`](reports/02_ALERT_TRIAGE.md) | `0edd0dd01536750a20278320fff88d6540b653ad5b3b679a1d2c833681459dfe` | 996 | deterministic rule evaluation and triage |
| 3 | [`03_CASE_TIMELINE.md`](reports/03_CASE_TIMELINE.md) | `a0978ac640fcb0364673cc83b58a9226a7e0e3067c9c22aa210895e79f4ce004` | 1,238 | application case timeline |
| 4 | [`04_COLLECTION_AND_INTEGRITY.md`](reports/04_COLLECTION_AND_INTEGRITY.md) | `97a963f5b41baef527c325b0bfb50ced86a7d905c081a5477045b39b543eaa75` | 1,282 | bounded collection and manifest verification |
| 5 | [`05_PROCESS_IMPROVEMENT.md`](reports/05_PROCESS_IMPROVEMENT.md) | `2122b111cefaffe58897c099afa58e171bda2d7a4e3513139d8e9cf714859116` | 941 | fixed-protocol aggregate measurement |
| 6 | [`06_REPRODUCIBILITY_CONTROLS.md`](reports/06_REPRODUCIBILITY_CONTROLS.md) | `9ababe32cc650523e6caba1ba799d20bb50f24d981e252073a58a85dae487f46` | 1,167 | reproducibility and CI controls |

Any byte change to an artifact requires updating its digest and rerunning the
privacy and integrity checks.
