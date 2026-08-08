# Report 05: Measured Process Improvement

Classification: synthetic / sanitized
Source: fixed-protocol aggregate measurement

| Run | Identity lookup SQL | Total SQL | Wall seconds | Process seconds | Created | Duplicates |
|---|---:|---:|---:|---:|---:|---:|
| Baseline | 666 | 674 | 0.235733 | 0.233877 | 0 | 666 |
| Improved | 1 | 9 | 0.059567 | 0.058258 | 0 | 666 |
| Confirmation | 1 | 9 | 0.068088 | 0.067134 | 0 | 666 |

Primary result: identity lookup statements decreased from 666 to 1, a 99.85%
reduction, reproduced by confirmation. The first improved wall time was 74.73%
lower. Every run preserved five rules, 666 candidates, zero created alerts, 666
duplicates, stable identities, rule distribution, and 1,555 links.

What this proves: one bounded deduplication improvement under a locked same-fixture
SQLite protocol.

What this does not prove: concurrent, distributed, enterprise, other-database, or
production performance.
