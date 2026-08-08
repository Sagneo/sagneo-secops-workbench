# Report 04: Collection Approval, Manifest, and Tamper Failure

Classification: synthetic / sanitized
Source: bounded replacement request, bundle, and verification

## Approval and execution

- target: `linux-endpoint-01` on the private lab subnet;
- adapter: fixed `SshLabCollector`;
- profile: `linux-ir-lite-v1`;
- Reviewer decision preceded the accepted Analyst execution;
- original FAILED request remains immutable; the replacement SUCCEEDED.

## Sanitized manifest summary

Exactly eight allowlisted regular text artifacts were accepted:

`utc_time`, `system`, `processes`, `network`, `logins`, `failed_services`,
`ssh_sudo_journal`, and `ssh_config_metadata`.

Aggregate artifact bytes: 61,910. The committed verifier returned PASS against the
trusted manifest with bounded path, link, file-identity, per-file, and total-size
checks.

## Tamper failure

A separate preserved verification record reports an artifact-modification failure
and is linked to the single `EVID-001` alert. No raw artifact content, bundle
identifier, key, account, or private path is included here.

SHA-256 proves that the bytes presented to verification agree with a trusted
manifest. It does not prove authenticity or completeness before hashing, custody
outside the lab, or legal admissibility.
