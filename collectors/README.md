# Restricted fixed-profile collector

`linux-ir-lite-v1` is the only endpoint forced-command wrapper. The dedicated
`secopscollector` account has a locked password and a distinct key whose
`authorized_keys` entry must use both `restrict` and the exact forced command:

`sudo -n /usr/local/sbin/sagneo-linux-ir-lite-v1`

OpenSSH invokes forced commands through the account login shell. Therefore the
account requires `/bin/sh`; `/usr/sbin/nologin` prevents the forced command from
running. This does not grant an interactive shell because the sole authorized
key is forced and restricted, password authentication is locked, and the exact
sudoers entry permits only the root-owned wrapper.

The wrapper reads each fixed command through bounded stdout/stderr pipes while
the child is running. It terminates and reaps a child at five seconds, at one
byte beyond the 1 MiB artifact limit, or at the aggregate 5 MiB limit. It emits
no protocol records until all eight artifacts have completed successfully. The
client applies a conservative base64/JSON protocol ceiling derived from the
decoded 5 MiB limit and separately limits stderr.

Evidence verification accepts only the canonical eight-entry manifest schema
and exact flat `artifacts/<allowlisted-name>.txt` paths. Schema/path/link checks
finish before artifact access; regular files are opened without following links
where supported, identity-checked, and hashed through `limit + 1` streaming.

The final lab state must revoke the account, key, wrapper, sudoers entry, and its exact firewall
allowance. No arbitrary command, argument, path, forwarding, or additional key
is permitted.
