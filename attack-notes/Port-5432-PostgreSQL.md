# Port 5432 — PostgreSQL (Metasploitable 2)

## Target
- Host: 192.168.75.130
- Service: PostgreSQL 8.3 (Metasploitable 2 default)
- Attacker: 192.168.75.129 (Kali)

## Discovery
- `nmap -sV -sC -p 5432 -oA nmap_5432_postgres 192.168.75.130` confirmed PostgreSQL 8.3 on port 5432.
- Manual connection via `psql -h 192.168.75.130 -U postgres` succeeded with default credentials (`postgres`/blank or trivially guessable), confirming no meaningful authentication barrier.
- Superuser access confirmed (`usesuper = true`), opening up `pg_shadow` credential access and large-object file I/O.

## Exploitation
1. Credential harvesting via `SELECT usename, passwd FROM pg_shadow;` — dumped password hashes for all roles (superuser-only table).
2. Arbitrary file read confirmed via `lo_import()` / `lo_export()` against `/etc/passwd`.
3. Attempted command execution via non-existent `shell_out()` function calls — failed, confirming no such UDF pre-exists (expected; PostgreSQL 8.3 has no default RCE function).
4. Attempted file write via `COPY (SELECT 'test') TO '/var/www/test.txt';` — blocked with `Permission denied`, confirming filesystem permissions prevented a webshell-drop route via COPY.
5. UDF-based RCE attempted via Metasploit's `postgres_payload` module: uploaded a compiled shared object to `/tmp/*.so` and issued `CREATE OR REPLACE FUNCTION ... LANGUAGE C STRICT IMMUTABLE`.
   - Result: **failed** — `incompatible library: missing magic block`. The uploaded `.so` did not include the required `PG_MODULE_MAGIC` macro for this exact PostgreSQL 8.3 build, so full RCE was not achieved in this session.

## Detection — Application Log (validated)
PostgreSQL logs on this host (`postgresql-8.3-main.log`) captured every stage of the attack in plaintext, since `log_statement` was enabled:
- Pre-auth noise: malformed startup packets, SSL negotiation failures, repeated Ident auth failures for `postgres` and `msfadmin`.
- RCE reconnaissance: failed `shell_out()` calls, blocked `COPY ... TO` file write.
- RCE attempt: `CREATE OR REPLACE FUNCTION ... LANGUAGE C` referencing `/tmp/*.so`, followed by `incompatible library ... missing magic block`.

Four Sigma rules were written and validated line-by-line against this captured log:
- `postgres_udf_rce_creation.yml` — critical — the actual RCE attempt (C function creation from /tmp)
- `postgres_incompatible_library_load.yml` — high — failed .so load, strong RCE-attempt indicator
- `postgres_rce_probing.yml` — medium — reconnaissance for RCE primitives (shell_out probing, COPY write attempts)
- `postgres_ident_auth_failures.yml` — low — repeated auth failures against default accounts

## Detection — Network Layer (gap identified, not a rule)
Suricata was running throughout the attack (capturing from first packet). Findings:
- **Zero `alert` events** — the default Suricata ruleset did not recognize this traffic as malicious at any stage.
- `flow` events only logged connection metadata (byte counts, TCP flags, timing) — **no payload capture was enabled**, so the actual query content (`CREATE FUNCTION`, `LANGUAGE C`, etc.) was never recorded at the network layer, even though PostgreSQL's wire protocol is cleartext here.
- One connection was misclassified by Suricata's protocol-detection engine as `app_proto: smb`, meaning protocol-specific parsing never engaged for that flow.

**Conclusion:** with app-level logging enabled, detection is solid. If `log_statement` were disabled (a realistic misconfiguration), this attack would have been effectively invisible — Suricata's default ruleset provides no coverage, and payload capture was not active. A follow-up session will revisit this port with `payload: yes` / `payload-printable: yes` enabled in Suricata's `eve-log` config to build a working network-layer Sigma rule as defense-in-depth.

## MITRE ATT&CK Mapping
- T1190 — Exploit Public-Facing Application
- T1059 — Command and Scripting Interpreter
- T1082 — System Information Discovery
- T1110 — Brute Force / Credential Guessing
- T1003 — Credential Access (pg_shadow)

## Sigma Rules
See `/sigma-rules/postgres_udf_rce_creation.yml`,
 `/sigma-rules/postgres_incompatible_library_load.yml`,
  `/sigma-rules/postgres_rce_probing.yml`,
   `/sigma-rules/postgres_ident_auth_failures.yml`