# Port 5432 - PostgreSQL 8.3.x Remote Code Execution

## Target
- Service: PostgreSQL 8.3.0 - 8.3.7
- Host: Metasploitable 2 (192.168.75.130)
- OS: Ubuntu 8.04

## Summary
PostgreSQL 8.3.x on this host accepts unauthenticated-adjacent superuser access via a permissive `pg_hba.conf` (`host all all 0.0.0.0/0 md5`) combined with default `postgres/postgres` credentials. Superuser access to PostgreSQL on Linux permits arbitrary C shared library loading via `CREATE FUNCTION ... LANGUAGE C`, which Metasploit's `postgres_payload` module weaponizes into a full Meterpreter reverse shell.

## Discovery
- `nmap -sV -sC -p 5432` confirmed PostgreSQL 8.3.0-8.3.7
- `pg_hba.conf` showed `host all all 0.0.0.0/0 md5` — remote auth permitted from any source
- Local `ident sameuser` auth blocked direct OS-user login attempts (msfadmin/postgres mismatch)
- Manual enumeration via `sudo -u postgres psql` confirmed single superuser role (`postgres`), no additional databases or users

## Exploitation
- `exploit/linux/postgres/postgres_payload` (Metasploit) — authenticates with default `postgres/postgres` credentials over RHOSTS:5432
- Module compiles a payload shared object (`.so`), attempts to load it via `CREATE FUNCTION ... LANGUAGE C` from `/tmp/`
- Result: Meterpreter session running as `postgres` OS user

## Detection Gap
- **Suricata (network layer):** Zero alerts fired. Default ruleset has no signature for PostgreSQL wire-protocol exploitation; traffic appears as a standard TCP session to 5432 with no payload-layer inspection triggered.
- **PostgreSQL server log (application layer):** Full attack visibility. `postgresql-8.3-main.log` captured both the initial payload attempt (`incompatible library ... missing magic block`) and the successful follow-up (`create or replace function ... language c`), confirming iterative exploitation attempts before success.
- **Conclusion:** Network-layer detection alone is insufficient for this class of attack. Application-layer logging (PostgreSQL's own log) is the only reliable detection surface — reinforcing the standing finding across this lab that Suricata's default ruleset does not cover legacy/application-specific RCE chains.
## Sigma Rules 
postgres_incompatible_library_load.yml
postgres_rce_probing.yml
postgres_udf_rce_creation.yml

## MITRE ATT&CK
- T1190 — Exploit Public-Facing Application
- T1505.003 — Server Software Component (functional equivalent: malicious C extension as persistence/execution vector)

## Remediation Notes
- Restrict `pg_hba.conf` to `md5` auth only from known internal hosts, never `0.0.0.0/0`
- Disable default `postgres/postgres` credential pattern
- Restrict `CREATEFUNCTION` privilege for superuser roles where untrusted language use isn't required
- Monitor `postgresql.log` for `LANGUAGE C` function creation events — this alone would have caught the attack pre-success
