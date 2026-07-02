## Target
Metasploitable2 — 192.168.75.130:1099 (rmiregistry)

## Vulnerability
Java RMI registry running with no `SecurityManager` set, allowing the
registry to load classes from an arbitrary remote HTTP codebase URL
specified by a client, with no authentication and no whitelist on
allowed codebases. This is a default-configuration weakness in older
RMI implementations (pre-hardening), not a memory-corruption bug —
the "vulnerability" is a legitimate dynamic class-loading feature
with no trust boundary.

## Recon
nmap -sV -p 1099 --script=rmi-dumpregistry,rmi-vuln-classloader 192.168.75.130 -oA recon/port1099_nmap
- `rmi-vuln-classloader`: confirmed VULNERABLE — default config allows
  remote class loading → RCE
- `rmi-dumpregistry`: no bound objects returned — vulnerability is not
  dependent on what's registered in the registry

Verified independently with:
auxiliary/scanner/misc/java_rmi_server
→ `Java RMI Endpoint Detected: Class Loader Enabled` (cross-validates Nmap finding)

## Exploitation
exploit/multi/misc/java_rmi_server
payload: java/meterpreter/reverse_tcp
Module stands up a local HTTP server (SRVHOST/SRVPORT) hosting a
malicious `.jar`, sends an RMI call instructing the registry to load
a class from that codebase URL, target JVM fetches and executes it,
staged Meterpreter payload calls back to LHOST:LPORT.

Result: Meterpreter session as **root** (RMI service runs as root on
Metasploitable2 — unauthenticated network service at highest privilege
is a notable finding on its own).

## Detection Analysis

**Wazuh (agentless, ssh_generic_diff):** No visibility. This attack is
pure network/application-layer traffic (TCP 1099, HTTP 8080, TCP 4444)
— nothing touches the filesystem or auth log that agentless SSH-diff
monitoring would catch.

**Suricata (default ruleset):** Zero alerts fired across the entire
attack chain (nmap scan, scanner probe, exploit). Consistent with
findings on port 8180 — default/ET-open rulesets do not cover
application-layer exploitation of legacy/non-standard services.

**Raw traffic captured (validated in eve.json):**
- RMI protocol traffic (dest_port 1099) logged only as generic `flow`
  events — `app_proto: failed`, Suricata has no RMI protocol parser,
  so no usable application-layer fields exist for detection here.
- HTTP payload-delivery stage (dest_port 8080) fully parsed by
  Suricata's HTTP logger — target JVM fetched `.jar` via HTTP with
  `User-Agent: gnu-classpath/...` — this is the strongest and most
  generalizable detection opportunity, independent of RMI port or CVE.

## Sigma Rule
[`sigma-rules/rmi-classloader-jar-fetch.yml`](../sigma-rules/rmi-classloader-jar-fetch.yml)

Detects `gnu-classpath` User-Agent + `.jar` URL over HTTP — flags the
payload-delivery stage of Java RMI/dynamic-classloader exploitation
regardless of target RMI port or specific Metasploit module used.

## Key Finding
Detection at the RMI protocol layer is currently not viable without a
custom Suricata protocol parser or app-layer signature — Suricata has
no RMI decoder. The only reliable detection surface for this attack
class is the **HTTP codebase fetch**, since that's where Suricata's
built-in HTTP logger has full visibility. This reinforces a pattern
from prior ports: default IDS coverage tracks common/modern protocols,
not legacy enterprise services still present in real environments.