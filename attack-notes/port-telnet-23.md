# Port 23 — Telnet (Metasploitable 2)

## Service Identification

- **Port/Protocol:** 23/TCP
- **Service:** Telnet (in.telnetd, via xinetd)
- **Target:** Metasploitable 2 (192.168.75.130)
- **Risk:** Unencrypted authentication and session traffic; legacy daemon with minimal logging

## Enumeration
nmap -p 23 -sV 192.168.75.130

Confirmed open Telnet service. Initial attempt at credential brute-forcing used Hydra:
hydra -l msfadmin -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt telnet://192.168.75.130 -t 4 -V

This proved slow and unreliable as a primary access vector — Hydra's parsing of Telnet's non-standard prompt/response sequence is inherently fragile (Hydra's own warning confirms this: *"telnet is by its nature unreliable to analyze"*).

## Exploitation — Actual Access Path

Rather than rely on Hydra to gain access, the working approach used the **port 1524 root backdoor** (already established as a prior checklist item) to reset the `msfadmin` password directly:
nc 192.168.75.130 1524

passwd msfadmin

With a known password, direct Telnet login was then trivial:
telnet 192.168.75.130

**What was gained:** Direct shell access as `msfadmin`, bypassing the need for a successful brute-force guess. This reflects a realistic attacker decision: when a faster, more reliable path to credentials exists (a misconfigured backdoor service), a noisy and slow brute-force isn't the efficient choice — but Hydra was still run deliberately, as a separate exercise, to generate realistic attacker-pattern traffic for detection validation (see below).

## Detection Engineering Investigation

This port produced a more involved investigation than previous ones, because the intended detection logic ("repeated auth-failure-from-one-source") turned out to be **unbuildable as originally scoped** — and tracing why was the actual engineering work.

### Finding 1: Telnet auth events are not logged on this target

`in.telnetd` on this Metasploitable 2 build (Ubuntu 8.04 Hardy, glibc 2.7) logs only the TCP connection event:
in.telnetd[PID]: connect from <ip> (<ip>)

No authentication success or failure is ever written to `/var/log/auth.log` or `/var/log/syslog`. Confirmed via:
grep -i telnet /var/log/auth.log   # empty

grep -i telnet /var/log/syslog     # connection events only, no auth result

This rules out an auth-failure-based detection entirely — the data needed simply doesn't exist on this target. The detection had to be reframed from **authentication failure** to **connection volume/frequency**, a realistic compensating approach for legacy services with weak logging.

### Finding 2: Agentless monitoring cannot drive rule-based detection

Metasploitable 2's OS (Ubuntu 8.04, glibc 2.7) predates compatibility with modern Wazuh agent binaries — confirmed directly rather than assumed. Agentless `ssh_generic_diff` monitoring was therefore the architecturally correct choice, not a fallback.

However, empirical testing proved a deeper limitation: **`ssh_generic_diff` captures file diffs but never routes their content through `wazuh-analysisd` for decoding/rule-matching.** This was confirmed by:

1. Retargeting the agentless monitor from `auth.log` to `syslog` (where `in.telnetd` events actually appear)
2. Running a real Hydra brute-force to generate attack traffic
3. Locating the raw diff file in `/var/ossec/queue/diff/.../diff.<timestamp>` and confirming it **did** contain 236 `in.telnetd: connect from` lines from the attack
4. Confirming via `grep` against `alerts.log` that **zero** of Wazuh's built-in telnetd rules (5602, 5631) ever fired on this data

This proves agentless diff mode is integrity monitoring (notifying that a file changed) rather than log analysis (parsing what changed) — a meaningful distinction not always made clear in Wazuh documentation.

### Finding 3: Syslog forwarding pipeline validated independently, blocked by host networking

To get real-time decoding, a `<remote><connection>syslog</connection></remote>` listener was added to `ossec.conf`, and Metasploitable's classic `sysklogd` was configured to forward via `/etc/syslog.conf`. The pipeline was proven correct in isolation:

- Manual UDP injection from the Wazuh manager's own host (via `.NET UdpClient` to `127.0.0.1:514`) successfully triggered **Wazuh rule 5602** with correct decoding, end to end.

The remaining failure was isolated to the network path, not the detection pipeline itself: Metasploitable's primary interface (`eth0`) was discovered to be on a **NAT** network (192.168.75.0/24), not the intended Host-only network — a second NIC (`eth1`) had to be brought up to join the correct Host-only segment (192.168.16.0/24). Even after fixing routing and a Windows Firewall rule blocking the unclassified VMware adapter, traffic from any real network interface (including the Windows host's own non-loopback IP) failed to reach the Dockerized Wazuh manager — a known limitation of Docker Desktop's WSL2 backend, which reliably forwards published ports only via loopback.

**Decision:**
 Given time constraints and that the next target (Windows Server, with a real Wazuh agent) will not suffer this limitation, the syslog-forwarding fix was not pursued further. The detection logic was instead validated manually against captured evidence.

### Manual Validation

Using the diff file captured during the live Hydra run (`diff.1781776924`, containing 236 real `in.telnetd` connection events), the candidate detection threshold was checked directly:
grep "in.telnetd" diff.1781776924 | grep "Jun 16 07:50|Jun 16 07:51"

Result: **6 connection attempts from source IP 192.168.75.129 within 62 seconds** — satisfying a 6-events/120-second/same-source-IP threshold. This confirms the rule logic (modeled directly on Wazuh's own built-in rule 5631, which uses identical thresholds and is MITRE-tagged T1110) would have fired correctly had the live pipeline not been blocked by host networking.

## Sigma Rule

See [`sigma-rules/telnet_multiple_connections_bruteforce.yml`](../sigma-rules/telnet_multiple_connections_bruteforce.yml)

## MITRE ATT&CK Mapping

- **T1110 — Brute Force** (credential access)

## Real-World Context

Legacy Telnet deployments are still found in embedded systems, industrial control systems (ICS/SCADA), and unmanaged legacy infrastructure — environments where minimal/non-existent auth logging is common, not exceptional. This investigation demonstrates that **detection engineering frequently requires designing around a logging gap rather than assuming rich telemetry exists** — and that platform limitations (agentless mode, containerized SIEM networking) must be understood and validated, not assumed to "just work."

## Interview Articulation

*"I found that Telnet's logging only captured connection events, not authentication results  so I couldn't build an auth-failure detection. I reframed it as connection-frequency-based brute-force detection instead, validated the exact threshold logic against Wazuh's own built-in ruleset, and then proved my Sigma rule's logic against real captured attack data by hand  because the live alerting pipeline hit a genuine platform limitation (Docker Desktop's WSL2 networking) that I traced down to the root cause, rather than guessing. I documented that limitation transparently instead of hiding it, because knowing where your tooling breaks is as important as knowing how to use it."*