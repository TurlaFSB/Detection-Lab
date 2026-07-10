# Port 5900 - VNC (Virtual Network Computing)

## Target Information
- **Target:** Metasploitable 2 (192.168.75.130)
- **Attacker:** Kali Linux (192.168.75.129)
- **Port/Protocol:** 5900/tcp
- **Service:** VNC (RFB Protocol)
- **Date:** 2026-07-10

## Reconnaissance

### Service Enumeration
Confirmed the service and available authentication mechanisms before any exploitation attempt:
nmap --script vnc-info -p 5900 192.168.75.130 -oA vnc_info_scan

**Result:**
PORT     STATE SERVICE
5900/tcp open  vnc
| vnc-info:
|   Protocol version: 3.3
|   Security types:
|_    VNC Authentication (2)

**Analysis:** Security type 2 (VNC Authentication) confirmed password-based challenge-response auth is active — ruling out two other candidate attack paths before they were attempted:
- `realvnc-auth-bypass` (CVE-2006-2369) — not applicable; this targets a specific RealVNC 4.1.1-derived handshake flaw, and the negotiated security type here shows standard auth, not the vulnerable negotiation behavior.
- No-auth bypass — not applicable; security type 1 (None) was not offered.

## Exploitation

### Credential Validation
msfconsole -q
use auxiliary/scanner/vnc/vnc_login
set RHOSTS 192.168.75.130
run

**Result:**
[+] 192.168.75.130:5900 - Login Successful: :password

**Finding:** No credential research was required. The module's default `PASS_FILE` (`/usr/share/metasploit-framework/data/wordlists/vnc_passwords.txt`) already contains Metasploitable2's documented default password (`password`, blank username). Compromise required zero customization of the scan — a stock, un-tuned Metasploit run succeeds against this target immediately. This lowers the effective skill floor for exploitation to near zero and is worth noting as a severity amplifier in any report referencing this finding.

### Session Establishment
Validated credentials, obtained full interactive access via native VNC client:
vncviewer 192.168.75.130
Result: Full GUI desktop access to the target as `root` (X session owned by root per `ps aux` output — see Detection section), with no further exploitation required. Interactive control equivalent to physical console access.

## CVE / Weakness Reference
- **CVE-1999-0506** — generic weak/guessable password (umbrella CVE Metasploit tags this finding under; not VNC-specific).
- VNC protocol weakness: DES-based challenge-response truncates passwords to 8 characters, discarding any additional characters — a structural weakness independent of the specific password chosen, worth citing separately from the CVE.

## Detection Analysis

### Host-Based Logging — Confirmed Gap
Process inspection on the target:
ps aux | grep vnc

root  5280  0.0  2.5 ... Xtightvnc :0 -desktop X -auth /root/.Xauthority ... -rfbauth /root/.vnc/passwd -rfbport 5900 ...

**Finding:** No `-rfblog` flag present in the launch command. Confirmed via:
grep -i vnc /var/log/auth.log
grep -i vnc /var/log/syslog
grep -i vnc /var/log/messages
All three returned empty. **VNC authentication and session establishment on this host produce zero host-based log evidence under default configuration.** This is a harder gap than the niche-protocol `app_proto: failed` cases documented on prior ports (RMI, NFS, distccd) — there, Suricata at least flagged the protocol as unparsed. Here, the *host itself* is structurally blind regardless of network monitoring capability. Wazuh agentless (SSH/auth.log-based) has nothing to ingest for this service by design of the target's VNC daemon configuration.

### Network-Based Detection — Suricata RFB Parser
Unlike the host layer, Suricata 8.0.5 ships a native RFB application-layer parser and fully decodes the VNC handshake, including protocol version negotiation, security type, DES challenge/response pair, and (post-auth) framebuffer metadata:

```json
{
  "event_type": "rfb",
  "rfb": {
    "authentication": {
      "security_type": 2,
      "vnc": { "challenge": "...", "response": "..." },
      "security_result": "OK"
    },
    "screen_shared": true,
    "framebuffer": {
      "width": 1024, "height": 768,
      "name": "root's X desktop (metasploitable:0)"
    }
  }
}
```

**Validated behavior:** `security_result: "OK"` was consistently and reliably populated across every successful authentication observed (6/6 confirmed instances).

**Validated limitation:** A deliberately triggered failed login (Metasploit `vnc_login` with an incorrect password, confirmed failed via msfconsole output: `LOGIN FAILED: :wrong`) produced **no `security_result` value at all** in the corresponding Suricata event — not `"fail"`, not any value. Cross-checked across the full `eve.json` log (`grep -c '"security_result":"fail"'` → 0 matches ever). This is a parser-level gap in Suricata 8.0.5's RFB implementation for this server's protocol version (RFB 3.3), not a protocol- or configuration-level gap on the target. Documented as a known limitation rather than worked around blindly — a rule built on `rfb.secresult:fail` would silently never fire against this target class.

## Sigma Rules

See `sigma-rules/vnc-successful-auth.yml` and `sigma-rules/vnc-auth-indeterminate.yml`.

Rule 1 (successful auth) is `status: stable` — validated against 6 real successful authentication events.
Rule 2 (failed/indeterminate auth) is `status: experimental`, `level: low` — validated that it *doesn't* false-negative on the confirmed failed-login test case, but documented as a best-effort proxy given the parser limitation above, not a clean high-confidence signal.

## Attacker Perspective
VNC's blank-username/single-password model, combined with Metasploitable2's inclusion in Metasploit's own default wordlist, means this port requires no reconnaissance beyond port/service discovery to fully compromise. From an attacker's decision tree: any host presenting a VNC service is worth an automated credential sweep as a near-zero-cost action before investing in more complex exploitation elsewhere — the cost/reward ratio strongly favors trying VNC default creds early in an engagement.

## Defender Perspective
This port is a clear illustration of why network-layer (Suricata/NDR) visibility must be treated as a **primary** detection control for certain services, not a supplement to host logging — VNC on this host has no host-log detection path at all. It also illustrates a secondary, more subtle risk: even where network-layer visibility exists, parser coverage can be asymmetric (catches success, misses failure), which would blind a SOC to brute-force/credential-stuffing attempts against VNC while still catching the eventual successful compromise. Recommend: (1) enforce `-rfblog` on any VNC deployment as a compensating host control, (2) treat any `security_type:2` RFB event without a same-flow `security_result:OK` correlation as worth manual review pending parser fix, rather than assuming absence of a fail flag means absence of a failed attempt.

## MITRE ATT&CK Mapping
- **T1021.005** — Remote Services: VNC
- **T1110** — Brute Force (credential sweep against default wordlist)
- **T1078** — Valid Accounts (post-compromise, credential reuse potential)