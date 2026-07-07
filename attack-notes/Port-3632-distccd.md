# Port 3632 — distcc Daemon Command Execution (CVE-2004-2687)

## Summary

| Field | Value |
|---|---|
| Target | Metasploitable 2 (192.168.75.130) |
| Service | distccd (Distributed Compiler Daemon) |
| CVE | CVE-2004-2687 |
| CVSSv2 | 9.3 (High) |
| Disclosure | 2002-02-01 |
| Privilege gained | `daemon` (uid=1, gid=1) — **not root** |
| Exploit path | Unauthenticated remote command execution |

## Root Cause

distccd is designed to accept compile jobs from trusted build-farm clients over
the network. It ships with **no authentication and no input validation** on
the compiler/argument fields in its wire protocol by default. Any client that
can reach the port can substitute an arbitrary binary (e.g. `/bin/sh`) in
place of a compiler invocation, resulting in unauthenticated RCE. This is a
weak-configuration issue, not a memory-safety bug — the daemon behaves exactly
as designed, just with an insecure trust assumption baked in.

## Attack Workflow

1. **Recon/confirmation** — `nmap -p 3632 <target> --script distcc-cve2004-2687 -oA distcc_confirm`
   Confirmed vulnerable; script's default proof command (`id`) returned
   `uid=1(daemon) gid=1(daemon) groups=1(daemon)` in the "Extra information"
   field — proving RCE without touching Metasploit.
2. **Second proof-of-exploit** — re-ran with explicit arg:
   `--script-args="distcc-cve2004-2687.cmd='hostname'"` → returned `metasploitable`.
   (Note: nmap.org's documented example references an older script name,
   `distcc-exec`; the installed nmap 7.99 only ships `distcc-cve2004-2687.nse`.
   Confirmed the real argument key by reading the NSE source directly —
   `stdnse.get_script_args(SCRIPT_NAME .. '.cmd')` — rather than trusting the
   doc page, which had drifted from the actual shipped script.)
3. **Interactive shell** — `exploit/unix/misc/distcc_exec` (rank: excellent).
   First payload attempt (`cmd/unix/reverse`, bash `/dev/tcp`) failed —
   target's bash wasn't compiled with `/dev/tcp` support. Switched to
   `cmd/unix/reverse_perl`, which succeeded (Perl is present on virtually
   every Debian/Ubuntu-derived box, unlike optional bash compile flags).
   Confirms this is a **command-shell payload, not Meterpreter** — no
   `sysinfo`/`getuid` support, since those are Meterpreter-protocol commands.
4. **Shell stabilization** — `python -c 'import pty; pty.spawn("/bin/bash")'`
   to upgrade the raw socket shell to an interactive TTY.
5. **Privilege check** — confirmed `daemon` user, consistent with steps 1–2.
   Attempted to read `/var/log/syslog` from within the shell — denied
   (permission error), demonstrating the attacker's own foothold has no
   visibility into host-level logging, separate from what a defender sees.

## Attacker Mindset

distcc is exactly the kind of service a real-world engagement finds through
"boring" full-port-range scans that turn up legacy/internal tooling exposed
where it shouldn't be — build farms, CI infrastructure, internal dev tools.
The interesting interview point isn't "I found an RCE," it's recognizing that
**not every RCE gets you root**, and that privilege level should shape your
next move (this foothold as `daemon` would typically be a pivot point for
further local privesc, not an end state).

## Detection Findings

- **No dedicated distccd log file exists** on Metasploitable — the service
  performs no audit logging by design, consistent with its zero-auth model.
- Low-priv shell (`daemon`) **cannot read `/var/log/syslog`** — a real gap
  between attacker-visible and defender-visible evidence.
- **Suricata (ET-Open ruleset) fired zero alerts.** Flow-level records show
  Suricata *did* capture every connection to port 3632, but application-layer
  protocol identification explicitly failed (`"app_proto": "failed"`) —
  meaning no content-based signature ever got a chance to evaluate this
  traffic. This is a protocol-identification gap, not a missing-rule gap —
  same failure mode previously documented on port 1099 (Java RMI).
- **Wazuh agentless showed zero alerts** for this activity — consistent with
  the standing finding that agentless `ssh_generic_diff` mode only diffs
  named, watched log files. Since distccd writes no dedicated log and this
  attack never touches `/var/log/auth.log`, there was no watched artifact
  for agentless mode to compare against in the first place — a structural
  blind spot, not a missed check.
- Outbound reverse-shell callback traffic to attacker port 4444 showed a
  **repeated short-lived connection/retry pattern** (~74B/54B per flow,
  RST-terminated, recurring roughly every 2 seconds over several minutes) —
  a stronger behavioral IOC than a single flow record would be.

**Open validation item:** eve.json flow timestamps for the port-4444 callback
traffic showed 2026-07-06, one day prior to the live exploitation date
(2026-07-07). Clock sync between Kali and Metasploitable (or system time vs.
capture time) needs to be verified before this timing is cited in the public
write-up.

## Detections

- [Sigma: DistCC Exploitation via Flow Anomaly](../sigma-rules/distcc-flow-anomaly.yml)
- [Sigma: Repeated Outbound Beaconing to Attacker Port](../sigma-rules/distcc-beacon-retry.yml)

## References

- https://nvd.nist.gov/vuln/detail/CVE-2004-2687
- https://distcc.github.io/security.html
