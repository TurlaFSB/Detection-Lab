# detection-lab

A structured attack-and-detect research lab built on Metasploitable 2, documenting real exploitation chains alongside detection artifacts for each service.

This is not a CTF writeup repository. The goal is to build the muscle for thinking offensively and defensively at the same time — the same muscle a detection engineer, threat hunter, or red teamer needs in practice.

Every entry follows the same loop:

**Attack → Detect → Document → Publish**

---

## Lab Environment

| Component  | Detail |
|------------|--------|
| Attacker   | Kali Linux — `192.168.75.129` |
| Target     | Metasploitable 2 — `192.168.75.130` |
| Network    | VMware host-only |
| IDS        | Suricata 8.0.5 |
| SIEM       | Wazuh 4.7.0 (Docker) |
| Host       | AMD Ryzen 7 8845HS, 16GB DDR5, RTX 4050 |

---

## Repository Structure

```
detection-lab/
├── attack-notes/            # Concise technical references per port/service
│   ├── port-21-ftp.md
│   ├── port-22-ssh.md
│   ├── port-23-telnet.md
│   ├── port-25-smtp.md
│   ├── port-80-http.md
│   ├── port-445-smb.md
│   ├── port-1099-rmi.md
│   ├── port-1524-ingreslock.md
│   ├── port-2049-nfs.md
│   ├── port-6667-irc.md
│   └── port-8180-tomcat.md
├── sigma-rules/              # Detection rules mapped to each attack chain
│   ├── ftp-anonymous-login.yml
│   ├── ssh-bruteforce.yml
│   ├── telnet-cleartext-auth.yml
│   ├── smtp-vrfy-enum.yml
│   ├── smb-psexec-lateral.yml
│   ├── rmi-exploit-detect.yml
│   ├── ingreslock-backdoor.yml
│   ├── nfs-no-root-squash.yml
│   ├── irc-malicious-join.yml
│   └── tomcat-manager-deploy.yml
└── README.md
```

---

## Coverage

> Medium links will be updated as posts go live.


Here is Medium Profile for detailed attack procedure : https://medium.com/@PranavVerma

---

## Attack Note Format

Every attack note follows a consistent structure:

1. **Service and version** — what's running and why it matters
2. **Exploitation chain** — exact commands, no hand-waving
3. **Attacker mindset** — why an attacker targets this service, what they're after
4. **Detection opportunity** — where in the chain defenders can catch it
5. **Sigma rule reference** — link to the corresponding rule in this repo

The notes are written as technical references, not tutorials. They assume you know how to operate the tools.

---

## Sigma Rule Approach

Rules are written against real log sources from this lab:

- Wazuh agentless `ssh_generic_diff` monitoring `/var/log/auth.log` on Metasploitable
- Suricata `eve.json` for network-layer detection
- Syslog for service-specific events

Each rule documents the detection gap context — where Suricata's default ET-Open ruleset missed, and why a custom rule was necessary. Known limitations are stated explicitly rather than glossed over.

---

## Known Detection Gaps

Part of doing this honestly is documenting what doesn't work:

- **Wazuh agentless `ssh_generic_diff`** has zero visibility into in-process command execution. It detects file changes, not commands run in active sessions. This is an architectural gap, not a configuration error.
- **Suricata ET-Open** fired zero alerts across most attack chains in this lab. Default rulesets are tuned for generic internet traffic, not controlled lab exploitation — custom rules are mandatory for meaningful coverage.
- **Port 6667 Sigma rule** was published before full validation against real `eve.json` field structure — flagged as a gap pending re-validation.

---

## Methodology

Each port follows the PTES (Penetration Testing Execution Standard) phases:

**Reconnaissance → Scanning → Exploitation → Post-Exploitation → Detection → Documentation**

The detection layer runs concurrently — Suricata and Wazuh are live during every attack chain, and gaps in their coverage are treated as findings, not failures.

---



## Author
Pranav verma 

(TURLA)

> *"The best way to learn detection is to build the attack first."*
