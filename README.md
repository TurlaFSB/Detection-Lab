Detection-lab

A structured attack-and-detect research lab built on Metasploitable 2, documenting real exploitation chains alongside detection artifacts for each service. Every entry follows the same loop: attack → detect → document → publish.

This is not a CTF writeup repository. The goal is to build a muscle for thinking offensively and defensively at the same time — the same muscle a detection engineer, threat hunter, or red teamer needs in practice.


Lab Environment

ComponentDetailAttackerKali Linux 192.168.75.129
TargetMetasploitable 2 192.168.75.130
NetworkVMware host-onlyIDS
Suricata 8.0.5
SIEMWazuh 4.7.0 
(Docker)HostAMD Ryzen 7 8845HS, 16GB DDR5, RTX 4050


Repository Structure

detection-lab/
├── attack-notes/        # Concise technical references per port/service
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
├── sigma-rules/         # Detection rules mapped to each attack chain
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


Coverage

Each row is a completed attack-detect pair. Attack notes document the exploitation chain and attacker methodology. Sigma rules target the specific log events that betray each technique.

PortServiceTechniqueSigma RuleWriteup21FTPAnonymous login, arbitrary file read/write✅Medium22SSHBruteforce via Hydra, key-based persistence✅Medium23TelnetCleartext credential capture, session hijack✅Medium25SMTPVRFY/EXPN user enumeration✅Medium80HTTPApache misconfig, webshell upload✅Medium445SMBPsExec-style lateral movement via Metasploit✅Medium1099Java RMIRemote class loading, RCE via ysoserial✅Medium1524IngreslockPre-planted root backdoor, instant shell✅Medium2049NFSno_root_squash abuse, SSH key planting✅Medium6667IRCUnrealIRCd backdoor, reverse shell trigger✅Medium8180TomcatManager WAR deploy, JSP webshell → RCE✅Medium


Medium links will be updated as posts go live.




Attack Note Format

Every attack note follows a consistent structure:


Service and version — what's running and why it matters
Exploitation chain — exact commands, no hand-waving
Attacker mindset — why an attacker targets this service, what they're after
Detection opportunity — where in the chain defenders can catch it
Sigma rule reference — link to the corresponding rule in this repo


The notes are written as technical references, not tutorials. They assume you know how to operate the tools.


Sigma Rule Approach

Rules are written against real log sources from this lab:


Wazuh agentless ssh_generic_diff monitoring /var/log/auth.log on Metasploitable
Suricata eve.json for network-layer detection
Syslog for service-specific events


Each rule documents the detection gap context — where Suricata's default ET-Open ruleset missed, and why a custom rule was necessary. Known limitations are stated explicitly rather than glossed over.


Known Detection Gaps (Documented)

Part of doing this honestly is documenting what doesn't work:


Wazuh agentless ssh_generic_diff has zero visibility into in-process command execution. It detects file changes, not commands run in active sessions. This is an architectural gap, not a configuration error.
Suricata ET-Open fired zero alerts across most attack chains in this lab. Default rulesets are tuned for generic internet traffic, not controlled lab exploitation. Custom rules are mandatory for meaningful coverage.
Port 6667 Sigma rule was published before full validation against real eve.json field structure — flagged as a gap pending re-validation.



Methodology

Each port follows the PTES (Penetration Testing Execution Standard) phases:

Reconnaissance → Scanning → Exploitation → Post-Exploitation → Detection → Documentation

The detection layer runs concurrently — Suricata and Wazuh are live during every attack chain, and gaps in their coverage are treated as findings, not failures.


Related


Internship: VAPT at Net Access India Limited — web application testing (DVWA, real targets)
Certifications in progress: eJPT (Sem 6 target)
Next lab: Active Directory (Kerberoasting, BloodHound, Pass-the-Hash)



Author

B.Tech Computer Science (Cybersecurity) — SRM University
Actively exploring Detection Engineering, Threat Intelligence, and Digital Forensics.


"The best way to learn detection is to build the attack first."
