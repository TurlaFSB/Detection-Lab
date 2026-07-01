Artifact 1 — GitHub Attack Note
This goes in attack-notes/port-8180-tomcat.md. Format is concise technical reference, not a tutorial — the kind of thing a senior engineer reads in 2 minutes and gets full picture:
markdown# Port 8180 — Apache Tomcat 5.5 | Manager WAR Deployment → RCE

## Target
- Service: Apache Tomcat/Coyote JSP Engine 1.1
- Version: Apache Tomcat 5.5 (EOL since 2012)
- Port: 8180/tcp
- Host: 192.168.75.130 (Metasploitable 2)

## Vulnerability Class
Exposed Tomcat Manager application with default credentials.
No brute-force required — default cred `tomcat:tomcat` authenticated
on first attempt. Manager API allows authenticated WAR deployment,
which Tomcat executes with full JVM privileges as service user `tomcat55`.

This is not a CVE — it is legitimate application functionality
abused via credential failure. The attack surface is:
`default creds + exposed admin interface + no MFA/lockout = RCE as a feature`.

## Attack Chain
1. **Recon** — nmap -sV -sC confirmed Tomcat 5.5, banner via Apache-Coyote/1.1
2. **Auth probe** — curl -v to /manager/html returned 401 with
   `WWW-Authenticate: Basic realm="Tomcat Manager Application"`
   confirming HTTP Basic Auth (base64, no encryption)
3. **Default cred** — `tomcat:tomcat` returned 200 on first attempt.
   `Authorization: Basic dG9tY2F0OnRvbWNhdA==` decodes to `tomcat:tomcat`
4. **Payload generation** — msfvenom java/jsp_shell_reverse_tcp → shell.war
   WAR structure: WEB-INF/web.xml (deployment descriptor) +
   zzdwcyvvzt.jsp (randomized-name reverse shell)
5. **Deployment** — PUT to /manager/deploy?path=/shell via Tomcat 5.5 API
   (Note: /manager/text/ path is Tomcat 6+, doesn't exist on 5.5)
6. **Execution** — GET /shell/zzdwcyvvzt.jsp triggered JVM execution,
   reverse TCP shell landed on nc -lnvp 4444
7. **Access** — uid=110(tomcat55) gid=65534(nogroup), kernel 2.6.24-16-server

## Key Recon Finding
Tomcat 5.5 logs via jsvc SYSLOG flag — no files in /var/lib/tomcat5.5/logs/.
All application events go to /var/log/syslog. Discovered by reading
ps aux output: `-outfile SYSLOG -errfile SYSLOG` flags on jsvc process.
This is a common real-world log config divergence — always read process
flags before assuming log paths from documentation.

## Log Evidence (from /var/log/syslog)
Jul 1 05:23:33 metasploitable jsvc.exec[5173]: Manager: init: Associated with Deployer
Jul 1 05:23:34 metasploitable jsvc.exec[5173]: Manager: deploy: Deploying web application at '/shell'
Jul 1 05:23:34 metasploitable jsvc.exec[5173]: Manager: Uploading WAR file to /var/lib/tomcat5.5/webapps/shell.war
Jul 1 05:23:34 metasploitable jsvc.exec[5173]: HostConfig deployWAR INFO: Deploying web application archive shell.war

## Detection Opportunity
Three layered signals, each independently detectable:
1. Syslog: `Manager: deploy` + `Uploading WAR file` in jsvc process
2. Network: PUT request to `/manager/deploy` with binary body (WAR magic bytes PK)
3. Filesystem: new .war file written to webapps/ directory

Highest-fidelity signal: syslog `Manager: Uploading WAR file to` —
legitimate CI/CD deployments don't come from a single attacker IP
and are not preceded by 401s from the same source.

## MITRE ATT&CK Mapping
- T1190 — Exploit Public-Facing Application
- T1105 — Ingress Tool Transfer (WAR upload)
- T1059.007 — Command and Scripting Interpreter: JavaScript/JSP
- T1021 — Remote Services (Manager API as lateral movement vector)

## Sigma Rule
See sigma-rules/tomcat-war-deployment-rce.yml

## References
- Tomcat 5.5 Manager API: https://tomcat.apache.org/tomcat-5.5-doc/manager-howto.html
- PTES Phase: Exploitation → Post-Exploitation

Artifact 2 — Sigma Rule
This is grounded in the exact syslog lines we captured. Save as sigma-rules/tomcat-war-deployment-rce.yml:
yamltitle: Apache Tomcat Manager WAR Deployment via API
id: a7f3c2e1-9b4d-4f8a-bc12-3e5d7a901234
status: test
description: >
  Detects WAR file deployment through the Apache Tomcat Manager application,
  as seen in syslog when Tomcat is configured with jsvc -outfile SYSLOG.
  Legitimate CI/CD deployments should be baselined and excluded by source IP.
  Deployments from unknown IPs, especially preceded by 401 auth failures,
  indicate likely attacker abuse of default or stolen Manager credentials.
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://tomcat.apache.org/tomcat-5.5-doc/manager-howto.html
author: Pranav (TurlaFSB)
date: 2026-07-01
tags:
  - attack.initial_access
  - attack.t1190
  - attack.persistence
  - attack.t1505.003
logsource:
  product: linux
  service: syslog
detection:
  keywords:
    - 'Manager: deploy: Deploying web application'
    - 'Manager: Uploading WAR file to'
    - 'HostConfig deployWAR'
  condition: keywords
falsepositives:
  - Legitimate CI/CD pipelines deploying to Tomcat Manager
  - Authorized application releases via Manager API
  - Correlate with source IP — authorized deployments should come from known build servers only
level: high
Two things worth understanding about this rule's design:
Why keywords instead of field-based matching? Because this log source is syslog via jsvc, there's no structured field parsing — it's a flat string. On a mature SIEM with a proper Tomcat log parser you'd match on cs-method: PUT and cs-uri-stem|contains: /manager/deploy, but that requires a network-layer log source. This rule targets what we actually have: syslog. Both approaches are valid; the right one depends on your log source.
The falsepositives section is doing real work here. A blanket "WAR deployed = alert" would fire on every legitimate release in a real org. The detection value is in the context: unexpected source IP, preceded by auth failures, outside business hours, to a non-production host. Your rule fires correctly — suppression and tuning logic is the analyst's job downstream.

Artifact 3 — Medium Post Outline
Title: "How I Got a Shell Through Tomcat's Front Door: Exploiting Default Credentials and the Manager API (and How to Detect It)"
Structure:
Hook — "This wasn't a zero-day. I didn't write exploit code. I used the application exactly as designed — just with credentials that should never have been active."
Section 1: The Setup — What Tomcat Manager is, why it exists, why it's dangerous on a public-facing host. Brief recon narrative: nmap banner, curl probe, the WWW-Authenticate: Basic header and what it reveals about the auth mechanism. The base64 decode moment.
Section 2: The Attack — Default cred, WAR structure explained (web.xml + JSP payload, why the random filename matters), the Tomcat 5.5 vs 6+ API difference and why it matters operationally, the deploy → trigger → shell sequence. Screenshot of the connect to line in nc.
Section 3: What the Logs Actually Said — The real finding here: logs weren't where the docs said. jsvc SYSLOG flag explained. The three syslog lines that told the whole story. This section is what makes your post stand out — most walkthroughs never look at logs at all.
Section 4: Detection Engineering — The three detection layers (syslog, network PUT, filesystem). The Sigma rule with line-by-line explanation of design choices. What a defender should baseline and what should never be normal.
Section 5: Remediation — Remove Manager from production, enforce IP allowlisting if it must exist, replace default creds, enforce TLS (Basic Auth + HTTP = cleartext creds), implement account lockout.


 "The attacker used one curl command and one WAR file. The defender needs one Sigma rule and one firewall rule. The gap between compromise and detection closes when you understand both sides."
