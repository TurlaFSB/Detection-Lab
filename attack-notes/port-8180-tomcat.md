# Port 8180 — Apache Tomcat 5.5 | Manager WAR Deployment → RCE

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





