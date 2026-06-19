# Port 25 — SMTP VRFY User Enumeration (Metasploitable 2)

## Service Identification

* **Port/Protocol:** 25/TCP
* **Service:** SMTP (Postfix)
* **Target:** Metasploitable 2 (192.168.75.130)
* **Risk:** Unauthenticated disclosure of valid usernames through the SMTP VRFY command

## Enumeration

Service identification:

```bash
nmap -p 25 -sV 192.168.75.130
```

Output confirmed:

```text
25/tcp open smtp Postfix smtpd
```

Banner grabbing was performed using:

```bash
nc -nv 192.168.75.130 25
```

Banner:

```text
220 metasploitable.localdomain ESMTP Postfix (Ubuntu)
```

SMTP capabilities were enumerated with:

```text
EHLO test
```

Server response:

```text
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-STARTTLS
250-ENHANCEDSTATUSCODES
250-8BITMIME
250 DSN
```

The presence of `250-VRFY` immediately indicated a possible username enumeration vector.

## Exploitation

Unlike Telnet, exploitation here was entirely manual because the protocol itself exposes the necessary functionality.

Within the SMTP session:

```text
VRFY root
252 2.0.0 root

VRFY msfadmin
252 2.0.0 msfadmin

VRFY admin
550 5.1.1 <admin>: Recipient address rejected: User unknown in local recipient table

VRFY nonexistentuser12345
550 5.1.1 <nonexistentuser12345>: Recipient address rejected: User unknown in local recipient table
```

**What was gained:** Confirmation that the accounts `root` and `msfadmin` exist. An attacker can leverage these usernames during subsequent password-spraying or brute-force attacks. The technique itself does not provide credentials or code execution, but significantly reduces the search space for later stages of the intrusion.

## Detection Engineering Investigation

Unlike Telnet, Postfix provided rich logging. However, the investigation uncovered a different limitation: the most valuable attacker event (successful username discovery) turns out to be completely invisible.

### Finding 1: Failed VRFY attempts are logged

Postfix records rejected username lookups inside:

```text
/var/log/mail.log
```

Example:

```text
postfix/smtpd[9421]: NOQUEUE: reject: VRFY from unknown[192.168.75.129]:
550 5.1.1 <admin>: Recipient address rejected:
User unknown in local recipient table;
to=<admin> proto=ESMTP helo=<test>
```

This telemetry contains:

* Source IP address
* Queried username
* SMTP protocol information
* EHLO value

Compared with Telnet, Postfix provides substantially richer logging.

### Finding 2: Successful username disclosure leaves no evidence

The successful requests:

```text
VRFY root
252 2.0.0 root

VRFY msfadmin
252 2.0.0 msfadmin
```

were investigated by searching:

```bash
grep -i "root\|msfadmin" /var/log/mail.log
```

No output was returned.

This means the exact event an attacker cares about — discovering a valid account — is never logged. Only failed guesses generate server-side evidence.

As a result, direct detection of successful enumeration is impossible. Detection must instead focus on the surrounding failed attempts.

### Finding 3: Wazuh includes Postfix support but no VRFY detection

Inspection of the ruleset:

```bash
grep -r "VRFY\|postfix" /var/ossec/ruleset/decoders/ /var/ossec/ruleset/rules/ -l
```

returned:

```text
/var/ossec/ruleset/decoders/0220-postfix_decoders.xml
/var/ossec/ruleset/rules/0280-attack_rules.xml
/var/ossec/ruleset/rules/0030-postfix_rules.xml
```

However:

```bash
grep -B5 -A15 "VRFY" /var/ossec/ruleset/rules/*.xml
```

returned no matches.

This confirmed that Wazuh ships with Postfix decoders and generic Postfix rules, but no dedicated detection for SMTP VRFY enumeration.

### Finding 4: Agentless monitoring again prevents rule-based detection

As with previous services, Metasploitable 2 cannot run a modern Wazuh agent due to its age, making agentless monitoring the architecturally correct choice.

However, empirical testing again showed that `ssh_generic_diff` performs integrity monitoring rather than log analysis. Although changes to `/var/log/mail.log` were detected, individual Postfix events were never routed through `wazuh-analysisd`, meaning no Postfix decoder or rule ever processed the VRFY events.

The limitation is therefore architectural rather than rule-related.

### Manual Validation

Inspection of `/var/log/mail.log` confirmed that failed VRFY requests consistently generated log entries containing:

```text
NOQUEUE: reject: VRFY
```

This string provides a stable detection artifact suitable for Sigma rule development.

Although successful username disclosures remain invisible, a burst of failed VRFY requests from a single source IP is highly indicative of active user enumeration.

## Sigma Rule

See [`sigma-rules/Postfix_SMTP_VRFY_Enumeration.yml`](../sigma-rules/Postfix_SMTP_VRFY_Enumeration.yml)

## MITRE ATT&CK Mapping

* **T1595 — Active Scanning** (Reconnaissance)

## Real-World Context

SMTP VRFY enumeration is an old technique but remains relevant because legacy mail servers and poorly hardened Postfix deployments are still encountered in enterprise environments.

This investigation highlights a recurring lesson in detection engineering: the event that matters most to the attacker is not necessarily the event most visible to defenders. Successful username discovery leaves no trace, forcing defenders to detect the surrounding behavior rather than the outcome itself.

## Interview Articulation

*"I discovered that Postfix logs failed VRFY requests but not successful ones. The interesting part was that the exact event an attacker cares about — confirming a valid username  leaves no evidence. I verified that Wazuh ships with Postfix decoders but no dedicated VRFY detection logic, and I also confirmed that agentless monitoring prevented the events from reaching the analysis engine. Because direct detection was impossible, I shifted to behavior-based detection and developed a Sigma rule around repeated failed VRFY attempts instead. The exercise reinforced that detection engineering is often about understanding logging gaps and designing around them rather than assuming perfect visibility."*
