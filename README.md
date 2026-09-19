#  Splunk SIEM Detection Lab: Password Spray Attack Analysis

##  Project Overview
This project simulates an adversary conducting a **Password Spraying Attack** against local workstation accounts and demonstrates the configuration of telemetry ingestion and threat detection using **Splunk Enterprise** and Windows Security Event Logs.

---

## ⚙️ Telemetry & Ingestion Architecture
* **Target Environment:** Windows 10/11 Workstation
* **SIEM Platform:** Splunk Enterprise (Free License)
* **Monitored Channel:** `WinEventLog://Security`[cite: 1]
* **Target Event ID:** `4625` (Logon Failure - An account failed to log on)

### 1. Audit Policy Configuration
Enabled Windows local logon auditing via command line to ensure authentication failures are written to the security channel:
```cmd
auditpol /set /subcategory:"Logon" /failure:enable /success:enable
2. Log Ingestion Pipeline (inputs.conf)
Configured Splunk's local event log collection pipeline by adding the following stanza to $SPLUNK_HOME\etc\system\local\inputs.conf[cite: 1]:
[WinEventLog://Security]
disabled = 0
start_from = newest
current_only = 0
checkpointInterval = 5
Attack Simulation (Password Spraying)
Simulated a threat actor attempting to authenticate across multiple user accounts using a single common password (Winter2026!)[cite: 1]:
net use \\localhost /user:attacker_user1 Winter2026!
net use \\localhost /user:attacker_user2 Winter2026!
net use \\localhost /user:attacker_user3 Winter2026!
net use \\localhost /user:user_admin Winter2026!
net use \\localhost /user:user_finance Winter2026!
SOC Detection Engineering (SPL)
Because Windows 4625 event logs record both the Subject and Target accounts under the same field structure, multi-value regular expression extraction was used to accurately parse the targeted victim identities:
index=* EventCode=4625 
| rex max_match=2 "Account Name:\s*(?<TargetUser>[^\r\n\t]+)" 
| mvexpand TargetUser
| search TargetUser!="-" TargetUser!="SYSTEM" TargetUser!=*$*
| stats count by TargetUser
📸 Detection Evidence
💡 Mitigation & Hardening
Multi-Factor Authentication (MFA): Enforce MFA across all endpoints to neutralize sprayed credentials.

Account Lockout Thresholds: Implement smart lockout mechanisms with automatic cool-down periods rather than permanent lockouts.

Behavioral Baseline: Alert on anomalous failed logons originating from single IP sources across multiple account targets within a 5-minute threshold.

