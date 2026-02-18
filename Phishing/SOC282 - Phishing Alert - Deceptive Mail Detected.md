# SOC Alert Investigation

## 1. Alert Overview
- **Platform:** LetsDefend SOC Environment
- **Alert Name / ID:** SOC282 - Phishing Alert - Deceptive Mail Detected
- **Event ID:** 257
- **Category:** Phishing
- **Severity:** Medium
- **Date & Time:** May, 13, 2024, 09:22 AM
- **MITRE ATT&CK (if applicable):**
  - T1566.001 – Phishing: Spearphishing Attachment
  - T1059.003 – Command and Scripting Interpreter: Windows Command Shell
  - T1082 – System Information Discovery
  - T1057 – Process Discovery
  - T1016 – System Network Configuration Discovery
  - T1087 – Account Discovery
  - T1571 – Non-Standard Port (C2 on port 3451)
  - T1219 – Remote Access Software (AsyncRAT/VenomRAT)

**Description:**  
A phishing email with the subject "Free Coffee Voucher" was sent from the spoofed/suspicious domain `coffeeshooop.com` (note the deliberate triple-'o' typosquat) to internal user Felix (`Felix@letsdefend.io`). The email contained a malicious attachment — `free-coffee.zip` — which, when extracted and executed, deployed `Coffee.exe`, a backdoor identified as **Backdoor.Marte.VenomRAT / AsyncRAT**. The malware established a connection to a remote Command & Control (C2) server and performed extensive post-compromise reconnaissance on the host. The email security gateway allowed the email through (Device Action: Allowed), meaning it reached the user's inbox without being blocked.

---

## 2. Initial Analysis

- Attacker IP: 37.120.233.226
- Host IP: 172.16.20.151
- Hostname / User: Felix
- Relevant Logs / Indicators:
  - SMTP Address: 103.80.134.63
  - Source Address: free@coffeeshooop.com
  - Destination Address: Felix@letsdefend.io
  - E-mail Subject: Free Coffee Voucher
  - Attachment: `free-coffee.zip` (password: `infected`) → contains `Coffee.exe`
  - Device Action: Allowed (email reached inbox)
  - Malware Family: AsyncRAT / Backdoor.Marte.VenomRAT
  - C2 Communication: `37.120.233.226` over port `3451` (non-standard)
  - Mutex Created: `Venom_RAT_HVNC_Mutex_Venom RAT_HVNC`
  - Malware persistence path: `%AppData%`

---

## 3. Investigation Steps

- **Step 1 – Alert Triage:** Reviewed the SOC282 alert in the ticket queue. Took ownership of the alert and created a new case to document the investigation.
- **Step 2 – Email Header & Metadata Analysis:** Navigated to the Email Security module. Extracted sender address (`free@coffeeshooop.com`), SMTP relay IP (`103.80.134.63`), recipient (`Felix@letsdefend.io`), subject (`Free Coffee Voucher`), and timestamp. Noted the "Device Action: Allowed" — confirming the email bypassed the email gateway and was delivered to the inbox.
- **Step 3 – Sender Reputation Check:** Queried the sender domain `coffeeshooop.com` and SMTP IP `103.80.134.63` on VirusTotal and threat intelligence platforms. Both were flagged as malicious/suspicious. The domain was identified as a typosquatted domain designed to impersonate a legitimate coffee brand.
- **Step 4 – Attachment Analysis (Static):** Identified the attachment `free-coffee.zip`. Extracted the archive (password: `infected`) to obtain `Coffee.exe`. Computed the SHA256 hash: `6f33ae4bf134c49faa14517a275c039ca1818b24fc2304649869e399ab2fb389`. Submitted the hash to VirusTotal — flagged as malicious by multiple AV vendors (Backdoor.Marte.VenomRAT / AsyncRAT).
- **Step 5 – Attachment Analysis (Dynamic / Sandbox):** Submitted `Coffee.exe` to ANY.RUN sandbox for dynamic analysis. Observed the following behaviors:
  - Immediately dropped an additional executable upon launch.
  - Connected to C2 server `37.120.233.226` on port `3451`.
  - Created mutex: `Venom_RAT_HVNC_Mutex_Venom RAT_HVNC`.
  - Installed itself in `%AppData%` for persistence.
  - Performed system reconnaissance (see Findings section).
- **Step 6 – Host-Based Investigation:** Pivoted to the affected endpoint `172.16.20.151` (Felix's machine). Reviewed Log Management to confirm the malicious file was downloaded and executed. Confirmed `Coffee.exe` was executed **3 times** between 01:00 PM and 01:01 PM on the same day.
- **Step 7 – Process Tree Analysis:** Reviewed the process execution chain on the host:
  `explorer.exe` → `Coffee.exe` → `cmd.exe` → multiple child processes (reconnaissance commands)
- **Step 8 – Network Log Review:** Inspected outbound network connections from the host. Confirmed outbound connections to `37.120.233.226:3451` immediately after `Coffee.exe` execution — consistent with C2 beaconing. Noted 2 instances of `FW Permit` and 1 instance of `FW Deny` for the `Coffee.exe` process across the 3 executions.
- **Step 9 – URL Analysis:** Analysed the embedded "Redeem Now" URL in the email body via VirusTotal. The URL was flagged as malicious and linked to a dropper/phishing landing page.
- **Step 10 – Verdict Determination:** Based on all evidence — malicious sender domain, malicious attachment confirmed as RAT, successful execution on host, C2 communication established, and post-compromise reconnaissance observed — the alert was classified as a **True Positive**.

---

## 4. Findings & Evidence

- **VirusTotal URL Analysis:** https://www.virustotal.com/gui/url/28a8b017e29398b93894e1f372ca6f495b98c4dc819cd5e5374e30f3e81f8f8d
- **Malicious Process Execution:** `Coffee.exe` was executed **3 times** within the time window of 01:00 PM – 01:01 PM on host `172.16.20.151`. Of the 3 executions: 2 resulted in `FW Permit` and 1 in `FW Deny`.
- **Malware Identification:** `Coffee.exe` (SHA256: `6f33ae4bf134c49faa14517a275c039ca1818b24fc2304649869e399ab2fb389`) was positively identified as **Backdoor.Marte.VenomRAT / AsyncRAT** — a Remote Access Trojan that grants full remote control to the attacker.
- **C2 Communication Confirmed:** Outbound connections from `172.16.20.151` to `37.120.233.226` on port `3451` (non-standard) were observed immediately after malware execution, confirming active C2 channel establishment.
- **Post-Compromise Reconnaissance Commands Observed:**
  - `systeminfo` — OS and hardware enumeration
  - `hostname` — machine name discovery
  - `wmic logicaldisk get` — storage device enumeration
  - `net user` — local account discovery
  - `tasklist /svc` — running process and service enumeration
  - `ipconfig /all` — full network configuration discovery
  - `route print` — routing table enumeration
- **Persistence Mechanism:** Malware installed itself in `%AppData%` and created the mutex `Venom_RAT_HVNC_Mutex_Venom RAT_HVNC` to prevent duplicate execution.
- **Typosquatted Sender Domain:** `coffeeshooop.com` (triple 'o') — a deliberate impersonation of a legitimate domain to deceive the recipient and bypass basic email filters.
- **Email Gateway Failure:** Device Action was `Allowed`, meaning the phishing email was not caught by the email security product and was delivered directly to Felix's inbox.

---

## 5. Incident Classification
- **Final Verdict:** True Positive
- **Attack Stage:** Initial Access → Execution → Persistence → Command & Control (C2)
- **Attack Vector:** Spearphishing Attachment (`.zip` containing `.exe`)
- **Malware Type:** Remote Access Trojan (RAT) — AsyncRAT / VenomRAT
- **Impact:** Full remote access to the compromised host; active C2 channel established; extensive host reconnaissance performed; potential for lateral movement, data exfiltration, and further payload deployment.

---

## 6. Response & Mitigation

- **Immediate Containment:**
  - Isolated / contained the compromised host `172.16.20.151` from the network to prevent lateral movement and further C2 communication.
  - Deleted the phishing email from Felix's mailbox to prevent re-opening.
- **Indicator Blocking:**
  - Blocked sender domain `coffeeshooop.com` at the email gateway.
  - Blocked SMTP relay IP `103.80.134.63` at the email gateway.
  - Blocked C2 IP `37.120.233.226` on port `3451` at the perimeter firewall.
  - Added `Coffee.exe` SHA256 hash (`6f33ae4bf134c49faa14517a275c039ca1818b24fc2304649869e399ab2fb389`) to the EDR blocklist to prevent re-execution.
- **Credential Reset:** Reset Felix's account credentials as the host was fully compromised and credentials may have been harvested by the RAT.
- **Malware Removal & Host Remediation:** Performed full malware scan and remediation on `172.16.20.151`. Removed `Coffee.exe` and any dropped files from `%AppData%`. Verified no additional persistence mechanisms (scheduled tasks, registry run keys) were left behind.
- **Threat Hunt:** Conducted a threat hunt across the environment to check if any other hosts communicated with `37.120.233.226` or executed `Coffee.exe`, to rule out lateral spread.
- **IOC Sharing:** Shared all IOCs (sender domain, SMTP IP, C2 IP, file hash, mutex name) with the threat intelligence team for environment-wide monitoring.

---

## 7. Lessons Learned

- **Email Gateway Tuning:** The email security product failed to block the phishing email (Device Action: Allowed). Email filtering rules should be reviewed and strengthened — particularly for `.zip` attachments containing executables, and for newly registered or typosquatted domains.
- **User Awareness Training:** Felix executed the malicious attachment. Regular phishing simulation exercises and security awareness training should be conducted to help users identify social engineering lures (e.g., "Free Coffee Voucher" urgency tactics).
- **Attachment Sandboxing:** Implement automatic sandboxing of all email attachments (especially compressed archives like `.zip`) before delivery to end-user inboxes. This would have detected `Coffee.exe`'s malicious behavior before execution.
- **Non-Standard Port Monitoring:** The C2 communication occurred on port `3451`, which is non-standard. Network monitoring rules should alert on unusual outbound connections to non-standard ports from workstations.
- **Endpoint Detection Gaps:** `Coffee.exe` was executed 3 times before being detected. EDR rules should be configured to alert on and block execution of unknown executables from user download directories and `%AppData%`.
- **Principle of Least Privilege:** Ensure users like Felix do not have permissions to execute arbitrary binaries. Application whitelisting or execution policies can significantly reduce the blast radius of such attacks.

---

## Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| Sender Email | free@coffeeshooop.com |
| Sender Domain | coffeeshooop.com |
| SMTP Relay IP | 103.80.134.63 |
| C2 IP | 37.120.233.226 |
| C2 Port | 3451 |
| Attachment Name | free-coffee.zip |
| Malware Name | Coffee.exe |
| SHA256 Hash | `6f33ae4bf134c49faa14517a275c039ca1818b24fc2304649869e399ab2fb389` |
| Malware Family | AsyncRAT / Backdoor.Marte.VenomRAT |
| Mutex | `Venom_RAT_HVNC_Mutex_Venom RAT_HVNC` |
| Persistence Path | `%AppData%` |
| Victim Host IP | 172.16.20.151 |
| Victim User | Felix (Felix@letsdefend.io) |

---

## Notes
- Environment: Simulated SOC / Lab Environment
- This investigation was conducted for learning and skill development purposes.
