# SOC Alert Investigation

## 1. Alert Overview

- **Platform:** Letsdefend SOC Environment
- **Alert Name / ID:** SOC114 - Malicious Attachment Detected - Phishing Alert
- **Event ID:** 45
- **Category:** Phishing
- **Severity:** High
- **Date & Time:** Jan, 31, 2021, 03:48 PM
- **MITRE ATT&CK (if applicable):**
  - T1566.001 – Phishing: Spearphishing Attachment
  - T1204 – User Execution

**Description:**

An email with the subject “Invoice” containing a malicious password-protected attachment was delivered to an internal user from an external address. The email security system detected the attachment as malicious. Log management confirmed that the recipient opened the attachment, increasing the risk of endpoint compromise.

---

## 2. Initial Analysis

The alert indicated that a phishing email containing a malicious attachment was successfully delivered to the user's mailbox.

Suspicious indicators identified:

- Generic subject line: “Invoice”
- Password-protected attachment (commonly used to evade email scanning engines)
- Malicious attachment detection by email security system
- Log evidence showing the user opened the attachment

- SMTP Address: 49.234.43.39
- Source Address: accounting@cmail.carleton.ca
- Destination Address: richard@letsdefend.io
- Destination IP: 172.16.20.3
- E-mail Subject: Invoice
- Relevant Logs / Indicators:
  - Device Action: Allowed
  - Destination Port: 25
  - Email gateway logs
  - Attachment detection logs
  - Endpoint activity logs
  - Log management showing file execution/open event

---

## 3. Investigation Steps

- Reviewed full email headers to identify sender origin.
- Verified whether the sender domain was spoofed or malicious.
- Analyzed attachment hash (if available) via threat intelligence platforms.
- Confirmed that the attachment was password-protected (evasion technique).
- Checked log management system for user interaction events.
- Confirmed that the attachment was opened by the recipient.
- Reviewed endpoint logs for suspicious process creation.
- Checked for outbound network connections post-execution.
- Assessed whether lateral movement or privilege escalation occurred.

---

## 4. Findings & Evidence

- The email contained a password-protected malicious attachment.
- The email was successfully delivered to the user mailbox.
- Log management confirmed that the user opened the attachment.
- Password-protected attachments are commonly used to bypass email security scanning.
- Confirmed user interaction increased the likelihood of malware execution and system compromise.
- No confirmed lateral movement observed at the time of investigation (if applicable).
- Log management confirmed file execution event after attachment was opened.
- Suspicious process activity was monitored following execution.

The incident posed a high risk due to confirmed user interaction with a malicious file.

- Email attachment link: https://download.cyberlearn.academy/download/download?url=https://files-ld.s3.us-east-2.amazonaws.com/c9ad9506bcccfaa987ff9fc11b91698d.zip
- VirusTotal analysis of email attachment: https://www.virustotal.com/gui/url/30f740f66885b9ae8dc3ef5a81e4d90c7a05f17eac95db7b023e99479b9ee502
- AlienVault analysis of SMTP address: https://otx.alienvault.com/indicator/ip/49.234.43.39
- VirusTotal analysis showed multiple AV detections confirming the attachment as malicious.
- AlienVault OTX indicated the SMTP IP 49.234.43.39 has been previously reported for malicious activity.

---

## 5. Incident Classification

- **Final Verdict:** True Positive
- **Attack Stage (if any):**
  - Initial Access (Phishing)
  - Execution (User opened malicious attachment)

---

## 6. Response & Mitigation

- The phishing email was deleted from the user's mailbox.
- The affected mail server was monitored and containment procedures were applied as per lab scenario requirements.
- Endpoint isolation procedures were applied.
- Recommended full malware scan on the affected system.
- Reset user credentials as a precautionary measure.
- Continued monitoring for suspicious outbound connections.
- The incident was contained at the execution stage with no evidence of further compromise or lateral spread.

---

## 7. Lessons Learned

- Password-protected attachments are frequently used to evade detection.
- User awareness training is critical to prevent opening suspicious attachments.
- Rapid containment significantly reduces potential impact.
- Monitoring user activity logs is essential in confirming execution.

---

## Notes

- Environment: Simulated SOC / Lab Environment
- This investigation was conducted for learning and skill development purposes.
