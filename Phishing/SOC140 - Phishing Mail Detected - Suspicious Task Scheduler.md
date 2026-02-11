# SOC Alert Investigation

## 1. Alert Overview

- **Platform:** LetsDefend SOC Environment
- **Alert Name / ID:** SOC140 - Phishing Mail Detected - Suspicious Task Scheduler
- **Event ID:** 82
- **Category:** Email Security / Phishing
- **Severity:** Medium
- **Date & Time:** Mar, 21, 2021, 12:26 PM
- **MITRE ATT&CK (if applicable):**
  - T1566 – Phishing
  - T1053.005 – Scheduled Task/Job (Persistence - Attempted)

**Description:**

The alert was triggered when a phishing email containing malicious indicators was detected by the security solution. The system flagged suspicious characteristics related to task scheduler activity patterns commonly associated with malware persistence. The device action showed “Blocked”, indicating the threat was prevented before delivery.

---

## 2. Initial Analysis

Upon reviewing the alert, the email was identified as malicious based on reputation analysis and behavioral detection rules. The security control blocked the message before it reached the recipient’s mailbox.

- SMTP Address: 189.162.189.159
- Source Address: aaronluo@cmail.carleton.ca
- Destination Address: mark@letsdefend.io
- E-mail Subject: COVID19 Vaccine
- Relevant Logs / Indicators:
  - Device Action: Blocked
  - No evidence of mailbox delivery

---

## 3. Investigation Steps

- Reviewed email security logs to confirm delivery status.
- Verified device action status (Blocked).
- Checked mailbox logs to confirm the email was not delivered.
- Confirmed no scheduled task was successfully created.
- Checked for any related suspicious process execution.
- Verified no outbound malicious network communication occurred.

---

## 4. Findings & Evidence

- URL of E-mail Attachment: https://download.cyberlearn.academy/download/download?url=https://files-ld.s3.us-east-2.amazonaws.com/72c812cf21909a48eb9cceb9e04b865d.zip
- VirusTotal Analysis of E-mail attachment: https://www.virustotal.com/gui/url/8fc31b607a8e3049e330f2b016c69e14363b5521188ef54fccc18a113b735041
- The phishing email was detected by security controls.
- Device action status confirmed the email was blocked before reaching the user.
- No user interaction occurred.
- No scheduled task was created on the endpoint.
- No execution or persistence mechanisms were established.
- No signs of compromise were identified.
- The attachment was password-protected, a common evasion technique used to bypass email scanning engines.
- The email body claimed "Hey, did you read breaking news about Covid-19. Open it now!" and insisted on opening the attachment with the password provided in the email

**Threat Behaviour Analysis:**

The phishing email leveraged COVID-19–themed social engineering to create urgency and increase the likelihood of user interaction. The use of a password-protected attachment suggests an attempt to evade automated email scanning mechanisms. The detection rule referencing suspicious Task Scheduler behavior indicates that the payload may have been designed to establish persistence via scheduled tasks if executed. However, the security control successfully blocked the threat before delivery, preventing any compromise.

---

## 5. Incident Classification

- **Final Verdict:** True Positive (Prevented)
- **Attack Stage (if any):** Initial Access (Attempted – Blocked)

---

## 6. Response & Mitigation

- No containment required as the threat was blocked automatically.
- Confirmed email gateway protections were functioning correctly.
- Ensured malicious sender/domain remains blocked.
- Documented the alert for monitoring and trend analysis.

---

## 7. Lessons Learned

- Email security controls effectively prevented a phishing attempt.
- Early-stage detection eliminates the risk of user interaction.
- Continuous monitoring and correlation of email and endpoint logs is essential.
- Defense-in-depth strategy reduces risk of persistence mechanisms such as scheduled tasks.

---

## Notes

- Environment: Simulated SOC / Lab Environment
- This investigation was conducted for learning and skill development purposes.
