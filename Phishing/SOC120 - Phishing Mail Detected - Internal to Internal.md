# SOC Alert Investigation

## 1. Alert Overview

- **Platform:** LetsDefend SOC Environment
- **Alert Name / ID:** SOC120 - Phishing Mail Detected - Internal to Internal
- **Event ID:** 52
- **Category:** Email Security / Phishing
- **Severity:** Medium
- **Date & Time:** Feb, 07, 2021, 04:24 AM
- **MITRE ATT&CK (if applicable):** T1566 – Phishing

**Description:**

An internal email was flagged as a potential phishing attempt. The email was sent from one internal user to another with the subject “Meeting” and a short message requesting to arrange a meeting. The alert was triggered due to phishing detection mechanisms identifying suspicious characteristics in the email.

---

## 2. Initial Analysis

The email content appeared simple and harmless at first glance. However, it raised suspicion due to:

- Generic subject line (“Meeting”)
- Very short and vague message body
- Internal-to-internal phishing scenario
- Lack of prior conversation context

Such characteristics are commonly associated with social engineering attempts where attackers try to initiate communication before delivering malicious links or attachments.

- Source Address: john@letsdefend.io
- Destination Address: susie@letsdefend.io
- SMTP Address: 172.16.20.3
- E-mail Subject: Meeting
- Relevant Logs / Indicators:
  - Device Action: Allowed

---

## 3. Investigation Steps

- Reviewed full email headers to verify sender authenticity.
- Checked SPF, DKIM, and DMARC authentication results.
- Verified whether the sender account showed signs of compromise.
- Analyzed login history for suspicious IP addresses or unusual login times.
- Checked whether similar emails were sent to multiple internal users.
- Confirmed that no attachments or embedded links were present.
- Validated with the recipient whether the email was expected (if applicable in lab scenario).

---

## 4. Findings & Evidence

- No attachments or embedded links were found in the email.
- Email header analysis showed the message originated from a legitimate internal mail server.
- No suspicious login activity was observed for the sender account.
- No evidence of lateral movement or phishing campaign activity was identified.
- The body only consisted of a short and vague message saying "Hi Susie, Can we arrange a meeting today if you are available?"

The email was flagged due to heuristic detection but did not contain malicious indicators. Threat intelligence analysis was not required as the email did not contain any URLs, attachments, or external indicators.

---

## 5. Incident Classification

- **Final Verdict:** False Positive
- **Attack Stage (if any):** N/A

---

## 6. Response & Mitigation

- No containment action was required.
- Continued monitoring of the sender account for unusual activity.
- Reinforced user awareness regarding vague internal email communications.
- Recommended ongoing phishing awareness training.

---

## 7. Lessons Learned

- Internal emails can trigger phishing alerts due to behavioral detection mechanisms.
- Generic and short emails are common phishing techniques, but contextual validation is essential.
- Email header authentication checks (SPF/DKIM/DMARC) are critical in investigation.

---

## Notes

- Environment: Simulated SOC / Lab Environment
- This investigation was conducted for learning and skill development purposes.
