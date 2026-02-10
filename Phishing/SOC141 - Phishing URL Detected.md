# SOC Alert Investigation

## 1. Alert Overview

- **Platform:** LetsDefend SOC Environment
- **Alert Name / ID:** SOC141 - Phishing URL Detected
- **Event ID:** 86
- **Category:** Phishing
- **Severity:** High
- **Date & Time:** Mar, 22, 2021, 09:23 PM
- **MITRE ATT&CK (if applicable):** T1566.002 – Spearphishing Link

**Description:**

The alert was triggered after a URL embedded within an email was detected as potentially malicious. The detection logic flagged the URL based on characteristics commonly associated with phishing campaigns, such as deceptive domain structure and redirection behavior.

---

## 2. Initial Analysis

- Source IP: 172.16.17.49
- Destination IP: 91.189.114.8
- URL: http://mogagrocol.ru/wp-content/plugins/akismet/fv/index.php?email=ellie@letsdefend.io
- Source Hostname: EmilyComp
- Destination Hostname: mogagrocol.ru
- Username: ellie
- Relevant Logs / Indicators:
  - User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36
  - Device Action: Allowed
  - Email security alert
  - Embedded hyperlink within email body
  - Suspicious domain or URL pattern

The presence of a suspicious URL within an unsolicited email raised concerns of a phishing attempt designed to lure the user into visiting a malicious website.

---

## 3. Investigation Steps

- Extracted and reviewed the URL from the email body
- Analyzed the URL structure for signs of impersonation or obfuscation
- Checked the URL reputation using threat intelligence sources
- Reviewed email headers to verify sender authenticity
- Assessed whether the user interacted with the URL
- Correlated the alert with other phishing-related events

---

## 4. Findings & Evidence

- VirusTotal URL Analyis: https://www.virustotal.com/gui/url/149ad5bdb6fd67fd319f5b90b96c300beee2375ddef1dacd0c60f52da9c1f8fe
- The URL used a deceptive domain intended to impersonate a legitimate service
- URL analysis indicated redirection behavior commonly used in phishing attacks
- Threat intelligence sources flagged the URL as malicious
- No evidence indicated that the user clicked or interacted with the URL
- The email exhibited social engineering characteristics designed to prompt user action

Threat intelligence confirmed the URL was associated with phishing activity.

The observed activity is consistent with a **phishing attempt using a malicious URL**.

---

## 5. Incident Classification

- **Final Verdict:** True Positive (Phishing URL)
- **Attack Stage (if any):** Initial Access

---

## 6. Response & Mitigation

- The affected endpoint was contained to prevent potential compromise following detection of a malicious phishing URL.
- Blocked the malicious URL at the email and web gateway.
- Ensured the phishing email was removed or quarantined from all user mailboxes.
- Verified whether the user interacted with the URL prior to containment.
- Recommended credential reset and endpoint scanning as a precautionary measure.
- Advised user awareness regarding phishing links and suspicious emails.
- Endpoint containment was performed as a precautionary measure due to the risk of credential compromise or malware delivery associated with phishing URLs.

---

## 7. Lessons Learned

- Phishing URLs remain a common initial access technique
- URL reputation analysis is critical for early phishing detection
- User awareness significantly reduces phishing success rates
- Prompt containment prevents phishing attempts from escalating
- Continuous monitoring helps identify repeated phishing campaigns
- Early endpoint containment is an effective precautionary measure for phishing URL incidents, helping reduce the risk of credential compromise or secondary malware execution.

---

## Notes

- Environment: Simulated SOC / Lab Environment
- This investigation was conducted for learning and skill development purposes.
