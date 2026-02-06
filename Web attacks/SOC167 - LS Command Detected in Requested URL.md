# SOC Alert Investigation

## 1. Alert Overview

- **Platform:** LetsDefend SOC Environment
- **Alert Name / ID:** SOC167 - LS Command Detected in Requested URL
- **Event ID:** 117
- **Category:** Web Attack
- **Severity:** High
- **Date & Time:** Feb, 27, 2022, 12:36 AM
- **MITRE ATT&CK (if applicable):** T1059.004 – Command and Scripting Interpreter: Unix Shell

**Brief Summary:**  
When the Request URL is examined, it is seen that the word "skills" is searched on the LetsDefend Blog page. However, the letters "ls" at the end of the word caused the rule to be triggered incorrectly.
It is a false positive alarm.
To be sure, when the Browser History of the device is examined from the Endpoint Security page, it is confirmed that there is no attack.

---

## 2. Initial Analysis

- Source IP: 188.114.96.15
- Destination IP: 172.16.17.46
- URL: https://letsdefend.io/blog/?s=skills
- Hostname / User: EliotPRD
- Relevant Logs / Indicators:
  - User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:24.0) Gecko/20100101 Firefox/24.0
  - Alert Trigger Reason: URL Contains LS
  - Device Action: Allowed
  - HTTP Request Method: GET

The requested URL observed was "https://letsdefend.io/blog/?s=skills
". At first glance, the query parameter contained the substring ls, which caused the detection rule to flag the request as a potential command injection attempt.

---

## 3. Investigation Steps

- Analyzed the full requested URL and query parameters
- Checked for command separators or shell metacharacters (;, |, &&)
- Looked for URL encoding or obfuscation techniques
- Reviewed browser history from the Endpoint Security page
- Correlated user activity with the request timing

---

## 4. Findings & Evidence

- Investigated the endpoint with the hostname EliotPRD and got the following information:
  - Domain: letsdefend.local
  - Bit Level: 64
  - OS: Ubuntu 16.04.4
  - Primary User: eliot
  - Client/Server: Client
- Investigated log management for the IP 172.16.17.46 with destination address of 188.114.96.15 at the time of the and found the following information:
  - HTTP Response Status: 200
  - HTTP Response Size: 2577
- VirusTotal Score: https://www.virustotal.com/gui/ip-address/172.16.17.46
- AlienVault Report: https://otx.alienvault.com/browse/global/pulses?q=172.16.17.46&include_inactive=0&sort=-modified&page=1&limit=10&indicatorsSearch=172.16.17.46
- The string ls was part of the legitimate search term “skills”.
- No command execution syntax or chaining was present.
- Browser history confirmed normal user behavior.
- No additional suspicious traffic or payloads were observed.
- Although the detection rule mapped to Unix shell command execution, further analysis confirmed no actual command execution attempt.
- It was a false positive as the url requested happened to have the letters ls coincidentally which is what triggered an alert.

---

## 5. Incident Classification

- **Final Verdict:** False Positive
- **Attack Stage (if any):** N/A

---

## 6. Response & Mitigation

- No containment or remediation required
- Recommended improving detection logic to reduce false positives caused by partial string matches

---

## 7. Lessons Learned

This case highlights the limitations of signature-based detection rules and emphasizes the importance of validating attacker intent before classifying web traffic as malicious.

---

## Notes

- Environment: LetsDefend Simulated SOC / Lab Environment
- This investigation was conducted for learning and skill development purposes.
