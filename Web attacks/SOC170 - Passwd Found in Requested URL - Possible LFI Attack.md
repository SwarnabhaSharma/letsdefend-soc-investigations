# SOC Alert Investigation

## 1. Alert Overview

- **Platform:** LetsDefend's SOC Environment
- **Alert Name / ID:** SOC170 - Passwd Found in Requested URL - Possible LFI Attack
- **Event ID:** 120
- **Category:** Web Attack
- **Severity:** High
- **Date & Time:** Mar, 01, 2022, 10:10 AM
- **MITRE ATT&CK (if applicable):** T1190 – Exploit Public-Facing Application

**Description:**

The alert was triggered after the web application detected HTTP requests containing file path traversal patterns commonly associated with Local File Inclusion (LFI) attempts. The request parameters matched detection logic designed to identify attempts to access sensitive files on the server. The requested URL contained 'passwd'.

---

## 2. Initial Analysis

- Source IP: 106.55.45.162
- Destination IP: 172.16.17.13
- URL: https://172.16.17.13/?file=../../../../etc/passwd
- Hostname / User: WebServer1006
- Relevant Logs / Indicators:
  - HTTP Request Method: GET
  - User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)
  - Device Action: Allowed

---

## 3. Investigation Steps

- Reviewed HTTP request logs for directory traversal patterns
- Analyzed request parameters for file inclusion attempts
- Checked server responses for evidence of file disclosure
- Correlated multiple requests from the same source IP
- Verified whether the requested files should be accessible
- Assessed whether the behavior aligned with legitimate user activity

---

## 4. Findings & Evidence

- After investigating the logs from source IP to destination IP we discovered that:
  - HTTP Response Status: 500
  - HTTP Response Size: 0

This indicates that the attack attempt was not successful.

- The source IP attempted to include local system files using path traversal sequences
- Requests targeted sensitive files such as `/etc/passwd`
- No legitimate business use case was identified for accessing system files via the application

Threat intelligence enrichment was not applicable, as LFI attacks are logic-based application vulnerabilities rather than reputation-based indicators.

The observed activity is consistent with a **Local File Inclusion (LFI) attack** targeting a public-facing web application.

---

## 5. Incident Classification

- **Final Verdict:** True Positive (unsuccessful LFI attempt)
- **Attack Stage (if any):** N/A

---

## 6. Response & Mitigation

- Recommended validating and sanitizing file input parameters
- Suggested implementing strict allowlists for file inclusion
- Advised disabling unnecessary file inclusion functionality
- Recommended monitoring for repeated LFI attempts from the same source
- Endpoint containment was not performed, as no endpoint compromise was observed

---

## 7. Lessons Learned

- LFI vulnerabilities can lead to sensitive file disclosure
- Input validation is critical for preventing file inclusion attacks
- Web application logic flaws bypass traditional endpoint defenses
- Successful LFI attempts should be escalated due to data exposure risk
- SOC teams must collaborate closely with Application Security for remediation

---

## Notes

- Environment: Simulated SOC / Lab Environment
- This investigation was conducted for learning and skill development purposes.
