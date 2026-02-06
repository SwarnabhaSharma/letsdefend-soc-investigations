# SOC Alert Investigation

## 1. Alert Overview

- **Platform:** LetsDefend SOC Environment
- **Alert Name / ID:** SOC169 - Possible IDOR Attack Detected
- **Event ID:** 119
- **Category:** Web Attack
- **Severity:** Medium
- **Date & Time:** Feb, 28, 2022, 10:48 PM
- **MITRE ATT&CK (if applicable):** T1190 – Exploit Public-Facing Application

**Brief Summary:**
On the Log Management page, we filter by source IP address and detect all requests. When the requests were examined, it was determined that the attacker wanted to change the ID value and access information belonging to different users. When the request sizes are examined, there is a different response size for each user and the status code is 200. For this reason, the attack is considered to have been successful. Since the attack may have been successful the incident should be escalated to Tier 2.

---

## 2. Initial Analysis

- Source IP: 134.209.118.137
- Destination IP: 172.16.17.15
- URL: https://172.16.17.15/get_user_info/
- Hostname / User: WebServer1005
- Relevant Logs / Indicators:
  - HTTP Request Method: POST
  - User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)
  - Device Action: Allowed

---

## 3. Investigation Steps

- Reviewed HTTP request logs for object identifier manipulation.
- Investigated the source IP on sites like VirusTotal and AlienVault
- Analyzed access patterns for sequential or unauthorized object access.
- Verified whether access control checks were enforced server-side
- Correlated request timestamps with user session activity
- Checked application responses for unauthorized data exposure
- Assessed whether the behavior was consistent with normal user activity

---

## 4. Findings & Evidence

- Investigated the affected web server with the hostname WebServer1005 and obtained the following information:
  - Domain: letsdefend.local
  - Bit Level: 64
  - OS: Windows Server 2019
  - Primary User: webadmin35
  - Client/Server: Server
- Investigated log management for the IP 134.209.118.137 with destination address of 172.16.17.15 at the time of the and obtained the following information:
  - HTTP Response Status: 200
  - HTTP Response Size: 267
  - POST Parameters: ?user_id=5
  - In a span of 5 minutes, the source IP attempted object identifier manipulation five times, all of which were successful.

Threat intelligence enrichment was not applicable, as IDOR attacks are logic-based vulnerabilities rather than reputation-based indicators.

- The user modified object identifiers within the request parameters
- Requests were successfully processed by the application
- Application responses returned valid content for different object IDs
- No client-side or server-side access restriction was observed during the requests
- The behavior is consistent with a **potential IDOR vulnerability**

However, no clear evidence confirmed exposure of sensitive or restricted data beyond the scope of the lab environment.

---

## 5. Incident Classification

- **Final Verdict:** True Positive
- **Attack Stage (if any):** Initial Access

---

## 6. Response & Mitigation

- The issue was escalated to the Application Security team for remediation of server-side access control weaknesses.
- Recommended reviewing and enforcing server-side authorization checks
- Suggested implementing object-level access control validation
- Advised logging and monitoring for repeated object ID manipulation
- Recommended secure design review for similar application endpoints
- Endpoint containment was not performed, as no evidence of endpoint compromise or malicious automation was observed.

---

## 7. Lessons Learned

- The issue was escalated to the Application Security team, as the observed behavior indicated a server-side authorization flaw rather than endpoint compromise. Endpoint containment was not required.
- IDOR vulnerabilities often bypass traditional security controls
- Authorization checks must be enforced server-side for every object access
- Behavioral analysis is critical for detecting logic-based web attacks
- Successful IDOR attempts should always be escalated due to potential data exposure risk

---

## Notes

- Environment: Simulated SOC / Lab Environment
- This investigation was conducted for learning and skill development purposes.
