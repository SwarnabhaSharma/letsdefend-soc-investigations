# Web Attack Investigations

This directory contains documented SOC investigations related to **web-based security alerts** identified in the LetsDefend SOC environment.

The focus of these investigations is to analyze suspicious HTTP/HTTPS activity, determine attacker intent, validate indicators using threat intelligence, and classify alerts as **True Positive or False Positive** based on evidence.

---

## 🔍 Types of Alerts Covered
The investigations in this folder may include (but are not limited to):

- Command injection detection
- SQL injection attempts
- Cross-Site Scripting (XSS) indicators
- Suspicious URL parameters
- Web scanning and enumeration activity
- False positives caused by string-based detection rules

---

## 🧠 Investigation Approach
Each investigation follows a structured SOC workflow:

1. **Alert triage** and understanding why the rule triggered  
2. **URL and parameter analysis** to assess malicious intent  
3. **Log correlation** across available data sources  
4. **Threat intelligence enrichment** (e.g., VirusTotal, AlienVault OTX)  
5. **Incident classification** (True Positive / False Positive)  
6. **Response and mitigation recommendations**  

The goal is to demonstrate **analyst reasoning and decision-making**, not just alert resolution.

---

## 📄 File Naming Convention
Each investigation file follows this format: SOC<alert-no.> - <full-alert-name.>


