# Phishing Alert Investigations

This directory contains documented **phishing-related SOC investigations** conducted in the LetsDefend SOC environment.  
The focus of these investigations is to analyze phishing techniques, validate malicious indicators, assess user impact, and document appropriate response actions.

Each write-up reflects a **real SOC workflow**, emphasizing analyst reasoning, evidence validation, and containment decisions rather than simply closing alerts.

---

## 🔍 Types of Phishing Cases Covered

The investigations in this folder may include:

- Phishing emails containing **malicious URLs**
- Phishing emails with **malicious attachments** (e.g., Excel 4.0 / XLM macros)
- Credential-harvesting phishing attempts
- Social engineering–based phishing campaigns
- Phishing alerts with and without confirmed user interaction

---

## 🧠 Investigation Methodology

Each phishing investigation follows a structured SOC process:

1. **Alert triage** to understand why the phishing alert was triggered  
2. **Email and URL analysis** to identify malicious indicators  
3. **Threat intelligence validation** (e.g., VirusTotal) where applicable  
4. **User interaction assessment** (clicked / not clicked)  
5. **Incident classification** (True Positive / False Positive)  
6. **Response actions**, including containment when required  
7. **Lessons learned** to improve future detection and response  

The goal is to demonstrate **how phishing incidents are evaluated and handled in real SOC environments**, not just to identify malicious emails.

---

## 📄 File Naming Convention

Each investigation file follows this format: SOC<alert-id>-<full-alert-name>
 

