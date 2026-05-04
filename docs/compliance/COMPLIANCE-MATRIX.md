# GlobalSec — Compliance Matrix

> **Author:** Alvin, Security Architect
> **Version:** 1.0
> **Frameworks covered:** 25+

---

## Purpose

This matrix maps each regulatory framework to the GlobalSec agents that produce the audit evidence required for compliance. It serves as:
- **Audit response artefact** — auditors can see at a glance which agents satisfy which controls
- **Gap analysis tool** — identifies frameworks that lack coverage
- **Implementation guide** — prioritises agents based on regulatory exposure

---

## Global Frameworks

### ISO/IEC 27001:2022

| Annex A Control | Description | Primary Agents |
|-----------------|-------------|----------------|
| A.5 — Organisational | Information security policies | Compliance/GRC |
| A.6 — People | Background checks, training | Insider Risk + Compliance/GRC |
| A.7 — Physical | Physical security | Out of scope (physical) |
| A.8.1 — Asset Management | Asset inventory | Asset Management |
| A.8.2-3 — Information classification | DLP + classification | DLP + DSPM |
| A.8.5-6 — Authentication | Strong auth | Entra ID + PIM |
| A.8.7 — Malware protection | Anti-malware | EDR |
| A.8.8 — Vulnerability mgmt | Vuln program | Vulnerability Management |
| A.8.9 — Configuration mgmt | Config hardening | CSPM (Wiz) + CWPP |
| A.8.10 — Information deletion | Data retention | Data Residency + DLP |
| A.8.11 — Data masking | Pseudonymization | DLP + DSPM |
| A.8.12 — Data leakage prevention | DLP | DLP + Insider Risk |
| A.8.13 — Backup | Backup strategy | Backup & Recovery |
| A.8.14-16 — Logging & monitoring | SIEM | SIEM (Sentinel) |
| A.8.17-18 — Privileged access | PAM | PIM + PAM |
| A.8.19 — Network controls | Firewalls, segmentation | Network Detection + WAF |
| A.8.20 — Network security | Encryption in transit | All (TLS enforcement) |
| A.8.21 — Network services | Service security | API Security + WAF |
| A.8.22 — Network segregation | Segmentation | Network Detection |
| A.8.23 — Web filtering | Web proxy | SSE/Netskope |
| A.8.24 — Cryptography | Crypto controls | All (Azure Key Vault) |
| A.8.25-26 — Secure SDLC | SAST/DAST | SAST + DAST/SCA |
| A.8.27-28 — Application security | App architecture | API Security + WAF |
| A.8.29 — Security testing | Pen testing | Out of scope (procured) |
| A.8.30 — Outsourced development | Vendor mgmt | Third-Party Risk |
| A.8.31 — Test data | Data masking | DLP + DSPM |
| A.8.32 — Change management | Change controls | All (audit logs) |
| A.8.33 — Test information | Test data security | DLP |
| A.8.34 — System audits | Audit logs | SIEM |
| A.5.23-30 — Incident management | IR program | Incident Response + SOAR |

### NIST CSF 2.0

| Function | Category | Primary Agents |
|----------|----------|----------------|
| **GOVERN (GV)** | Policy, risk management, supply chain | Compliance/GRC + Risk Dashboard + TPRM |
| **IDENTIFY (ID)** | Asset mgmt, business environment, governance, risk assessment | Asset Mgmt + Vulnerability + EASM |
| **PROTECT (PR)** | Access control, awareness, data security, info protection | Entra ID + PIM + PAM + DLP + EDR |
| **DETECT (DE)** | Anomalies, continuous monitoring, detection processes | SIEM + Network Detection + EDR + Threat Intel |
| **RESPOND (RS)** | Response planning, communications, analysis, mitigation | IR + SOAR + Crisis Comms |
| **RECOVER (RC)** | Recovery planning, improvements, communications | Backup & Recovery + Crisis Comms |

### SOC 2 Type II

| Trust Service Criteria | Primary Agents |
|------------------------|----------------|
| Security (CC) | All security agents |
| Availability (A) | Backup & Recovery + Asset Mgmt + Crisis Comms |
| Processing Integrity (PI) | SAST + DAST + Compliance/GRC |
| Confidentiality (C) | DLP + DSPM + Data Residency + Insider Risk |
| Privacy (P) | DLP + Data Residency + Compliance/GRC |

### PCI DSS v4.0

| Requirement | Description | Primary Agents |
|-------------|-------------|----------------|
| Req 1 | Network segmentation | Network Detection + WAF |
| Req 2 | Configuration hardening | CSPM (Wiz) |
| Req 3 | Cardholder data protection | DLP + DSPM |
| Req 4 | Encryption in transit | All |
| Req 5 | Anti-malware | EDR |
| Req 6 | Secure development | SAST + DAST/SCA |
| Req 7 | Access restriction | Entra ID + PAM |
| Req 8 | Authentication | Entra ID + PIM |
| Req 9 | Physical access | Out of scope |
| Req 10 | Logging & monitoring | SIEM |
| Req 11 | Vulnerability testing | Vulnerability Management |
| Req 12 | Information security policy | Compliance/GRC |

### MITRE ATT&CK v14

| Tactic | Coverage Agents |
|--------|-----------------|
| Reconnaissance (TA0043) | EASM + Brand Protection |
| Resource Development (TA0042) | Threat Intel + Brand Protection |
| Initial Access (TA0001) | EDR + Email Security + WAF |
| Execution (TA0002) | EDR |
| Persistence (TA0003) | EDR + Network Detection |
| Privilege Escalation (TA0004) | PIM + PAM + EDR |
| Defense Evasion (TA0005) | EDR + Network Detection |
| Credential Access (TA0006) | Entra ID + PAM |
| Discovery (TA0007) | EDR + Network Detection |
| Lateral Movement (TA0008) | Network Detection + Defender for Identity |
| Collection (TA0009) | DLP + Insider Risk |
| Command and Control (TA0011) | DNS Security + Network Detection |
| Exfiltration (TA0010) | DLP + Network Detection |
| Impact (TA0040) | EDR + Backup & Recovery |

---

## European Frameworks

### GDPR (EU 2016/679)

| Article | Requirement | Primary Agents |
|---------|-------------|----------------|
| Art. 5 | Principles (lawfulness, minimisation, accuracy, storage, integrity) | DLP + Data Residency + Compliance/GRC |
| Art. 25 | Privacy by design and by default | All (architectural) |
| Art. 30 | Records of processing | Compliance/GRC + DSPM |
| Art. 32 | Security of processing | All security agents |
| Art. 33 | Breach notification (72-hour rule) | Crisis Comms + IR |
| Art. 35 | Data Protection Impact Assessment | Compliance/GRC |
| Art. 44-49 | International transfers | Data Residency |

### NIS2 Directive (EU 2022/2555)

Applies to essential and important entities. Primary agents:
- Asset Management (asset inventory)
- Risk Dashboard (risk management)
- IR (incident reporting — 24h early warning, 72h notification, 1-month report)
- Vulnerability Management
- All detection agents
- Compliance/GRC for governance

### DORA (EU 2022/2554)

Digital Operational Resilience Act for financial entities.
- All resilience agents (Backup & Recovery + Crisis Comms)
- Third-Party Risk (ICT third-party risk management)
- IR + SIEM for incident reporting
- Compliance/GRC for governance

---

## US Frameworks

### HIPAA (45 CFR §164)

| Safeguard | Primary Agents |
|-----------|----------------|
| §164.308 — Administrative | Compliance/GRC + Insider Risk |
| §164.310 — Physical | Out of scope (physical) |
| §164.312 — Technical | EDR + DLP + Entra ID + PAM + SIEM + Backup |
| §164.314 — Organizational | Third-Party Risk + Compliance/GRC |
| §164.316 — Policies | Compliance/GRC |

### SOX (Sections 302, 404)

- Compliance/GRC for control testing
- SIEM for audit logging
- Entra ID + PAM for access controls
- Asset Management for IT general controls
- All agents for change management evidence

### CCPA / CPRA (California)

- DLP for sensitive data identification
- Data Residency for sale/sharing tracking
- Insider Risk for unauthorized access
- Compliance/GRC for consumer request fulfilment

### NYDFS Cybersecurity Regulation (23 NYCRR 500)

Comprehensive — every section maps to multiple agents:
- §500.02 — Cybersecurity program: All agents
- §500.04 — CISO: Risk Dashboard
- §500.06 — Audit Trail: SIEM
- §500.07 — Access Privileges: PIM + PAM
- §500.08 — Application Security: SAST + DAST
- §500.09 — Risk Assessment: Risk Dashboard + TPRM
- §500.11 — Third-Party: Third-Party Risk
- §500.12 — Multi-Factor Auth: Entra ID
- §500.14 — Training: Compliance/GRC
- §500.15 — Encryption: All
- §500.16 — Incident Response: IR + Crisis Comms
- §500.17 — Notice: Crisis Comms

---

## APAC Frameworks

| Regulation | Country | Primary Agents |
|-----------|---------|----------------|
| **DPDP Act 2023** | India | DLP + Data Residency + IR |
| **PDPA** | Singapore | DLP + Data Residency + Compliance/GRC |
| **Privacy Act 1988** | Australia | DLP + Data Residency + IR |
| **APPI** | Japan | DLP + Data Residency |
| **PIPA** | Korea | DLP + Data Residency |
| **PDPO** | Hong Kong | DLP + Data Residency |
| **Personal Data Protection Act** | Thailand | DLP + Data Residency |

---

## GCC Frameworks

| Regulation | Country | Primary Agents |
|-----------|---------|----------------|
| **UAE PDPL (Federal Decree-Law 45/2021)** | UAE | DLP + Data Residency + IR |
| **DIFC DPL 2020** | UAE-DIFC | DLP + Data Residency + Compliance/GRC |
| **ADGM Data Protection Regulations 2021** | UAE-ADGM | Same |
| **Saudi PDPL** | Saudi Arabia | Same |
| **Qatar DPPL (Law 13/2016)** | Qatar | Same |
| **Bahrain PDPL** | Bahrain | Same |
| **Kuwait DPL** | Kuwait | Same |
| **Oman Data Protection Law** | Oman | Same |

---

## African Frameworks

| Regulation | Country | Primary Agents |
|-----------|---------|----------------|
| **POPIA** | South Africa | DLP + Data Residency + IR + Compliance/GRC |
| **NDPA 2023** | Nigeria | Same |
| **Data Protection Act 2019** | Kenya | Same |
| **Personal Data Protection Law 151/2020** | Egypt | Same |

---

## LATAM Frameworks

| Regulation | Country | Primary Agents |
|-----------|---------|----------------|
| **LGPD** | Brazil | DLP + Data Residency + Compliance/GRC + IR |
| **LFPDPPP** | Mexico | Same |
| **Law 25.326** | Argentina | Same |

---

## OWASP Top 10 (Web Application — 2021)

| Risk | Primary Agents |
|------|----------------|
| A01: Broken Access Control | API Security + Entra ID + WAF |
| A02: Cryptographic Failures | All (TLS enforcement, Azure Key Vault) |
| A03: Injection | WAF + SAST + DAST |
| A04: Insecure Design | SAST + Compliance/GRC |
| A05: Security Misconfiguration | CSPM + CWPP |
| A06: Vulnerable Components | DAST/SCA (Snyk) |
| A07: Identification & Authentication Failures | Entra ID + PIM |
| A08: Software and Data Integrity Failures | SAST + DAST + Container Security |
| A09: Security Logging and Monitoring Failures | SIEM |
| A10: Server-Side Request Forgery (SSRF) | WAF + API Security |

---

## OWASP Mobile Top 10 (2024)

| Risk | Primary Agents |
|------|----------------|
| M1: Improper Credential Usage | MTD + Mobile App Security |
| M2: Inadequate Supply Chain Security | DAST/SCA |
| M3: Insecure Authentication/Authorization | Entra ID + MTD |
| M4: Insufficient Input/Output Validation | DAST |
| M5: Insecure Communication | MTD |
| M6: Inadequate Privacy Controls | DLP + DSPM |
| M7: Insufficient Binary Protections | Mobile App Security |
| M8: Security Misconfiguration | MDM (Intune) |
| M9: Insecure Data Storage | DLP + DSPM |
| M10: Insufficient Cryptography | All |

---

## Auditor Workflow

When responding to an audit for any framework above:

1. **Compliance/GRC Agent** generates the framework-specific evidence package
2. Auditor receives a portal link with:
   - Control descriptions
   - Mapped agents
   - Live evidence (last 90 days of logs, alerts, configurations)
   - Exception register with risk acceptance documentation
3. **Risk Dashboard Agent** provides quantitative metrics (control pass rates, MTTD, etc.)
4. **SIEM Agent** provides query access to underlying log evidence

---

*GlobalSec COMPLIANCE-MATRIX v1.0 · CONFIDENTIAL*
