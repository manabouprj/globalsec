# GlobalSec — High Level Design (HLD)

> **Author:** Alvin, Security Architect
> **Version:** 1.0
> **Classification:** CONFIDENTIAL — INTERNAL USE ONLY
> **Companion document:** `GlobalSec-LLD-v1.0.md`

---

## Document Control

| Field | Value |
|-------|-------|
| Document title | GlobalSec High Level Design |
| Version | 1.0 |
| Author | Alvin (Security Architect) |
| Audience | CISO, CTO, Security Architecture Council, Cloud Architecture Council, Regional Security Leads, Internal Audit |
| Review cadence | Quarterly |
| Distribution | Internal only |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Business Context & Drivers](#2-business-context--drivers)
3. [Solution Architecture](#3-solution-architecture)
4. [Multi-Region Topology](#4-multi-region-topology)
5. [SOC Operating Model](#5-soc-operating-model)
6. [Layered Architecture](#6-layered-architecture)
7. [Agent Catalogue](#7-agent-catalogue)
8. [Identity & Access Architecture](#8-identity--access-architecture)
9. [Data Architecture & Sovereignty](#9-data-architecture--sovereignty)
10. [Network Architecture](#10-network-architecture)
11. [Human-Agent Chat Interface](#11-human-agent-chat-interface)
12. [Single Pane of Glass Dashboard](#12-single-pane-of-glass-dashboard)
13. [Tooling Selection (Gartner MQ Leaders)](#13-tooling-selection-gartner-mq-leaders)
14. [Compliance Framework Mapping](#14-compliance-framework-mapping)
15. [Phased Deployment Strategy](#15-phased-deployment-strategy)
16. [Operational Model](#16-operational-model)
17. [Cost Model](#17-cost-model)
18. [Risk Register & Assumptions](#18-risk-register--assumptions)

---

## 1. Executive Summary

GlobalSec is an enterprise-scale, AI-agent-driven security platform designed for a multinational organisation with **115,000+ employees across 75 countries** spanning six geographic regions: APAC, Africa, Americas, Europe, GCC, and Middle East.

The platform delivers comprehensive security coverage across **17 security domains** through approximately **40 specialised AI agents**, orchestrated by **Paperclip**, surfaced through a global **Single Pane of Glass (SPOG) dashboard**, and operated through conversational interfaces on **Microsoft Teams** (primary) and **Slack** (secondary).

### Foundational Principles

| Principle | Description |
|-----------|-------------|
| **Cloud-agnostic, Azure-preferred** | Level 2 multi-cloud capable architecture — same agent code runs on Azure, AWS, GCP, or bare Kubernetes via runtime configuration. Reference deployment is Azure to maximize M365 E5 entitlements. See `docs/architecture/CLOUD-PORTABILITY.md` |
| **Best-of-breed integration** | Each control domain uses the Gartner Magic Quadrant leader. Tools are vendor-neutral where possible (CrowdStrike, Wiz, Tenable, Cloudflare run identically across clouds) |
| **Centralized SOC, regional reach** | Central SOC in the Middle East owns global tooling and incident response; Regional Security Leads provide local coordination |
| **Regional autonomy with global oversight** | Agents process data within regional boundaries to meet residency requirements; metadata flows to global control plane |
| **Zero Trust by default** | Microsoft Entra ID + Conditional Access + PIM enforces identity-based access at every boundary |
| **Compliance multiplexing** | Every event is tagged with applicable regulations (GDPR, UAE PDPL, HIPAA, etc.) for automated audit evidence |
| **Phased deployment** | 6 phases over 24 months, designed to deliver value from Phase 1 onwards while managing risk |

### Strategic Outcomes

- **Unified security posture** across all 6 regions through a single dashboard and reporting layer
- **Sub-15-minute MTTD** for critical threats anywhere in the global estate
- **Compliance-by-design** for 20+ regulatory frameworks (GDPR, UAE PDPL, DIFC, ADGM, HIPAA, PCI DSS, SOC 2, ISO 27001, NIS2, DORA, India DPDP, China PIPL, Brazil LGPD, etc.)
- **Centralized SOC efficiency** with regional accountability through Security Leads
- **Cost optimization** via Azure-native services + best-of-breed where it materially matters

---

## 2. Business Context & Drivers

### 2.1 Organisation Profile

| Dimension | Value |
|-----------|-------|
| Workforce | 115,000+ employees |
| Geographic footprint | 75 countries |
| Regions of operation | APAC · Africa · Americas · Europe · GCC · Middle East |
| Cloud strategy | Centralized Azure Commercial subscription (no sovereign cloud) |
| Headquarters | Middle East |
| Growth trajectory | Active expansion |

### 2.2 Threat Landscape

The enterprise faces threats consistent with global multinational organisations:

| Threat Category | Specific Concerns |
|-----------------|-------------------|
| **Nation-state actors** | APT groups targeting energy, finance, technology sectors |
| **Ransomware** | Sophisticated double/triple-extortion ransomware operators |
| **Supply chain** | Software supply chain compromise (SolarWinds-class attacks), third-party SaaS compromise |
| **Insider threats** | Both malicious and negligent insider risk across 115K users |
| **Cloud misconfiguration** | Public exposure of Azure resources, IAM overpermissioning |
| **Identity-based attacks** | Credential theft, MFA fatigue, OAuth phishing, token theft |
| **DDoS / availability** | Volumetric and application-layer attacks against customer-facing services |
| **Regulatory penalties** | GDPR (€20M / 4% of revenue), various regional equivalents |
| **Geopolitical risk** | Sanctions enforcement, regional conflict-driven cyber escalation |

### 2.3 Regulatory Environment

The platform must demonstrate compliance with regulations across all six operating regions:

| Region | Key Regulations |
|--------|-----------------|
| **APAC** | India DPDP (2023), Singapore PDPA, Australia Privacy Act, Japan APPI, China PIPL (no PRC operations assumed), Hong Kong PDPO, Korea PIPA |
| **Africa** | South Africa POPIA, Nigeria NDPA, Kenya DPA, Egypt Personal Data Protection Law |
| **Americas** | US (HIPAA, SOX, CCPA, NYDFS, FedRAMP if gov contracts), Canada PIPEDA, Brazil LGPD, Mexico LFPDPPP |
| **Europe** | GDPR, NIS2 Directive, DORA (financial services), Schrems II implications, ePrivacy |
| **GCC** | UAE PDPL, DIFC DPL 2020, ADGM DPR 2021, Saudi PDPL, Qatar DPPL, Bahrain PDPL, Kuwait DPL |
| **Middle East** | Egypt, Jordan, Lebanon — varying maturity levels |
| **Industry-specific** | PCI DSS v4.0, ISO/IEC 27001:2022, SOC 2 Type II, NIST CSF 2.0, MITRE ATT&CK v14, OWASP Top 10 |

### 2.4 Business Drivers

| Driver | Outcome Required |
|--------|-----------------|
| Regulatory compliance | Continuous audit-ready evidence across 20+ frameworks |
| Operational efficiency | Single SOC operating across 24 timezones with regional handoff |
| Cost discipline | Maximum reuse of Azure-native + Microsoft 365 E5 entitlements |
| Brand protection | Prevent breach disclosure events that damage 75-country reputation |
| Cyber insurance | Maintain insurability with continuous control demonstration |
| M&A integration | Rapid security onboarding of acquired entities (regional acquisitions common) |
| Board-level reporting | Quarterly cyber posture reporting at Board / Audit Committee level |

---

## 3. Solution Architecture

### 3.1 Conceptual View

```
                          ┌──────────────────────────────────────────────────────┐
                          │           GLOBAL CONTROL PLANE                       │
                          │           (Hosted in Middle East — Qatar Central)    │
                          │                                                      │
                          │  Paperclip Master · Global SPOG · Reporting Engine   │
                          │  Microsoft Sentinel (Global) · Defender XDR          │
                          │  Entra ID Tenant (Global) · Compliance Manager       │
                          └──────────────────────────┬───────────────────────────┘
                                                     │
        ┌────────────────────┬───────────────────────┼───────────────────┬────────────────────┐
        │                    │                       │                   │                    │
   ┌────▼────┐          ┌────▼────┐            ┌────▼────┐          ┌────▼────┐         ┌────▼────┐
   │  APAC   │          │  EMEA   │            │ AMER    │          │   GCC   │         │ AFRICA  │
   │  Hub    │          │   Hub   │            │  Hub    │          │   Hub   │         │   Hub   │
   │Singapore│          │Amsterdam│            │ Virginia│          │  Dubai  │         │  Joburg │
   └────┬────┘          └────┬────┘            └────┬────┘          └────┬────┘         └────┬────┘
        │                    │                       │                   │                    │
   ┌────▼────────┐      ┌────▼────────┐         ┌────▼────────┐     ┌────▼────────┐    ┌────▼────────┐
   │ Regional    │      │ Regional    │         │ Regional    │     │ Regional    │    │ Regional    │
   │ Paperclip   │      │ Paperclip   │         │ Paperclip   │     │ Paperclip   │    │ Paperclip   │
   │ Local agents│      │ Local agents│         │ Local agents│     │ Local agents│    │ Local agents│
   │ Sentinel WS │      │ Sentinel WS │         │ Sentinel WS │     │ Sentinel WS │    │ Sentinel WS │
   │ Regional    │      │ Regional    │         │ Regional    │     │ Regional    │    │ Regional    │
   │ Lead        │      │ Lead        │         │ Lead        │     │ Lead        │    │ Lead        │
   └─────────────┘      └─────────────┘         └─────────────┘     └─────────────┘    └─────────────┘
```

### 3.2 Core Architectural Decisions

| Decision | Rationale |
|----------|-----------|
| **Cloud abstraction layer** (SecretProvider, EventBus, ObjectStore, IdentityProvider) | Enables Level 2 multi-cloud — same agent code runs on Azure / AWS / GCP / bare K8s via `GLOBALSEC_CLOUD_PROVIDER` env var |
| **Two-tier orchestration** (global + regional) | Local data residency compliance + global correlation |
| **Single Entra ID tenant** with regional Entra B2B | One identity plane = one source of truth; regional B2B for partners |
| **Microsoft Sentinel global instance + regional Log Analytics workspaces** | Cross-workspace queries enable global SOC view while keeping logs regional |
| **Azure Virtual WAN hub-spoke** | Native Azure networking, ExpressRoute Global Reach for on-prem |
| **Microsoft Defender XDR as primary XDR** + **CrowdStrike Falcon as primary EDR** | Defender XDR aggregates Defender for Endpoint, Identity, Cloud Apps, Office 365; CrowdStrike provides best-in-class endpoint telemetry |
| **Vault-injected secrets** | Azure Key Vault with managed identities; zero credentials in code |
| **Chat as primary operator UX** | Microsoft Teams (already licensed) with Slack secondary for engineering |
| **Global SPOG with regional drill-down** | One pane for CISO + Central SOC; per-region views for Regional Leads |
| **Compliance-as-code** | Azure Policy enforces residency; Compliance Manager auto-collects evidence |

---

## 4. Multi-Region Topology

### 4.1 Regional Hubs

Each region is anchored to an Azure region with appropriate data residency:

| Region | Azure Region | Hub Location | Data Residency Coverage |
|--------|--------------|--------------|-------------------------|
| **APAC** | Southeast Asia | Singapore | India DPDP, Singapore PDPA, Australia Privacy Act, Japan APPI, Korea PIPA |
| **EMEA / Europe** | West Europe | Amsterdam | GDPR, NIS2, DORA |
| **Americas** | East US 2 | Virginia | US federal/state laws, Canada PIPEDA, LGPD via cross-region |
| **GCC** | UAE North | Dubai | UAE PDPL, DIFC, ADGM, Saudi PDPL, Bahrain, Kuwait |
| **Middle East** | Qatar Central | Doha | Qatar DPPL, Egypt PDPL, Jordan, Lebanon — **also hosts Global Control Plane** |
| **Africa** | South Africa North | Johannesburg | South Africa POPIA, Nigeria NDPA, Kenya DPA |

### 4.2 Inter-Region Connectivity

- **Azure Virtual WAN** connects all 6 regional hubs via Microsoft backbone (low latency, encrypted)
- **ExpressRoute** connects on-premises offices in each region to nearest regional hub
- **ExpressRoute Global Reach** allows on-prem-to-on-prem traffic across regions over Microsoft backbone
- **Private Endpoints** for all PaaS services — no public endpoints exposed
- **Azure Firewall Premium** in each hub for east-west and north-south inspection
- **Azure DDoS Protection Standard** on all public-facing IPs

### 4.3 Data Flow Patterns

**Local processing, global metadata:**
- Raw security telemetry stays in regional Log Analytics workspaces
- Only **metadata** (alert IDs, severity, MITRE tactic, source agent, posture deltas) flows to the global control plane
- Cross-workspace KQL queries enable global SOC analysts to drill into regional data on demand
- Long-term archival stays regional (Azure Storage with immutability locks per regional retention requirements)

**Identity is global:**
- Single Entra ID tenant
- Conditional Access policies are global with regional exceptions where required
- Privileged Identity Management (PIM) provides JIT access globally

---

## 5. SOC Operating Model

### 5.1 Hub-and-Spoke SOC

The enterprise operates a **hub-and-spoke SOC model** rather than follow-the-sun:

```
                          ┌──────────────────────────────────┐
                          │       CENTRAL SOC                │
                          │       Middle East (Doha/Dubai)   │
                          │                                  │
                          │  · Tier 1 / Tier 2 / Tier 3      │
                          │  · 24/7 staffing via shifts      │
                          │  · Global threat hunting         │
                          │  · Major incident command        │
                          │  · Tooling ownership             │
                          └────────────────┬─────────────────┘
                                           │
              ┌────────────┬───────────────┼────────────────┬─────────────┐
              │            │               │                │             │
        ┌─────▼─────┐ ┌────▼─────┐  ┌──────▼──────┐  ┌──────▼──────┐ ┌────▼──────┐
        │  APAC     │ │  EMEA    │  │   AMER      │  │   GCC       │ │  AFRICA   │
        │  Regional │ │  Regional│  │   Regional  │  │   Regional  │ │  Regional │
        │  Lead     │ │  Lead    │  │   Lead      │  │   Lead      │ │  Lead     │
        │           │ │          │  │             │  │             │ │           │
        │  · BU     │ │  · BU    │  │   · BU      │  │   · BU      │ │  · BU     │
        │  liaison  │ │  liaison │  │   liaison   │  │   liaison   │ │  liaison  │
        │  · Local  │ │  · Local │  │   · Local   │  │   · Local   │ │  · Local  │
        │  IR coord │ │  IR coord│  │   IR coord  │  │   IR coord  │ │  IR coord │
        │  · Reg.   │ │  · Reg.  │  │   · Reg.    │  │   · Reg.    │ │  · Reg.   │
        │  compliance│ compliance│  │   compliance│  │   compliance│ │  compliance│
        └───────────┘ └──────────┘  └─────────────┘  └─────────────┘ └───────────┘
```

### 5.2 Roles & Responsibilities

| Role | Location | Headcount (target) | Responsibilities |
|------|----------|-------------------|------------------|
| **CISO** | Middle East HQ | 1 | Global accountability, board reporting |
| **Head of SOC** | Central SOC | 1 | SOC leadership, tooling strategy |
| **Tier 1 Analysts** | Central SOC | 12 (3 shifts × 4) | 24/7 alert triage, ticket creation |
| **Tier 2 Analysts** | Central SOC | 8 | Investigation, correlation, playbook execution |
| **Tier 3 / Threat Hunters** | Central SOC | 4 | Proactive hunting, IR command, advanced threats |
| **Regional Security Leads** | Each region (×6) | 6 | BU coordination, regional compliance, escalation |
| **Security Engineers** | Distributed | 12 | Agent operations, integration, automation |
| **Threat Intel Analysts** | Central SOC | 3 | TI ingestion, IOC management, vendor relations |
| **GRC Team** | Distributed | 8 | Compliance evidence, audit response, policy |
| **Total core security headcount** | | **~55** | (~1 security FTE per 2,000 employees) |

### 5.3 Escalation Workflow

```
Alert raised by agent
        │
        ▼
SIEM correlates → IR Agent creates ticket in ServiceNow
        │
        ▼
Tier 1 (Central SOC, 24/7) — triage within 15 min SLA
        │
        ├── False Positive? → Close + tune
        ├── Routine? → Auto-playbook executes
        └── Escalate to Tier 2
                        │
                        ▼
                Tier 2 — investigation within 1 hr SLA
                        │
                        ├── Resolve via standard playbook
                        └── Escalate to Tier 3
                                        │
                                        ▼
                Tier 3 + Regional Lead — major incident
                        │
                        ├── Regional Lead notifies BU stakeholders
                        ├── Tier 3 leads technical IR
                        └── Crisis Comms agent triggered if reportable breach
                                        │
                                        ▼
                CISO + Legal + Comms briefed
```

### 5.4 Communication Channels

| Channel Type | Tool | Use |
|--------------|------|-----|
| Real-time chat | Microsoft Teams (#globalsec-soc-central) | Tier 1/2/3 daily ops |
| Regional channels | Teams (#globalsec-soc-apac, #globalsec-soc-emea, etc.) | Regional Lead ↔ Central SOC |
| Major incident bridge | Teams Live Meeting + War Room | All major incidents |
| Engineering | Slack (#globalsec-engineering) | Agent dev + automation |
| Executive escalation | Phone tree + Teams | CISO and above |

---

## 6. Layered Architecture

The platform is organised into 6 horizontal layers:

### Layer 6 — Reporting & Insight
- Global SPOG dashboard
- Auto-generated monthly technical and quarterly business reports
- Board-level dashboards
- Audit evidence portals

### Layer 5 — Human Interface
- Microsoft Teams (primary) — central + regional channels
- Slack (secondary) — engineering channels
- ServiceNow (incident tickets, change management)
- PowerBI embedded in Teams

### Layer 4 — Orchestration
- Global Paperclip control plane (Middle East)
- Regional Paperclip orchestrators (one per region)
- Inter-orchestrator event bus over Azure Service Bus
- Azure Key Vault for secrets injection
- Azure Managed Identities for authentication

### Layer 3 — Agent Mesh
- ~40 specialised AI agents
- Containerised, deployed via Azure Kubernetes Service (AKS)
- Per-region agent instances where data residency required
- Single global instance for non-residency-sensitive agents (e.g. Threat Intel)

### Layer 2 — Tool Integration
- Best-of-breed security tools (CrowdStrike, Sentinel, Wiz, Tenable, etc.)
- Microsoft Defender XDR suite (native integration)
- Azure-native services (Defender for Cloud, Purview, Entra)

### Layer 1 — Infrastructure
- Azure Landing Zones aligned to Microsoft Cloud Adoption Framework (CAF)
- Hub-and-spoke topology via Azure Virtual WAN
- ExpressRoute for hybrid connectivity
- Azure Firewall Premium per regional hub

---

## 7. Agent Catalogue

The platform comprises approximately **40 agents** across 17 security domains. The full per-agent technical specification is in `GlobalSec-LLD-v1.0.md`.

### 7.1 Agent Categories

| Category | Agent Count | Examples |
|----------|-------------|----------|
| **Endpoint** | 2 | EDR (CrowdStrike), MDM (Intune) |
| **Identity** | 3 | Entra ID, PIM, PAM (CyberArk) |
| **Email & Communication** | 2 | Email Security (Defender + Proofpoint), Teams Security |
| **Network** | 4 | DNS Security, Web Proxy/SSE (Netskope), Network Detection (Darktrace), CDN Security |
| **Application** | 5 | WAF + Bot (Cloudflare), API Security (Salt), SAST (Checkmarx), DAST/SCA (Snyk), Mobile Threat Defense (Lookout) |
| **Data** | 4 | DLP (Purview), Insider Risk (Purview IRM), DSPM (Varonis), Data Residency |
| **Detection & Response** | 3 | SIEM (Sentinel), SOAR, Incident Response |
| **Cloud Security** | 3 | CSPM/CNAPP (Wiz), CWPP (Defender for Cloud), Container Security |
| **Threat Intelligence** | 3 | Threat Intel (Recorded Future), Brand Protection (ZeroFox), Deception (Illusive) |
| **Governance** | 5 | Asset Management (Axonius), Vulnerability Management (Tenable), Compliance/GRC (ServiceNow), Risk Dashboard, EASM |
| **Resilience** | 2 | Backup & Recovery (Veeam + Azure Backup), Crisis Communications |
| **Specialized** | 4 | Third-Party Risk (OneTrust), Mobile App Security (NowSecure), OT/IoT Security (Defender for IoT), ESG/Sustainability |

### 7.2 Agent Tier Classification

| Tier | Description | Agent Count |
|------|-------------|-------------|
| **Tier 0 — Core** | Mandatory for any operational deployment | 12 agents |
| **Tier 1 — Standard** | Required for enterprise scale | 18 agents |
| **Tier 2 — Advanced** | Specialized capabilities | 10 agents |

### 7.3 Full Agent List

| # | Agent | Tier | Domain | Tool / Vendor |
|---|-------|------|--------|---------------|
| 1 | EDR Agent | T0 | Endpoint | CrowdStrike Falcon Enterprise |
| 2 | MDM Agent | T1 | Endpoint | Microsoft Intune |
| 3 | Entra ID Agent | T0 | Identity | Microsoft Entra ID + ID Governance |
| 4 | PIM Agent | T0 | Identity | Microsoft Entra Privileged Identity Management |
| 5 | PAM Agent | T1 | Identity | CyberArk Privilege Cloud |
| 6 | Email Security Agent | T0 | Communication | Microsoft Defender for O365 P2 + Proofpoint TAP |
| 7 | Teams Security Agent | T1 | Communication | Microsoft Defender for Cloud Apps |
| 8 | DNS Security Agent | T0 | Network | Cisco Umbrella + Azure DNS Private Resolver |
| 9 | SSE / Web Proxy Agent | T1 | Network | Netskope ONE |
| 10 | Network Detection Agent | T1 | Network | Darktrace + Defender for Identity |
| 11 | CDN Security Agent | T2 | Network | Cloudflare |
| 12 | WAF + Bot Agent | T0 | Application | Cloudflare Enterprise + Azure Front Door WAF |
| 13 | API Security Agent | T1 | Application | Salt Security |
| 14 | SAST Agent | T1 | Application | Checkmarx One |
| 15 | DAST/SCA Agent | T1 | Application | Snyk |
| 16 | Mobile Threat Defense Agent | T2 | Application | Lookout |
| 17 | DLP Agent | T0 | Data | Microsoft Purview DLP |
| 18 | Insider Risk Agent | T1 | Data | Microsoft Purview Insider Risk Management |
| 19 | DSPM Agent | T1 | Data | Varonis Data Security Platform |
| 20 | Data Residency Agent | T0 | Data | Custom + Azure Policy + Purview |
| 21 | SIEM Agent | T0 | Detection | Microsoft Sentinel |
| 22 | SOAR Agent | T1 | Detection | Microsoft Sentinel SOAR + Logic Apps |
| 23 | Incident Response Agent | T0 | Detection | ServiceNow SecOps + PagerDuty |
| 24 | CSPM / CNAPP Agent | T0 | Cloud | Wiz |
| 25 | CWPP Agent | T1 | Cloud | Microsoft Defender for Cloud |
| 26 | Container Security Agent | T1 | Cloud | Wiz + Defender for Containers |
| 27 | Threat Intelligence Agent | T1 | Threat Intel | Recorded Future |
| 28 | Brand Protection Agent | T2 | Threat Intel | ZeroFox |
| 29 | Deception Agent | T2 | Threat Intel | Illusive (Proofpoint) |
| 30 | Asset Management Agent | T0 | Governance | Axonius |
| 31 | Vulnerability Management Agent | T0 | Governance | Tenable One |
| 32 | Compliance / GRC Agent | T1 | Governance | ServiceNow GRC + Microsoft Compliance Manager |
| 33 | Risk Dashboard Agent | T0 | Governance | Custom + Sentinel + Power BI |
| 34 | EASM Agent | T1 | Governance | Microsoft Defender EASM |
| 35 | Backup & Recovery Agent | T1 | Resilience | Veeam + Azure Backup |
| 36 | Crisis Communications Agent | T2 | Resilience | Custom + Teams + Email |
| 37 | Third-Party Risk Agent | T1 | Specialized | OneTrust + SecurityScorecard |
| 38 | OT / IoT Security Agent | T2 | Specialized | Microsoft Defender for IoT + Claroty |
| 39 | ESG / Sustainability Agent | T2 | Specialized | Custom + Azure Sustainability Calculator |
| 40 | Chat Interface Agent | T0 | Integration | Slack Bolt + Teams Bot Framework |

---

## 8. Identity & Access Architecture

### 8.1 Identity as the New Perimeter

In a global enterprise with no traditional network perimeter, **identity is the security boundary**. The platform implements a Zero Trust identity model:

```
User Request
    │
    ▼
Conditional Access Policy
    │
    ├── Device compliant? (Intune attestation)
    ├── Location risk? (Named locations, anomaly detection)
    ├── User risk? (Identity Protection)
    ├── Application sensitivity? (Resource tier)
    │
    ▼
Decision: Allow / MFA / Block / Require Compliant Device
    │
    ▼
If privileged access requested → PIM elevation
    │
    ├── JIT activation with approval
    ├── Time-bounded (default 1 hour, max 8 hours)
    ├── Audit log immutable
    │
    ▼
PAM session (CyberArk) for sensitive infrastructure
    │
    ├── Session recording
    ├── Credential vaulting (no human sees passwords)
    ├── Real-time monitoring
```

### 8.2 Identity Components

| Component | Tool | Purpose |
|-----------|------|---------|
| **Authoritative directory** | Microsoft Entra ID | Single source of truth for 115K identities |
| **Conditional Access** | Entra ID Conditional Access | Policy-based access decisions |
| **Identity Protection** | Entra ID Identity Protection | Risk-based authentication |
| **Privileged Identity Management** | Entra PIM | JIT for privileged Azure / M365 roles |
| **Identity Governance** | Entra ID Governance | Access reviews, lifecycle management, entitlement management |
| **Privileged Access Management** | CyberArk Privilege Cloud | Privileged credential vault, session recording |
| **MFA enforcement** | Microsoft Authenticator (preferred) + FIDO2 keys (executives) | Phishing-resistant MFA |
| **B2B / external identity** | Entra ID External Identities | Partner / vendor access |
| **Workload identity** | Managed Identities + Workload Identity Federation | Service-to-service auth |

### 8.3 Privilege Tiers

The platform implements **Microsoft Tiered Administration Model**:

| Tier | Scope | Access Method | Approver |
|------|-------|---------------|----------|
| **Tier 0** | Domain controllers, Entra Global Admins, root Azure subscription | PIM + PAM session, hardware token | CISO + Head of SOC |
| **Tier 1** | Server admin, regional Azure subscriptions, security tooling | PIM, MFA, session recording | Head of SOC |
| **Tier 2** | Workstation admin, application admin | MFA, conditional access | Manager |
| **Tier 3** | Standard user | MFA, conditional access | Self-service |

---

## 9. Data Architecture & Sovereignty

### 9.1 Data Classification Schema

| Classification | Examples | Controls |
|----------------|----------|----------|
| **Public** | Marketing materials, public website | No restrictions |
| **Internal** | Internal communications, non-sensitive operational data | Encrypted at rest, internal access only |
| **Confidential** | Customer PII, financial data, employee records | Encrypted at rest + transit, DLP policies, regional residency |
| **Restricted** | Cardholder data, health data, executive comms | Strict DLP, watermarking, no external sharing, audit every access |
| **Top Secret** | M&A info, strategic plans, classified gov data | Air-gapped storage, executive-only access |

### 9.2 Data Residency Enforcement

Each region's data must remain within Azure regions that satisfy local regulations:

| Region | Approved Azure Regions | Prohibited Regions |
|--------|------------------------|--------------------|
| APAC (general) | Southeast Asia, East Asia, Australia East, Japan East, Korea Central | China, Russia |
| Europe | West Europe, North Europe, France Central, Germany West Central, UK South | Non-EU/EEA |
| GCC | UAE North, UAE Central, Qatar Central | Outside MENA |
| Africa | South Africa North, South Africa West | — |
| Americas | East US 2, West US 3, Brazil South, Canada Central | — |

**Enforcement:** Azure Policy `Allowed locations` denies resource creation outside approved regions per subscription/management group.

### 9.3 Data Lifecycle

```
Creation → Classification (auto via Purview) → Storage (regional) → Use (DLP enforced)
   → Sharing (Purview + Conditional Access) → Retention (per regulation) → Deletion (verified)
```

### 9.4 Cross-Border Transfer Controls

When data must legitimately cross regions (e.g., consolidated reporting):

- **Pseudonymization** applied via Purview before transfer
- **Standard Contractual Clauses (SCCs)** for EU → non-EU
- **Approved transfer mechanisms** logged for audit
- **Data Residency Agent** continuously monitors and alerts on prohibited transfers

---

## 10. Network Architecture

### 10.1 Hub-and-Spoke via Azure Virtual WAN

```
                   ┌─────────────────────────────────┐
                   │   Azure Virtual WAN             │
                   │   (Microsoft Backbone)          │
                   └─┬──────┬──────┬──────┬──────┬───┘
                     │      │      │      │      │
         ┌───────────┘  ┌───┘   ┌──┘    ┌─┘     └──────┐
         │              │       │       │              │
    ┌────▼────┐   ┌─────▼───┐ ┌─▼────┐ ┌▼─────┐  ┌────▼────┐
    │ APAC    │   │ EMEA    │ │AMER  │ │ GCC  │  │AFRICA   │
    │ Hub     │   │ Hub     │ │Hub   │ │ Hub  │  │ Hub     │
    │SG       │   │NL       │ │US    │ │UAE   │  │ZA       │
    │         │   │         │ │      │ │      │  │         │
    │·AzFW Pre│   │·AzFW Pre│ │·AzFW │ │·AzFW │  │·AzFW    │
    │·DDoS    │   │·DDoS    │ │·DDoS │ │·DDoS │  │·DDoS    │
    │·ExR     │   │·ExR     │ │·ExR  │ │·ExR  │  │·ExR     │
    └────┬────┘   └────┬────┘ └──┬───┘ └──┬───┘  └────┬────┘
         │             │         │        │           │
    ┌────▼────┐   ┌────▼────┐ ┌──▼──┐  ┌──▼──┐  ┌────▼────┐
    │Spoke    │   │Spoke    │ │Spoke│  │Spoke│  │Spoke    │
    │VNets    │   │VNets    │ │VNets│  │VNets│  │VNets    │
    │(BU prod)│   │(BU prod)│ │     │  │     │  │         │
    └─────────┘   └─────────┘ └─────┘  └─────┘  └─────────┘
```

### 10.2 Network Security Components

| Component | Tool | Purpose |
|-----------|------|---------|
| Virtual WAN | Azure | Hub interconnect over Microsoft backbone |
| Hub firewalls | Azure Firewall Premium | Threat intel-based filtering, IDPS, TLS inspection |
| DDoS protection | Azure DDoS Protection Standard | L3/4 + L7 DDoS mitigation |
| WAF | Cloudflare Enterprise + Azure Front Door | OWASP rule sets, bot management |
| Private connectivity | Azure Private Link / Private Endpoints | No public exposure of PaaS services |
| Hybrid connectivity | ExpressRoute (per region) | Office-to-Azure |
| Cross-region routing | ExpressRoute Global Reach | Office-to-office over Microsoft |
| Network Detection | Darktrace + Defender for Identity | East-west traffic anomaly detection |
| Secure Service Edge | Netskope ONE | SaaS access control, CASB, ZTNA |

### 10.3 Network Segmentation

- **Production / Non-production** separation via dedicated subscriptions
- **East-west microsegmentation** via Network Security Groups + Application Security Groups
- **Container networking** via Azure CNI with NetworkPolicy
- **Zero Trust** — no implicit trust based on network location; identity + device posture govern access

---

## 11. Human-Agent Chat Interface

### 11.1 Primary Platform: Microsoft Teams

The enterprise standardises on Microsoft Teams (already part of M365 E5 entitlement). Each agent has a dedicated channel within the **GlobalSec** Team:

```
Team: GlobalSec Security Operations
├── 🌍 General — announcements
├── 🚨 #soc-central — Tier 1/2/3 alerts (high traffic)
├── 🇸🇬 #soc-apac — APAC Regional Lead channel
├── 🇳🇱 #soc-emea — EMEA Regional Lead channel
├── 🇺🇸 #soc-amer — AMER Regional Lead channel
├── 🇦🇪 #soc-gcc — GCC Regional Lead channel
├── 🇿🇦 #soc-africa — Africa Regional Lead channel
│
├── Agent Channels:
│   ├── #agent-edr — CrowdStrike alerts
│   ├── #agent-siem — Sentinel alerts
│   ├── #agent-identity — Entra + PIM events
│   ├── #agent-pam — CyberArk session events
│   ├── #agent-email — Defender for O365 alerts
│   ├── #agent-dlp — Data exfil events
│   ├── #agent-insider — Purview IRM alerts
│   ├── #agent-cloud — Wiz / Defender for Cloud
│   ├── #agent-vuln — Tenable findings
│   ├── #agent-asset — Axonius drift
│   ├── #agent-network — Darktrace alerts
│   ├── #agent-waf — Cloudflare attacks
│   ├── #agent-api — Salt Security
│   ├── #agent-threat-intel — Recorded Future
│   ├── #agent-brand — ZeroFox
│   ├── #agent-3p-risk — OneTrust
│   └── ... (one per agent, ~40 channels)
│
├── #ir-major — Major incident war room
├── #ir-playbook-runs — SOAR execution log
├── #compliance-evidence — Audit evidence collection
├── #risk-dashboard — Posture queries
└── #engineering — Agent dev (Slack mirror)
```

### 11.2 Secondary Platform: Slack

For engineering and DevSecOps workflows that engineering teams already operate in Slack — agent code repos, CI/CD failures, dependency updates.

### 11.3 Slash Commands

Same command syntax as EcomSec, expanded for enterprise needs:

| Command | Description |
|---------|-------------|
| `/status [agent-id]` | Live health and current metrics |
| `/alert list [region]` | Active alerts, optionally filtered by region |
| `/alert ack <id>` | Acknowledge with operator + timestamp |
| `/isolate <hostname>` | Endpoint isolation (EDR) |
| `/block <ip\|domain\|url>` | Block across DNS + WAF + Web Proxy + Email |
| `/scan <target>` | On-demand scan |
| `/hunt <query>` | Run a threat hunting KQL query in Sentinel |
| `/playbook run <name>` | Execute SOAR playbook |
| `/incident create <severity>` | Create ServiceNow incident |
| `/region <region>` | Switch regional context |
| `/compliance check <framework>` | Audit-ready evidence dump |
| `/report [monthly\|quarterly\|board]` | Generate report |
| `/setup <agent-id>` | Interactive agent setup wizard |
| `/escalate <incident-id>` | Escalate to Regional Lead or CISO |
| `/help` | Full command reference |

---

## 12. Single Pane of Glass Dashboard

### 12.1 Three-Tier Dashboard Architecture

| Tier | Audience | Hosted In | Purpose |
|------|----------|-----------|---------|
| **Board / CISO** | C-suite, Audit Committee | Power BI in Teams | Quarterly posture, risk heatmap, regulatory exposure |
| **Central SOC** | SOC Manager, Tier 2/3 | Custom React SPOG (Azure App Service) | Real-time global ops, MITRE coverage, threat hunting |
| **Regional Lead** | Per-region leads | Same SPOG with regional filter | Regional view of agents, BU coordination |

### 12.2 Widget Catalogue (Expanded)

Inherits all EcomSec widgets plus enterprise-specific:

| Widget | Tier | Description |
|--------|------|-------------|
| Global Posture Score | All | 0-100 with regional breakdown |
| Regional Posture Heatmap | All | Map view of 6 regions with RAG status |
| Compliance Matrix | Board | Frameworks × regions with % compliance |
| MITRE ATT&CK Coverage Heatmap | SOC | Per-region tactic coverage |
| Live Alert Feed | SOC | Streaming alerts with regional filter |
| Top 10 Risks | Board | Business-language risk register |
| Agent Health Matrix | SOC | All ~40 agents × 6 regions = 240 health indicators |
| Threat Activity World Map | All | Live attack origins |
| Identity Risk Snapshot | SOC | Risky users, leaked credentials, MFA gaps |
| Privileged Access Audit | SOC | Active PIM activations, PAM sessions |
| Vulnerability Burndown | SOC | CVE remediation by severity over time |
| Insider Risk Indicators | SOC | Purview IRM signals |
| Third-Party Risk Heatmap | All | Vendor risk scores |
| Cost & Optimization | SOC | Tool spend, license utilization |
| Incident Timeline | All | Major incidents with MTTR |
| Regulatory Readiness | Board | Audit calendar, evidence completeness |
| Change Risk Indicator | SOC | Unusual config changes detected |
| Insider Risk | SOC | Purview IRM signals |
| ESG / Sustainability | Board | Cyber-related ESG metrics |

---

## 13. Tooling Selection (Gartner MQ Leaders)

### 13.1 Selection Methodology

Each tool was selected based on:
1. **Gartner Magic Quadrant Leader status** (current or recent)
2. **Native Azure integration** depth
3. **Enterprise scale capability** (115K+ users)
4. **Regional support** across 75 countries
5. **Existing M365 E5 entitlement leverage** where applicable

### 13.2 Full Tool Selection Matrix

| Domain | Selected Tool | Gartner Position | Why |
|--------|--------------|------------------|-----|
| EDR | **CrowdStrike Falcon Enterprise** | MQ Leader (Endpoint Protection Platforms) | User specified; best-in-class telemetry |
| XDR | **Microsoft Defender XDR** | MQ Leader (XDR) | Native consolidation of M365 signals |
| SIEM | **Microsoft Sentinel** | MQ Leader (SIEM) | Cloud-native, Azure-integrated, scales to 115K |
| SOAR | **Sentinel SOAR + Logic Apps** | Integrated with SIEM Leader | Native automation |
| IAM | **Microsoft Entra ID + ID Governance** | MQ Leader (Access Management) | M365 E5 entitlement |
| PAM | **CyberArk Privilege Cloud** | MQ Leader (PAM) | Industry standard for enterprise |
| Email | **Microsoft Defender for O365 P2 + Proofpoint TAP** | Both MQ Leaders | Defender native, Proofpoint advanced |
| DLP | **Microsoft Purview DLP** | MQ Leader (Enterprise DLP) | M365 E5 entitlement |
| Insider Risk | **Microsoft Purview IRM** | MQ Leader (Insider Risk Mgmt) | Same platform |
| CASB / SSE | **Netskope ONE** | MQ Leader (SSE) | Comprehensive SSE platform |
| WAF | **Cloudflare Enterprise** | MQ Leader (WAAP) | Performance + security |
| API Security | **Salt Security** | MQ Leader (API Security) | API-first approach |
| Bot Management | **Cloudflare Bot Management** | Same vendor as WAF | Integrated |
| CSPM/CNAPP | **Wiz** | MQ Leader (CNAPP) | Agentless, fastest scan times |
| CWPP | **Microsoft Defender for Cloud** | MQ Leader (CWPP) | Azure-native |
| Vuln Mgmt | **Tenable One** | MQ Leader (Vuln Assessment) | Best CVE coverage |
| SAST | **Checkmarx One** | MQ Leader (SAST) | Best language coverage |
| DAST/SCA | **Snyk** | MQ Leader (Application Security Testing) | Developer-friendly |
| NDR | **Darktrace** | MQ Leader (NDR) | AI-driven detection |
| Threat Intel | **Recorded Future** | MQ Leader (Security Threat Intel) | Most comprehensive sources |
| Brand Protection | **ZeroFox** | MQ Leader (Digital Risk Protection) | Strong takedown ops |
| DSPM | **Varonis Data Security Platform** | MQ Leader (DSPM) | Data-centric approach |
| Backup | **Veeam + Azure Backup** | MQ Leader (Backup) | Veeam enterprise, Azure native |
| GRC | **ServiceNow GRC** | MQ Leader (IRM) | Existing ServiceNow likely deployed |
| TPRM | **OneTrust + SecurityScorecard** | Both MQ Leaders | OneTrust for workflow, SSC for ratings |
| Mobile (MTD) | **Lookout** | MQ Leader (Mobile Threat Defense) | Cross-platform |
| MDM | **Microsoft Intune** | MQ Leader (UEM) | M365 E5 entitlement |
| OT/IoT | **Defender for IoT + Claroty** | MQ Leaders (OT Security) | If applicable |
| Asset Mgmt | **Axonius** | MQ Leader (Cyber Asset Attack Surface Mgmt) | Best aggregation |
| EASM | **Microsoft Defender EASM** | MQ Visionary | Native + cost-effective |
| Deception | **Illusive (Proofpoint)** | Niche but mature | Specialized capability |

---

## 14. Compliance Framework Mapping

### 14.1 Regulations Covered

The platform demonstrates compliance across **20+ frameworks**:

| Region | Regulation | Key Agents Providing Evidence |
|--------|-----------|-------------------------------|
| Global | ISO/IEC 27001:2022 | All — Compliance/GRC orchestrates |
| Global | NIST CSF 2.0 | All — mapped across 6 functions |
| Global | SOC 2 Type II | Asset Mgmt, IAM, Incident Response, Backup |
| Global | PCI DSS v4.0 | WAF, SIEM, Vuln Mgmt, Network Detection |
| Global | MITRE ATT&CK v14 | EDR, SIEM, Threat Intel, Network Detection |
| Global | OWASP Top 10 (2021) | WAF + Bot, API Security, SAST/DAST |
| Europe | GDPR | DLP, Data Residency, Insider Risk, IR |
| Europe | NIS2 Directive | All — risk-based with reporting |
| Europe | DORA (financial services) | All — operational resilience focus |
| US | HIPAA (if healthcare) | DLP, IAM, EDR, Backup |
| US | SOX | IAM, PAM, SIEM, Audit logging |
| US | CCPA / CPRA | DLP, Data Residency, Insider Risk |
| US | NYDFS Cyber | Comprehensive — all agents |
| US | FedRAMP (if gov) | Specialized control set |
| Canada | PIPEDA | DLP, Data Residency |
| LATAM | LGPD (Brazil) | DLP, Data Residency, IR |
| LATAM | Mexico LFPDPPP | DLP, Data Residency |
| GCC | UAE PDPL | DLP, Data Residency, IR |
| GCC | DIFC DPL 2020 | Same |
| GCC | ADGM DPR 2021 | Same |
| GCC | Saudi PDPL | Same |
| GCC | Qatar DPPL | Same |
| Africa | South Africa POPIA | DLP, Data Residency |
| Africa | Nigeria NDPA | Same |
| Africa | Kenya DPA | Same |
| APAC | India DPDP (2023) | DLP, Data Residency |
| APAC | Singapore PDPA | Same |
| APAC | Australia Privacy Act | Same |
| APAC | Japan APPI | Same |
| APAC | Korea PIPA | Same |

### 14.2 Compliance-as-Code

**Azure Policy** enforces:
- Resource location restrictions per region
- Encryption requirements (data at rest + in transit)
- Tag policies (data classification, owner, compliance scope)
- Network configurations (no public IP, private endpoints required)
- Identity policies (MFA enforcement, no legacy auth)

**Microsoft Compliance Manager** auto-collects:
- Audit evidence per framework
- Control effectiveness scores
- Improvement actions

**ServiceNow GRC** orchestrates:
- Audit calendar
- Evidence collection workflow
- Auditor portal access
- Findings remediation tracking

---

## 15. Phased Deployment Strategy

The platform deploys across **6 phases over 24 months** to manage risk, demonstrate value, and align with budget cycles.

### Phase 1 — Foundation (Months 1–4)
**Goal:** Establish identity, central SOC, and core visibility

| Agents | Purpose |
|--------|---------|
| Entra ID Agent | Identity baseline |
| PIM Agent | Privileged access controls |
| EDR Agent (CrowdStrike) | Endpoint protection rolled out region-by-region |
| Email Security Agent | Phishing & BEC defense |
| SIEM Agent (Sentinel) | Central logging |
| Risk Dashboard Agent | Posture visibility |
| Chat Interface Agent | Teams integration |
| Asset Management Agent | Inventory baseline |

**Deliverables:** Central SOC operational; CrowdStrike on 25K endpoints (priority offices); Sentinel ingesting M365 + Azure logs.

### Phase 2 — Core Defense (Months 5–8)
**Goal:** Application + data + cloud baseline

| Agents | Purpose |
|--------|---------|
| WAF + Bot Agent | Web protection |
| API Security Agent | API attack surface |
| DLP Agent | Data leak prevention |
| CSPM/CNAPP Agent (Wiz) | Cloud posture |
| Vulnerability Management Agent | CVE program |
| Incident Response Agent | IR automation |
| SOAR Agent | Playbook automation |
| Data Residency Agent | Regional compliance |

**Deliverables:** Production web/API protected; cloud baseline scan complete; first SOAR playbook live (credential stuffing response).

### Phase 3 — Advanced Detection (Months 9–13)
**Goal:** Network detection, threat intel, advanced response

| Agents | Purpose |
|--------|---------|
| Network Detection Agent (Darktrace) | East-west visibility |
| Threat Intelligence Agent (Recorded Future) | TI feed |
| PAM Agent (CyberArk) | Privileged session management |
| MDM Agent (Intune) | Device compliance |
| SAST Agent + DAST/SCA Agent | DevSecOps |
| SSE / Web Proxy Agent (Netskope) | Cloud-delivered web security |

**Deliverables:** Darktrace deployed across all regions; PAM controlling Tier 0 access; SAST/DAST in CI/CD; Netskope rollout 50%.

### Phase 4 — Data & Insider Risk (Months 14–17)
**Goal:** Advanced data protection, insider threat program

| Agents | Purpose |
|--------|---------|
| Insider Risk Agent (Purview IRM) | Insider threat program |
| DSPM Agent (Varonis) | Data-centric risk |
| CWPP Agent (Defender for Cloud) | Workload protection |
| Container Security Agent | Kubernetes security |
| Compliance / GRC Agent (ServiceNow) | Audit automation |
| EASM Agent (Defender EASM) | External attack surface |

**Deliverables:** Insider risk program live; Varonis identifies stale-data risks; ISO 27001 audit-ready.

### Phase 5 — Specialised (Months 18–21)
**Goal:** Advanced and specialized capabilities

| Agents | Purpose |
|--------|---------|
| Brand Protection Agent (ZeroFox) | DRPS |
| Third-Party Risk Agent (OneTrust) | Vendor program |
| Mobile Threat Defense Agent (Lookout) | Mobile attack surface |
| Mobile App Security Agent | Mobile app testing |
| Backup & Recovery Agent (Veeam + Azure Backup) | Resilience |
| CDN Security Agent | Content delivery security |
| Teams Security Agent | Collaboration security |

**Deliverables:** TPRM program covering top 500 vendors; mobile fleet protected; backup recovery drills passing.

### Phase 6 — Optimization (Months 22–24)
**Goal:** Specialized + emerging

| Agents | Purpose |
|--------|---------|
| OT / IoT Security Agent | If applicable |
| Deception Agent (Illusive) | Honey-token deployment |
| ESG / Sustainability Agent | Cyber-ESG reporting |
| Crisis Communications Agent | Reportable breach response |

**Deliverables:** Full agent mesh operational; first board report delivered; platform handed to BAU operations.

### Phase Summary

| Phase | Months | Agents Added | Cumulative | Capability Outcome |
|-------|--------|--------------|------------|--------------------|
| 1 | 1–4 | 8 | 8 | Identity + endpoint + email + SIEM |
| 2 | 5–8 | 8 | 16 | App + data + cloud + IR baseline |
| 3 | 9–13 | 6 | 22 | Network + TI + PAM + SAST |
| 4 | 14–17 | 6 | 28 | Insider risk + DSPM + GRC |
| 5 | 18–21 | 7 | 35 | TPRM + mobile + backup + brand |
| 6 | 22–24 | 5 | 40 | Specialized + emerging |

---

## 16. Operational Model

### 16.1 RACI Matrix (Summary)

| Activity | CISO | Head of SOC | Tier 1/2 | Tier 3 | Regional Leads | Engineering | Compliance |
|----------|------|-------------|----------|--------|----------------|-------------|-----------|
| Tooling strategy | A | R | C | C | C | C | I |
| Agent operations | I | A | R | R | C | R | I |
| Tier 1 alert triage | I | A | R | I | I | I | I |
| Major incident command | A | R | I | C | C | C | C |
| Regional BU coordination | I | C | I | I | A/R | I | I |
| Compliance evidence | A | C | I | I | C | I | R |
| Board reporting | R | C | I | I | I | I | C |
| Audit response | A | C | I | I | C | C | R |

### 16.2 Cadence

| Activity | Frequency | Audience |
|----------|-----------|----------|
| Tier 1 standup | Daily | Central SOC |
| Regional sync | Weekly | Head of SOC + Regional Leads |
| Threat hunting | Continuous + weekly review | Tier 3 |
| Vulnerability review | Weekly | SOC + Engineering |
| Major incident review | Per incident + monthly summary | All |
| Monthly tech report | Monthly | Engineering, IT, Internal Audit |
| Quarterly business report | Quarterly | Board, Audit Committee |
| Annual security strategy | Annually | Board |
| Audit response | As scheduled | Compliance + relevant teams |
| Tabletop exercises | Quarterly | Cross-functional |
| Red team exercise | Bi-annually | Cross-functional |

### 16.3 Service Level Objectives

| Metric | Target |
|--------|--------|
| Tier 1 alert triage | 15 minutes |
| Tier 2 investigation start | 1 hour |
| Critical incident MTTR | 4 hours |
| High vulnerability patch (production) | 7 days |
| Critical vulnerability patch (production) | 48 hours |
| Posture score recalculation | Real-time (5 min metrics cycle) |
| Regulatory breach notification | Within regulation timeline (e.g., GDPR 72h) |
| Backup recovery (Tier 0 systems) | RPO 1h, RTO 4h |
| Backup recovery (Tier 1 systems) | RPO 4h, RTO 24h |

---

## 17. Cost Model

### 17.1 Annual Cost Estimate (USD)

For 115,000 employees, the platform's annual operating cost is estimated at:

| Category | Low Estimate | High Estimate |
|----------|--------------|---------------|
| **Microsoft entitlements** (already in M365 E5) | $0 (incremental) | $0 (incremental) |
| **CrowdStrike Falcon Enterprise** (115K) | $5.7M | $8.0M |
| **Wiz CNAPP** | $1.5M | $2.5M |
| **Tenable One** | $1.0M | $1.8M |
| **CyberArk Privilege Cloud** | $0.8M | $1.5M |
| **Netskope ONE** | $1.5M | $2.5M |
| **Cloudflare Enterprise** | $0.5M | $1.0M |
| **Salt Security** | $0.4M | $0.8M |
| **Recorded Future** | $0.4M | $0.7M |
| **ZeroFox** | $0.3M | $0.5M |
| **Darktrace** | $0.6M | $1.2M |
| **Snyk + Checkmarx** | $0.5M | $1.0M |
| **Varonis** | $0.5M | $1.0M |
| **OneTrust** | $0.3M | $0.6M |
| **Lookout MTD** | $0.5M | $1.0M |
| **Veeam Enterprise Plus** | $0.3M | $0.6M |
| **ServiceNow GRC** | $0.5M | $1.0M |
| **Axonius** | $0.3M | $0.6M |
| **Other (Proofpoint, Illusive, etc.)** | $0.5M | $1.0M |
| **Azure infrastructure** (compute, storage, networking, Sentinel) | $1.0M | $2.5M |
| **Implementation services (Phase 1–6)** | $3.0M | $6.0M |
| **Internal headcount** (~55 FTEs) | $11M | $16M |
| **Total Year 1** (incl. implementation) | **~$30M** | **~$50M** |
| **Total Steady-State Annual** | **~$22M** | **~$38M** |

This translates to:
- **~$190 – $330 per employee per year** at steady state
- **~1.5% – 2.5% of typical enterprise IT budget** (industry benchmark)
- Aligned with peer enterprises of similar size

### 17.2 Cost Optimization Levers

- M365 E5 entitlement leverage saves ~$3M–$5M (Defender, Purview, Intune, Entra)
- Azure-native services (Sentinel, Defender for Cloud) avoid third-party SIEM/CWPP costs
- Volume pricing negotiated annually for top 5 vendors
- OSS components (MISP for TI staging, OWASP ZAP for free DAST, etc.)
- Dependabot + GitHub Advanced Security (already part of GitHub Enterprise if licensed)

---

## 17.5 Cloud Portability (Level 2 Multi-Cloud)

GlobalSec implements **Level 2 cloud-agnostic architecture**: the same agent code can deploy to Azure, AWS, GCP, or bare Kubernetes by changing one environment variable. The reference deployment is Azure to maximize Microsoft 365 E5 entitlements, but every component is portable.

### What's Abstracted

| Abstraction | Purpose | Azure Impl | AWS Impl | GCP Impl | K8s-Neutral |
|-------------|---------|------------|----------|----------|-------------|
| `SecretProvider` | Secret store | Azure Key Vault | AWS Secrets Manager | GCP Secret Manager | HashiCorp Vault |
| `EventBus` | Pub/sub | Azure Service Bus | SNS + SQS | Pub/Sub | Apache Kafka |
| `ObjectStore` | Blob storage | Azure Blob | S3 | GCS | MinIO |
| `IdentityProvider` | Workload identity | Managed Identity | IRSA | Workload ID | SA Token |

Selected at runtime via `GLOBALSEC_CLOUD_PROVIDER={azure|aws|gcp|kubernetes}`.

### Tooling Portability Strategy

Most security tooling is **already cloud-neutral** (CrowdStrike, Wiz, Tenable, Cloudflare, Darktrace, Recorded Future, Snyk, Checkmarx, OneTrust, Veeam) — same tool regardless of underlying cloud.

Cloud-specific tooling has documented alternatives. For example:
- **Sentinel** (Azure) ↔ **Splunk** (cloud-neutral) ↔ **Chronicle** (GCP) ↔ **Security Lake** (AWS)
- **Defender for O365** (Azure) ↔ **Proofpoint Enterprise** (cloud-neutral)
- **Purview DLP** (Azure) ↔ **Forcepoint DLP** (cloud-neutral)

### Cost Implications

- **Azure (recommended):** ~$17M/year (full M365 E5 leverage)
- **AWS or GCP:** ~$20M/year (additional licensing for Microsoft tool replacements)
- **K8s-neutral:** ~$21M/year (operational overhead of self-managed Vault/Kafka/MinIO)

The ~$3-4M annual premium for non-Azure deployment is the cost of avoiding Microsoft lock-in.

### Why Level 2 (not Level 3)

| Level | Description | GlobalSec Position |
|-------|-------------|--------------------|
| Level 2 | **Same code, configurable cloud, one cloud per deployment** | ✅ |
| Level 3 | Active multi-cloud — workloads run on multiple clouds simultaneously | Out of scope |

Level 3 (active multi-cloud) would require ~40-60% more annual operational cost without proportional benefit unless mandated by regulation. Not pursued.

> Full architecture detail in `docs/architecture/CLOUD-PORTABILITY.md`.

---

## 18. Risk Register & Assumptions

### 18.1 Top Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Vendor lock-in (Microsoft) | Low (mitigated) | High | Level 2 cloud-agnostic architecture — see §17.5 + `docs/architecture/CLOUD-PORTABILITY.md` |
| Tooling integration complexity | High | Medium | Phased rollout; integration test-first approach |
| Talent acquisition (55 security FTEs) | High | High | Long lead-time hiring; MSSP supplementation considered |
| Regional regulatory change | Medium | High | Compliance/GRC agent + legal review quarterly |
| M&A integration disruption | High | Medium | Standardized onboarding playbook |
| Geopolitical events (sanctions) | Medium | High | Regional isolation; sanctions screening agent |
| Insider threat | Medium | High | Purview IRM; PAM session recording; RBAC |
| Cloud cost overrun | Medium | Medium | FinOps reviews monthly; cost alerts |
| Alert fatigue at SOC | High | Medium | True-positive feedback loops; AI-based correlation |
| Tool sprawl | Medium | Medium | Quarterly tool review; rationalization |

### 18.2 Key Assumptions

- **Cloud platform:** Azure is the recommended reference deployment (assumed for cost model). AWS, GCP, and bare Kubernetes are also fully supported via the Level 2 cloud abstraction layer (see `docs/architecture/CLOUD-PORTABILITY.md`)
- Azure landing zones (or AWS Control Tower / GCP Foundations) **already established** with appropriate landing zones
- M365 E5 licensing is **already deployed** to all 115K users
- ExpressRoute connectivity is **already in place** for major offices
- Network connectivity between regions exists (VPN or ExpressRoute Global Reach)
- Executive support exists for Zero Trust strategic direction
- Budget approval for ~$30M Year 1 is committed
- Talent acquisition timeline of 12 months for full hiring is acceptable
- ServiceNow ITSM is already deployed enterprise-wide
- Microsoft Teams is the primary collaboration platform

### 18.3 Out of Scope

- Physical security (datacenter, office)
- Network infrastructure replacement (existing ExpressRoute, etc.)
- Application redesign or refactoring
- Penetration testing services (procured separately)
- Cyber insurance procurement
- Sovereign cloud deployment

---

## Appendix A — Cross-References

| Information | Document |
|-------------|----------|
| Per-agent technical specifications | `GlobalSec-LLD-v1.0.md` |
| Step-by-step installation | `docs/installation/INSTALLATION.md` |
| Compliance matrix detail | `docs/compliance/COMPLIANCE-MATRIX.md` |
| Operations runbooks | `docs/operations/` |
| Phased deployment plan | `docs/deployment-phases/PHASED-DEPLOYMENT.md` |
| Repository overview | `README.md` |

---

*GlobalSec HLD v1.0 · Author: Alvin, Security Architect · CONFIDENTIAL*
