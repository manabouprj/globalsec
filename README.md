# 🌐 GlobalSec — Enterprise AI-Powered Security Agent Platform

> **Author:** Alvin, Security Architect
> **Platform:** Global Multinational Security Operations
> **Orchestration:** Paperclip (multi-region)
> **Cloud:** Microsoft Azure (centralized subscription)
> **Version:** 1.0.0
> **Agents:** ~40 across 17 security domains

---

## Platform Overview

GlobalSec is an enterprise-scale, AI-agent-driven security platform designed for a multinational organisation with:

- **115,000+ employees** across **75 countries**
- **6 geographic regions:** APAC · Africa · Americas · Europe · GCC · Middle East
- **Centralized SOC** based in the Middle East with **Regional Security Leads** in each region
- **Centralized Azure subscription** as the cloud foundation
- **Best-of-breed tooling** selected from Gartner Magic Quadrant Leaders per domain

The platform comprises **~40 specialised AI agents** organised across **17 security domains**, orchestrated by **Paperclip** (multi-region deployment), surfaced through a **Single Pane of Glass (SPOG) dashboard**, and operated via conversational interfaces on **Microsoft Teams** (primary) and **Slack** (secondary).

---

## Architecture Highlights

```
                    ┌──────────────────────────────────────────┐
                    │     GLOBAL CONTROL PLANE                 │
                    │     (Middle East — Qatar Central)        │
                    │                                          │
                    │  Paperclip Master · Global SPOG          │
                    │  Sentinel Global · Defender XDR          │
                    │  Entra ID · Compliance Manager           │
                    └──────────────────┬───────────────────────┘
                                       │
       ┌────────┬──────────┬───────────┼──────────┬──────────┐
       │        │          │           │          │          │
   ┌───▼──┐ ┌──▼──┐  ┌────▼───┐  ┌────▼───┐  ┌──▼──┐   ┌───▼──┐
   │ APAC │ │EMEA │  │  AMER  │  │  GCC   │  │ ME  │   │AFRICA│
   │(SG)  │ │(NL) │  │ (US-VA)│  │ (UAE)  │  │(QA) │   │ (ZA) │
   └──────┘ └─────┘  └────────┘  └────────┘  └─────┘   └──────┘
```

### Foundational Principles

1. **Azure-native first** — built on a single Azure Commercial subscription using Microsoft Cloud Adoption Framework landing zones
2. **Best-of-breed integration** — Gartner MQ Leaders per domain integrated via Azure-native connectors
3. **Centralized SOC with regional reach** — Central SOC owns global tooling; Regional Security Leads coordinate with BUs
4. **Regional autonomy with global oversight** — agents process data within regional boundaries; only metadata flows to global plane
5. **Zero Trust by default** — Entra ID + Conditional Access + PIM at every boundary
6. **Compliance multiplexing** — every event tagged with applicable frameworks (GDPR, UAE PDPL, HIPAA, etc.)

---

## SOC Operating Model

GlobalSec uses a **hub-and-spoke SOC**:

```
                         CENTRAL SOC (Middle East)
                         24/7 via shifts (3 × 8h)
                         · Tier 1 / 2 / 3 / Threat Hunters
                         · Tooling ownership
                         · Major incident command
                                  │
        ┌─────────┬──────────────┼─────────────┬────────────┐
        │         │              │             │            │
   ┌────▼────┐ ┌──▼───┐    ┌────▼────┐    ┌───▼───┐   ┌────▼────┐
   │  APAC   │ │ EMEA │    │  AMER   │    │  GCC  │   │ AFRICA  │
   │  Lead   │ │ Lead │    │  Lead   │    │ Lead  │   │  Lead   │
   │         │ │      │    │         │    │       │   │         │
   │ BU      │ │ BU   │    │ BU      │    │ BU    │   │ BU      │
   │ liaison │ │liaison│   │ liaison │    │liaison│   │ liaison │
   └─────────┘ └──────┘    └─────────┘    └───────┘   └─────────┘
```

---

## Agent Catalogue (40 Agents · 17 Domains)

| Domain | Agents |
|--------|--------|
| **Endpoint** | EDR (CrowdStrike Falcon), MDM (Intune) |
| **Identity** | Entra ID, PIM, PAM (CyberArk) |
| **Communication** | Email Security (Defender + Proofpoint), Teams Security |
| **Network** | DNS Security, SSE (Netskope), Network Detection (Darktrace), CDN Security |
| **Application** | WAF + Bot (Cloudflare), API Security (Salt), SAST (Checkmarx), DAST/SCA (Snyk), Mobile Threat Defense (Lookout) |
| **Data** | DLP (Purview), Insider Risk (Purview IRM), DSPM (Varonis), Data Residency |
| **Detection** | SIEM (Sentinel), SOAR, Incident Response (ServiceNow + PagerDuty) |
| **Cloud** | CSPM/CNAPP (Wiz), CWPP (Defender for Cloud), Container Security |
| **Threat Intel** | Threat Intelligence (Recorded Future), Brand Protection (ZeroFox), Deception (Illusive) |
| **Governance** | Asset Mgmt (Axonius), Vuln Mgmt (Tenable One), Compliance/GRC (ServiceNow), Risk Dashboard, EASM |
| **Resilience** | Backup & Recovery (Veeam + Azure Backup), Crisis Communications |
| **Specialized** | Third-Party Risk (OneTrust), OT/IoT Security, ESG/Sustainability |
| **Integration** | Chat Interface (Teams + Slack) |

> Full per-agent setup procedures (API tokens, IAM scopes, Azure Key Vault commands, scaling guidance) in [`docs/lld/GlobalSec-LLD-v1.0.md`](docs/lld/GlobalSec-LLD-v1.0.md).

---

## Tooling Selection (Gartner MQ Leaders)

Every tool was selected based on **Gartner Magic Quadrant Leader status**, **native Azure integration**, **enterprise scale capability**, and **regional support**:

| Domain | Tool | Why |
|--------|------|-----|
| EDR | **CrowdStrike Falcon Enterprise** | MQ Leader (EPP); user-specified |
| XDR | **Microsoft Defender XDR** | MQ Leader (XDR); native consolidation |
| SIEM | **Microsoft Sentinel** | MQ Leader (SIEM); cloud-native |
| IAM | **Microsoft Entra ID** | MQ Leader (Access Mgmt); M365 E5 entitlement |
| PAM | **CyberArk Privilege Cloud** | MQ Leader (PAM); industry standard |
| Email | **Microsoft Defender for O365 + Proofpoint TAP** | Both MQ Leaders |
| DLP | **Microsoft Purview DLP** | MQ Leader (Enterprise DLP) |
| CASB/SSE | **Netskope ONE** | MQ Leader (SSE) |
| WAF | **Cloudflare Enterprise** | MQ Leader (WAAP) |
| API Security | **Salt Security** | API security leader |
| CSPM/CNAPP | **Wiz** | MQ Leader (CNAPP) |
| Vuln Mgmt | **Tenable One** | MQ Leader (Vulnerability Assessment) |
| SAST | **Checkmarx One** | MQ Leader (SAST) |
| DAST/SCA | **Snyk** | MQ Leader (Application Security Testing) |
| NDR | **Darktrace** | MQ Leader (NDR) |
| Threat Intel | **Recorded Future** | MQ Leader (Security Threat Intel) |
| Brand Protection | **ZeroFox** | MQ Leader (Digital Risk Protection) |
| DSPM | **Varonis** | MQ Leader (DSPM) |
| Backup | **Veeam + Azure Backup** | Veeam MQ Leader |
| GRC | **ServiceNow GRC** | MQ Leader (IRM) |
| TPRM | **OneTrust + SecurityScorecard** | Both MQ Leaders |
| Mobile | **Lookout (MTD) + Microsoft Intune (MDM)** | MQ Leaders |
| Asset Mgmt | **Axonius** | Cyber asset attack surface mgmt leader |

---

## Repository Structure

```
globalsec/
├── agents/                          # 40 agents organized by domain
│   ├── base_agent.py                # Multi-region base class
│   ├── entra-id-agent/
│   ├── pim-agent/
│   ├── pam-agent/
│   ├── edr-agent/                   # CrowdStrike Falcon (regional)
│   ├── mdm-agent/                   # Intune (global)
│   ├── email-security-agent/        # Defender O365 + Proofpoint
│   ├── teams-security-agent/
│   ├── dns-security-agent/
│   ├── sse-agent/                   # Netskope
│   ├── network-detection-agent/     # Darktrace + Defender for Identity
│   ├── cdn-security-agent/
│   ├── waf-bot-agent/
│   ├── api-security-agent/          # Salt Security
│   ├── sast-agent/                  # Checkmarx
│   ├── snyk-agent/                  # DAST/SCA
│   ├── mtd-agent/                   # Lookout
│   ├── dlp-agent/                   # Purview DLP
│   ├── insider-risk-agent/          # Purview IRM
│   ├── dspm-agent/                  # Varonis
│   ├── data-residency-agent/
│   ├── siem-agent/                  # Sentinel (multi-workspace)
│   ├── soar-agent/                  # Sentinel SOAR + Logic Apps
│   ├── incident-response-agent/     # ServiceNow + PagerDuty
│   ├── cspm-agent/                  # Wiz
│   ├── cwpp-agent/                  # Defender for Cloud
│   ├── container-security-agent/
│   ├── threat-intel-agent/          # Recorded Future
│   ├── brand-protection-agent/      # ZeroFox
│   ├── deception-agent/             # Illusive
│   ├── asset-management-agent/      # Axonius
│   ├── vulnerability-agent/         # Tenable One
│   ├── compliance-grc-agent/        # ServiceNow GRC
│   ├── risk-dashboard-agent/
│   ├── easm-agent/                  # Defender EASM
│   ├── backup-recovery-agent/       # Veeam + Azure Backup
│   ├── crisis-comms-agent/
│   ├── third-party-risk-agent/      # OneTrust + SecurityScorecard
│   ├── ot-iot-agent/                # Defender for IoT
│   ├── esg-agent/
│   └── chat-interface/              # Teams + Slack
├── orchestration/
│   └── paperclip-config/
│       ├── agent-registry-global.yaml
│       └── agent-registry-{region}.yaml  # per-region
├── dashboard/
│   ├── single-pane-of-glass/        # React SPOG (3 personas)
│   └── reporting-engine/            # Monthly + Quarterly + Board
├── infrastructure/
│   ├── azure-landing-zones/         # CAF-aligned bicep templates
│   ├── bicep/                       # Resource definitions
│   ├── terraform/                   # Alternative IaC
│   └── kubernetes/                  # AKS manifests + Helm charts
├── docs/
│   ├── hld/GlobalSec-HLD-v1.0.md   # Comprehensive HLD
│   ├── lld/GlobalSec-LLD-v1.0.md   # All 40 agents + setup
│   ├── architecture/                # Diagrams + topology
│   ├── installation/INSTALLATION.md
│   ├── deployment-phases/PHASED-DEPLOYMENT.md
│   ├── compliance/COMPLIANCE-MATRIX.md
│   ├── operations/                  # Runbooks
│   └── runbooks/
├── reports/
├── scripts/                         # Utility scripts
├── .github/workflows/               # CI/CD
├── .env.example
├── .gitignore
└── README.md
```

---

## Phased Deployment

The platform deploys across **6 phases over 24 months**:

| Phase | Months | Agents Added | Cumulative | Capability Outcome |
|-------|--------|--------------|------------|--------------------|
| **Phase 1 — Foundation** | 1–4 | 8 | 8 | Identity + endpoint + email + SIEM |
| **Phase 2 — Core Defense** | 5–8 | 8 | 16 | App + data + cloud + IR baseline |
| **Phase 3 — Advanced Detection** | 9–13 | 6 | 22 | Network + TI + PAM + SAST |
| **Phase 4 — Data & Insider** | 14–17 | 6 | 28 | Insider risk + DSPM + GRC |
| **Phase 5 — Specialised** | 18–21 | 7 | 35 | TPRM + mobile + backup + brand |
| **Phase 6 — Optimization** | 22–24 | 5 | 40 | Specialized + emerging |

> Full plan with budget gates and milestones in [`docs/deployment-phases/PHASED-DEPLOYMENT.md`](docs/deployment-phases/PHASED-DEPLOYMENT.md).

---

## Compliance Coverage

The platform demonstrates compliance across **20+ regulations** simultaneously:

| Region | Key Regulations |
|--------|-----------------|
| **Global** | ISO 27001:2022, NIST CSF 2.0, SOC 2 Type II, PCI DSS v4.0, MITRE ATT&CK v14, OWASP Top 10 |
| **Europe** | GDPR, NIS2 Directive, DORA |
| **US** | HIPAA, SOX, CCPA/CPRA, NYDFS Cyber, FedRAMP (if applicable) |
| **APAC** | India DPDP, Singapore PDPA, Australia Privacy Act, Japan APPI, Korea PIPA |
| **GCC** | UAE PDPL, DIFC DPL, ADGM DPR, Saudi PDPL, Qatar DPPL |
| **Africa** | South Africa POPIA, Nigeria NDPA, Kenya DPA |
| **LATAM** | Brazil LGPD, Mexico LFPDPPP |

---

## Cost Model (Annual, Steady-State)

| Category | Range (USD) |
|----------|-------------|
| Software/SaaS licensing (CrowdStrike, Wiz, Tenable, etc.) | $14M–$24M |
| Microsoft entitlements (M365 E5 already deployed — no incremental cost) | $0 |
| Azure infrastructure (compute, storage, Sentinel, networking) | $1M–$2.5M |
| Internal headcount (~55 FTEs) | $11M–$16M |
| **Steady-state total** | **~$22M–$38M** |
| Year 1 (incl. implementation) | **~$30M–$50M** |

Per-employee cost: ~$190–$330/year — aligned with peer enterprises of similar size.

---

## SOC Performance Targets (SLOs)

| Metric | Target |
|--------|--------|
| Tier 1 alert triage | 15 minutes |
| Tier 2 investigation start | 1 hour |
| Critical incident MTTR | 4 hours |
| High vulnerability patch (production) | 7 days |
| Critical vulnerability patch (production) | 48 hours |
| Backup recovery (Tier 0 systems) | RPO 1h / RTO 4h |
| Regulatory breach notification | Within regulation timeline (e.g., GDPR 72h) |

---

## Documentation Map

| Document | Audience | Purpose |
|----------|----------|---------|
| [`docs/hld/GlobalSec-HLD-v1.0.md`](docs/hld/GlobalSec-HLD-v1.0.md) | CISO, CTO, Architects | Why & what — strategic architecture |
| [`docs/lld/GlobalSec-LLD-v1.0.md`](docs/lld/GlobalSec-LLD-v1.0.md) | Engineers, SOC | How — per-agent setup & operations |
| [`docs/installation/INSTALLATION.md`](docs/installation/INSTALLATION.md) | Engineers | Step-by-step deployment |
| [`docs/deployment-phases/PHASED-DEPLOYMENT.md`](docs/deployment-phases/PHASED-DEPLOYMENT.md) | Program leads | 24-month rollout plan |
| [`docs/compliance/COMPLIANCE-MATRIX.md`](docs/compliance/COMPLIANCE-MATRIX.md) | GRC, Audit | Framework-to-control mapping |
| [`docs/operations/`](docs/operations/) | SOC | Runbooks for daily ops |

---

## Security Notice

⚠️ **NEVER commit credentials, API keys, secrets, or tokens to this repository.**

All credentials must be stored in **Azure Key Vault** and accessed via **Managed Identities**. The CI/CD pipeline includes secret scanning on every commit.

---

## Comparison with EcomSec

GlobalSec inherits the proven design patterns from **EcomSec** (single-region e-commerce platform), scaled and adapted for global enterprise:

| Aspect | EcomSec | GlobalSec |
|--------|---------|-----------|
| Topology | Single region | Multi-region (6 hubs + global control plane) |
| Cloud | Cloud-agnostic | Azure-native |
| Workforce | Medium (50–500) | Enterprise (115K+) |
| Agents | 26 | ~40 |
| SOC | Single team | Hub-and-spoke (Central + Regional Leads) |
| Compliance | UAE/PCI focus | 20+ frameworks across 75 countries |
| Identity | Okta/CyberArk | Entra ID + CyberArk |
| SIEM | Splunk or Sentinel | Microsoft Sentinel (multi-workspace) |
| Chat | Slack primary | Teams primary, Slack secondary |
| Phases | 4 (12-14 months) | 6 (24 months) |
| Annual cost | AED 860K–1.3M | $22M–$38M (steady-state) |

---

*GlobalSec v1.0.0 · Author: Alvin, Security Architect · CONFIDENTIAL — INTERNAL USE ONLY*
