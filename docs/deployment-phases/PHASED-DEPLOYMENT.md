# GlobalSec — Phased Deployment Plan

> **Author:** Alvin, Security Architect
> **Version:** 1.0
> **Total duration:** 24 months
> **Total budget:** ~$30M Year 1, ~$22M–$38M steady-state annual

---

## Overview

GlobalSec deploys across **6 phases over 24 months** to manage risk, demonstrate value, and align with budget cycles. Each phase has clear entry/exit criteria, defined budget, and observable outcomes.

```
Phase 1 (M1-4)   → Foundation: Identity + EDR + SIEM + Email
Phase 2 (M5-8)   → Core Defense: WAF + DLP + Cloud Posture + IR
Phase 3 (M9-13)  → Advanced Detection: NDR + TI + PAM + AppSec
Phase 4 (M14-17) → Data & Insider: IRM + DSPM + GRC
Phase 5 (M18-21) → Specialised: TPRM + Mobile + Backup + Brand
Phase 6 (M22-24) → Optimization: OT + Deception + ESG + Crisis Comms
```

---

## Phase 1 — Foundation (Months 1-4)

**Theme:** Establish identity, central SOC, and core visibility

### Agents Deployed
| # | Agent | Mode | Purpose |
|---|-------|------|---------|
| 1 | Entra ID Agent | Global | Identity baseline |
| 2 | PIM Agent | Global | Privileged access controls |
| 3 | EDR Agent (CrowdStrike) | Regional × 6 | Endpoint protection (priority offices) |
| 4 | Email Security Agent | Regional × 4 | Phishing & BEC defense |
| 5 | SIEM Agent (Sentinel) | Global + Regional WS | Central logging |
| 6 | Risk Dashboard Agent | Global | Posture visibility |
| 7 | Chat Interface Agent | Global | Teams integration |
| 8 | Asset Management Agent | Global | Inventory baseline |

### Milestones
- M1: Azure landing zones provisioned, AKS clusters deployed in 6 regions
- M2: Entra ID Agent live, Conditional Access policies enforced for all 115K users
- M3: CrowdStrike rolled out to first 25K endpoints (priority offices)
- M4: Sentinel ingesting M365 + Azure Activity Logs; Central SOC operational

### Budget — Phase 1
| Item | Estimate (USD) |
|------|---------------|
| CrowdStrike (25K seats Year 1) | $1.5M |
| Microsoft Sentinel ingestion | $400K (Phase 1 portion) |
| CyberArk (preview) | $200K |
| Azure infrastructure (Phase 1) | $400K |
| Implementation services | $1.0M |
| Internal headcount (partial) | $2M |
| **Phase 1 Total** | **~$5.5M** |

### Exit Criteria
- 25K endpoints have CrowdStrike deployed and reporting healthy
- 100% of 115K users enrolled in Entra ID with MFA
- Central SOC has 24/7 Tier 1 coverage
- All M365 + Azure Activity logs flowing into Sentinel
- First Sentinel critical alert successfully triaged end-to-end

---

## Phase 2 — Core Defense (Months 5-8)

**Theme:** Application + data + cloud protection baseline

### Agents Deployed
| # | Agent | Mode | Purpose |
|---|-------|------|---------|
| 9 | WAF + Bot Agent (Cloudflare) | Global | Web protection |
| 10 | API Security Agent (Salt) | Global | API attack surface |
| 11 | DLP Agent (Purview) | Regional × 6 | Data leak prevention |
| 12 | CSPM/CNAPP Agent (Wiz) | Global | Cloud posture |
| 13 | Vulnerability Mgmt Agent (Tenable One) | Global | CVE program |
| 14 | Incident Response Agent (ServiceNow + PagerDuty) | Global | IR automation |
| 15 | SOAR Agent | Global | Playbook automation |
| 16 | Data Residency Agent | Global | Regional compliance |

### Milestones
- M5: Cloudflare protecting all customer-facing properties; Salt Security deployed
- M6: Wiz onboarded across all Azure subscriptions, baseline scan complete
- M7: First SOAR playbook live (credential stuffing → ATO response)
- M8: DLP policies enforcing in production across 6 regions

### Budget — Phase 2
| Item | Estimate (USD) |
|------|---------------|
| Cloudflare Enterprise | $400K (annualized) |
| Wiz CNAPP (Phase 2 portion) | $1.0M |
| Tenable One | $700K |
| Salt Security | $300K |
| EDR rollout continuation (50K more seats) | $2.0M |
| Implementation services | $1.5M |
| Internal headcount | $2M |
| **Phase 2 Total** | **~$8M** |

### Exit Criteria
- 100% of public-facing applications behind Cloudflare WAF
- Wiz scoring 100% of cloud resources daily
- Tenable scanning all internet-facing infrastructure
- 5+ SOAR playbooks active in production
- DLP catching real exfil events (validated in red team exercise)

---

## Phase 3 — Advanced Detection (Months 9-13)

**Theme:** Network detection, threat intel, advanced response

### Agents Deployed
| # | Agent | Mode | Purpose |
|---|-------|------|---------|
| 17 | Network Detection Agent (Darktrace) | Regional × 6 | East-west visibility |
| 18 | Threat Intelligence Agent (Recorded Future) | Global | TI feed |
| 19 | PAM Agent (CyberArk) | Global | Privileged session management |
| 20 | MDM Agent (Intune) | Global | Device compliance |
| 21 | SAST Agent (Checkmarx) | Global | Code security in CI/CD |
| 22 | DAST/SCA Agent (Snyk) | Global | Dependency security |

### Milestones
- M9: Darktrace deployed in 3 regions; tuning underway
- M10: Recorded Future TI feeds correlated with Sentinel
- M11: CyberArk controlling Tier 0 access for all admins
- M12: SAST/DAST gates on all production CI/CD pipelines
- M13: Intune-managed devices = 100K+

### Budget — Phase 3
| Item | Estimate (USD) |
|------|---------------|
| Darktrace | $900K |
| Recorded Future | $550K |
| CyberArk Privilege Cloud | $1.2M |
| Snyk + Checkmarx (combined) | $750K |
| EDR rollout continuation (40K seats) | $1.6M |
| Implementation services | $1.0M |
| Internal headcount | $2M |
| **Phase 3 Total** | **~$8M** |

### Exit Criteria
- Darktrace covering 100% of east-west enterprise traffic
- 100% of Tier 0 access controlled via CyberArk PAM with session recording
- All production code repos have SAST/DAST gates enforced
- 100% of corporate mobile devices managed by Intune

---

## Phase 4 — Data & Insider Risk (Months 14-17)

**Theme:** Advanced data protection, insider threat program

### Agents Deployed
| # | Agent | Mode | Purpose |
|---|-------|------|---------|
| 23 | Insider Risk Agent (Purview IRM) | Global | Insider threat program |
| 24 | DSPM Agent (Varonis) | Regional × 6 | Data-centric risk |
| 25 | CWPP Agent (Defender for Cloud) | Global | Workload protection |
| 26 | Container Security Agent | Global | Kubernetes security |
| 27 | Compliance / GRC Agent (ServiceNow) | Global | Audit automation |
| 28 | EASM Agent (Defender EASM) | Global | External attack surface |

### Milestones
- M14: Insider risk policies live; first IRM case investigated
- M15: Varonis identifying overexposed sensitive data globally
- M16: ServiceNow GRC orchestrating ISO 27001 audit prep
- M17: ISO 27001 certification audit successfully passed

### Budget — Phase 4
| Item | Estimate (USD) |
|------|---------------|
| Varonis | $750K |
| ServiceNow GRC | $750K |
| Defender EASM | $200K |
| Implementation services | $1.5M |
| Internal headcount | $2M |
| **Phase 4 Total** | **~$5.2M** |

### Exit Criteria
- Insider risk program operational with quarterly review cadence
- Varonis baseline shows 100% of sensitive data classified
- ISO 27001:2022 certification achieved
- Defender EASM continuously monitoring external attack surface

---

## Phase 5 — Specialised (Months 18-21)

**Theme:** Advanced and specialized capabilities

### Agents Deployed
| # | Agent | Mode | Purpose |
|---|-------|------|---------|
| 29 | Brand Protection Agent (ZeroFox) | Global | DRPS |
| 30 | Third-Party Risk Agent (OneTrust) | Global | Vendor program |
| 31 | Mobile Threat Defense Agent (Lookout) | Global | Mobile attack surface |
| 32 | DNS Security Agent (full deployment) | Regional × 6 | Complete DNS coverage |
| 33 | SSE Agent (Netskope) | Regional × 3 | Cloud-delivered web security |
| 34 | Backup & Recovery Agent (Veeam + Azure Backup) | Regional × 6 | Resilience |
| 35 | CDN Security Agent | Global | Content delivery security |
| 36 | Teams Security Agent | Global | Collaboration security |

### Milestones
- M18: TPRM program covering top 500 vendors via OneTrust
- M19: Lookout protecting all 115K mobile devices
- M20: Netskope rolled out across all 75 countries
- M21: Veeam + Azure Backup recovery drills passing for Tier 0 systems

### Budget — Phase 5
| Item | Estimate (USD) |
|------|---------------|
| Lookout MTD | $750K |
| ZeroFox | $400K |
| OneTrust + SecurityScorecard | $700K |
| Netskope ONE | $2.0M |
| Veeam Enterprise Plus | $450K |
| Implementation services | $1.5M |
| Internal headcount | $2M |
| **Phase 5 Total** | **~$7.8M** |

### Exit Criteria
- Top 500 vendors continuously scored
- All mobile devices have MTD active
- Tier 0 system recovery drill: RPO ≤ 1h, RTO ≤ 4h achieved

---

## Phase 6 — Optimization (Months 22-24)

**Theme:** Specialized + emerging + handoff to BAU

### Agents Deployed
| # | Agent | Mode | Purpose |
|---|-------|------|---------|
| 37 | OT / IoT Security Agent (Defender for IoT + Claroty) | Regional (where OT exists) | OT visibility |
| 38 | Deception Agent (Illusive) | Global | Honey-token deployment |
| 39 | ESG / Sustainability Agent | Global | Cyber-ESG reporting |
| 40 | Crisis Communications Agent | Global | Reportable breach response |

### Milestones
- M22: OT/IoT visibility for all manufacturing/operational sites
- M23: Deception tokens deployed across enterprise
- M24: Full agent mesh operational; first board-level cyber report; platform handed to BAU operations team

### Budget — Phase 6
| Item | Estimate (USD) |
|------|---------------|
| Defender for IoT + Claroty | $400K |
| Illusive | $300K |
| Final implementation services | $500K |
| Internal headcount | $2M |
| **Phase 6 Total** | **~$3.2M** |

### Exit Criteria
- All 40 agents operational across all 6 regions
- First quarterly board cyber report delivered
- Platform handed to BAU operations team
- Lessons-learned report published

---

## Total Budget Summary

| Phase | Months | Phase Cost (USD) | Cumulative |
|-------|--------|------------------|------------|
| 1 — Foundation | 1-4 | $5.5M | $5.5M |
| 2 — Core Defense | 5-8 | $8.0M | $13.5M |
| 3 — Advanced Detection | 9-13 | $8.0M | $21.5M |
| 4 — Data & Insider | 14-17 | $5.2M | $26.7M |
| 5 — Specialised | 18-21 | $7.8M | $34.5M |
| 6 — Optimization | 22-24 | $3.2M | $37.7M |
| **Year 1 (M1-12) total** | | | **~$28-32M** |
| **Year 2 (M13-24) total** | | | **~$13-18M** |
| **Steady-state Year 3+ annual** | | | **~$22-38M** |

---

## Risk-Adjusted Sequencing Notes

- Phase 1 prioritizes **identity** because it is the new perimeter; without Entra ID + Conditional Access + MFA at scale, all other controls have weaker assumptions
- Phase 2 prioritizes **WAF + DLP** because customer-facing risk and data exfiltration are highest-impact
- Phase 3 introduces **PAM** intentionally late because it requires baseline IAM maturity from Phase 1
- Phase 4 launches **Insider Risk** only after at least 9 months of normal-pattern baseline data
- Phase 6 includes **Deception** last because it requires mature SOC ability to triage high-fidelity, low-volume signals

---

*GlobalSec PHASED-DEPLOYMENT v1.0 · CONFIDENTIAL*
