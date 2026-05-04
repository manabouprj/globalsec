# GlobalSec — Cloud Portability Architecture

> **Author:** Alvin, Security Architect
> **Version:** 1.1 (Level 2 — Multi-Cloud Capable)
> **Classification:** CONFIDENTIAL

---

## Executive Summary

GlobalSec v1.1 introduces a **Level 2 cloud-agnostic architecture**: the same agent code can deploy to Azure, AWS, GCP, or bare Kubernetes by setting a single environment variable. The reference deployment remains Azure to maximize Microsoft 365 E5 entitlements, but the platform is now portable.

This is **Level 2** in the cloud-agnosticism scale — not Level 3 (active multi-cloud) or Level 4 (zero cloud-specific tooling). Each individual deployment runs on one cloud at a time, but the deployment can be on any cloud.

---

## What "Level 2" Means

| Level | Description | GlobalSec Position |
|-------|-------------|--------------------|
| Level 1 | Could move clouds with effort | We exceed this |
| **Level 2** | **Same code, configurable cloud, one cloud per deployment** | ✅ **Current state** |
| Level 3 | Active multi-cloud — workloads on multiple clouds simultaneously | Not pursued |
| Level 4 | Zero cloud-specific tooling — pure Kubernetes only | Not pursued |

**What this gives you:**
- Strategic flexibility (M&A on AWS, regulatory mandate, vendor pricing leverage)
- Same skills transferable across clouds for engineers
- No vendor-specific code in agent business logic
- Reference Azure deployment retains 100% of M365 E5 value

**What this doesn't give you:**
- Disaster recovery between clouds
- Cost arbitrage between clouds
- Compliance with mandates requiring active multi-cloud
- Cloud-specific service features (some Microsoft Sentinel features have no AWS/GCP equivalent)

---

## The Four Cloud Concerns

Every cloud-coupled need in the platform is mapped to one of four abstractions:

| Abstraction | Purpose | Azure | AWS | GCP | Kubernetes-Native |
|-------------|---------|-------|-----|-----|-------------------|
| **SecretProvider** | Read API tokens, credentials | Azure Key Vault | AWS Secrets Manager | GCP Secret Manager | HashiCorp Vault |
| **EventBus** | Async pub/sub between agents | Azure Service Bus | SNS + SQS | Pub/Sub | Apache Kafka |
| **ObjectStore** | Reports, audit evidence, snapshots | Azure Blob Storage | S3 | GCS | MinIO |
| **IdentityProvider** | Workload identity for cloud APIs | Managed Identity | IRSA | Workload Identity | ServiceAccount Token |

These four abstractions live in `agents/cloud/__init__.py`. Implementations live in `agents/cloud/{azure_impl,aws_impl,gcp_impl,k8s_impl}.py`.

The selection is made at runtime via:

```bash
GLOBALSEC_CLOUD_PROVIDER=azure        # default
GLOBALSEC_CLOUD_PROVIDER=aws
GLOBALSEC_CLOUD_PROVIDER=gcp
GLOBALSEC_CLOUD_PROVIDER=kubernetes   # cloud-neutral via Vault + Kafka + MinIO
```

---

## Tooling Portability Matrix

Some security tooling is itself cloud-specific. For each domain, the platform supports a **primary tool** and one or more **alternatives**. Every agent has an interchangeable tool selection.

### Identity

| Provider Choice | Primary Tool | Equivalent Capability |
|-----------------|--------------|----------------------|
| Azure-aligned | Microsoft Entra ID + PIM | (cloud-neutral choice) |
| AWS-aligned | Okta + AWS IAM Identity Center | Same Conditional Access patterns |
| GCP-aligned | Okta + Cloud Identity | Same patterns |
| Cloud-neutral | Okta + Saviynt | Identity governance separate from cloud |

**Note:** Microsoft Entra ID can be the IDP regardless of cloud — it is licensed separately from Azure infrastructure. Many AWS- and GCP-deployed enterprises still use Entra ID.

### EDR

| Provider Choice | Primary Tool | Equivalent |
|-----------------|--------------|-----------|
| All providers | **CrowdStrike Falcon Enterprise** (cloud-neutral) | (no swap needed) |

CrowdStrike runs identically regardless of cloud. No abstraction needed.

### SIEM

| Provider Choice | Primary Tool | Alternative |
|-----------------|--------------|-------------|
| Azure-aligned | Microsoft Sentinel | Splunk, Elastic |
| AWS-aligned | Amazon Security Lake + OpenSearch | Splunk, Sentinel cross-cloud |
| GCP-aligned | Google Chronicle | Splunk, Sentinel cross-cloud |
| Cloud-neutral | Splunk Enterprise OR Elastic SIEM | (those are the cloud-neutral options) |

The SIEM Agent always exposes the same interface upward. Below the agent, it talks to whichever SIEM is configured.

### SOAR

| Provider Choice | Primary Tool |
|-----------------|--------------|
| Azure-aligned | Sentinel SOAR + Logic Apps |
| AWS-aligned | AWS Step Functions + Lambda |
| GCP-aligned | Cloud Workflows |
| Cloud-neutral | Tines OR Torq (vendor-neutral SOAR platforms) |

### Email Security

| Provider Choice | Primary Tool |
|-----------------|--------------|
| Azure-aligned | Microsoft Defender for O365 + Proofpoint TAP |
| AWS-aligned | Proofpoint TAP only (no AWS-native equivalent) |
| GCP-aligned | Google Workspace built-in + Proofpoint |
| Cloud-neutral | Proofpoint Enterprise + Mimecast |

### DLP / Insider Risk / DSPM

| Provider Choice | Primary Tools |
|-----------------|---------------|
| Azure-aligned | Microsoft Purview suite |
| AWS-aligned | Forcepoint DLP + AWS Macie |
| GCP-aligned | Google Cloud DLP + Forcepoint |
| Cloud-neutral | Forcepoint + Code42 + Varonis |

### CSPM / CNAPP

| Provider Choice | Primary Tool |
|-----------------|--------------|
| All providers | **Wiz** (cloud-neutral, scans all major clouds) |

Wiz is multi-cloud by design — same tool regardless of which clouds you run on.

### CWPP

| Provider Choice | Primary Tool |
|-----------------|--------------|
| Azure-aligned | Microsoft Defender for Cloud |
| AWS-aligned | AWS GuardDuty + Inspector |
| GCP-aligned | Security Command Center |
| Cloud-neutral | Sysdig Secure OR Aqua Security |

### MDM

| Provider Choice | Primary Tool |
|-----------------|--------------|
| Azure-aligned | Microsoft Intune |
| Cloud-neutral | VMware Workspace ONE OR Jamf (for Apple) |

### Vulnerability Management

| Provider Choice | Primary Tool |
|-----------------|--------------|
| All providers | **Tenable One** (cloud-neutral) |

### Compliance / GRC

| Provider Choice | Primary Tool |
|-----------------|--------------|
| Azure-aligned | ServiceNow GRC + Microsoft Compliance Manager |
| Cloud-neutral | ServiceNow GRC + OneTrust + manual evidence |

### All Other Tools

The following are vendor-agnostic and run identically on any cloud:

- **Network Detection:** Darktrace
- **API Security:** Salt Security
- **WAF + Bot:** Cloudflare Enterprise
- **CDN Security:** Cloudflare
- **Threat Intel:** Recorded Future
- **Brand Protection:** ZeroFox
- **DSPM:** Varonis
- **Asset Mgmt:** Axonius
- **Backup:** Veeam
- **TPRM:** OneTrust + SecurityScorecard
- **Mobile MTD:** Lookout
- **OT/IoT:** Claroty
- **PAM:** CyberArk Privilege Cloud
- **SAST/DAST:** Checkmarx + Snyk

---

## Reference Deployments

### Reference A — Azure (recommended default)

```bash
GLOBALSEC_CLOUD_PROVIDER=azure
```

**Used because:** Existing M365 E5 entitlement saves $3M-$5M/year in identity, email security, DLP, MDM, and EDR XDR layers.

**Tools selected:**
- Sentinel for SIEM
- Defender XDR for endpoint XDR consolidation
- Entra ID for identity
- Purview for DLP/IRM/DSPM
- Intune for MDM
- Defender for Cloud for CWPP
- Azure Service Bus + Key Vault + Blob

**Other tools** (CrowdStrike, Wiz, Tenable, Darktrace, etc.) remain identical.

### Reference B — AWS Deployment

```bash
GLOBALSEC_CLOUD_PROVIDER=aws
```

**Used when:** Acquired company runs on AWS, regulatory mandate requires AWS, or strategic shift.

**Tools selected:**
- Splunk Enterprise for SIEM (replaces Sentinel)
- Okta for identity (replaces Entra ID)
- Forcepoint DLP for DLP (replaces Purview DLP)
- Sysdig for CWPP (replaces Defender for Cloud)
- Workspace ONE for MDM (replaces Intune)
- Tines for SOAR (replaces Sentinel SOAR)
- Proofpoint for email (Defender for O365 not available)
- AWS SNS + SQS + Secrets Manager + S3

**Cost impact:** ~$3M-$5M/year additional licensing to replace M365 E5 security capabilities.

### Reference C — GCP Deployment

```bash
GLOBALSEC_CLOUD_PROVIDER=gcp
```

**Used when:** Acquired company runs on GCP, regulatory or sovereignty preference.

**Tools selected:**
- Google Chronicle for SIEM
- Same alternatives as AWS reference for non-Azure-native tools
- GCP Pub/Sub + Secret Manager + GCS

### Reference D — Bare Kubernetes (Cloud-Neutral)

```bash
GLOBALSEC_CLOUD_PROVIDER=kubernetes
```

**Used when:** On-premises Kubernetes, OpenShift, sovereign cloud not aligned with hyperscaler, or maximum flexibility required.

**Tools selected:**
- HashiCorp Vault for secrets
- Apache Kafka for events
- MinIO for object storage
- ServiceAccount tokens for identity
- All other security tooling unchanged (CrowdStrike, Splunk, Okta, etc.)

**Cost impact:** Highest TCO option — operational overhead of running Vault, Kafka, MinIO is significant.

---

## The Microsoft 365 E5 Entitlement Question

The biggest **financial implication** of going cloud-agnostic is whether you keep M365 E5 entitlements.

**Important fact:** M365 E5 is licensed separately from Azure. You can run on AWS or GCP and still use:
- Microsoft Entra ID for identity
- Microsoft Defender for Office 365 for email
- Microsoft Purview for DLP/IRM
- Microsoft Defender for Endpoint for EDR (alternative to CrowdStrike)
- Microsoft Intune for MDM
- Microsoft Defender XDR aggregator

**What requires Azure:**
- Microsoft Sentinel (Azure-only, but its data sources can be cross-cloud)
- Microsoft Defender for Cloud for CWPP
- Azure-specific PaaS (Service Bus, Key Vault, Blob, AKS)

**Recommended approach for Level 2:**

If your enterprise has M365 E5, **keep using the Microsoft security suite even when running on AWS or GCP**. This is technically possible and saves significant cost. Sentinel can ingest AWS CloudTrail and GCP audit logs as native data sources.

The cloud abstraction layer in GlobalSec is for **infrastructure-level cloud services** (secrets, events, storage). The **security tooling** is mostly cloud-neutral and can stay Microsoft-aligned regardless of underlying cloud.

---

## Cost Comparison

| Component | Azure-only | AWS-only | GCP-only | K8s-neutral |
|-----------|-----------|----------|----------|-------------|
| Infrastructure (compute, networking, storage) | $1.5M | $1.7M | $1.6M | $2.0M (on-prem ops) |
| SIEM (Sentinel vs Splunk vs Chronicle) | $1.5M | $2.5M | $2.0M | $2.5M |
| Identity (Entra vs Okta) | $0.8M (E5) | $1.5M (Okta) | $1.5M (Okta) | $1.5M |
| EDR (CrowdStrike) | $7M | $7M | $7M | $7M |
| Other tools (CNAPP, NDR, TI, etc.) | $5M | $5M | $5M | $5M |
| MDM (Intune vs Workspace ONE) | $0.8M (E5) | $1.5M | $1.5M | $1.5M |
| Email Sec (Defender for O365 + Proofpoint) | $0.5M | $1.5M (Proofpoint only) | $1.5M | $1.5M |
| **Approximate annual** | **$17M** | **$20.7M** | **$20.1M** | **$21M** |

**Conclusion:** Azure deployment is ~$3M-$4M/year cheaper than AWS/GCP/K8s-neutral when M365 E5 is leveraged. This is the financial case for keeping Azure as the reference deployment even with full multi-cloud capability.

---

## Migration Patterns

If a future migration becomes necessary, here is the sequence:

### Pattern 1 — Azure → AWS

1. Provision AWS landing zones (parallel to Azure)
2. Deploy `GLOBALSEC_CLOUD_PROVIDER=aws` agents to EKS clusters in AWS
3. Migrate SIEM data via Splunk Universal Forwarder cross-cloud
4. Migrate identity to Okta (or keep Entra ID and just swap infrastructure)
5. Cutover region by region (APAC first, smallest footprint)
6. Decommission Azure region after 90-day parallel run

### Pattern 2 — Azure → Hybrid (Azure-primary + AWS for one region)

1. Deploy `GLOBALSEC_CLOUD_PROVIDER=aws` to that region only
2. Federate event bus via cross-cloud Service Bus → SNS bridge
3. Federate SIEM data via Splunk Federated Search OR Sentinel multi-workspace
4. Maintain unified Entra ID across both

This gives you Level 2.5 — same code, multiple clouds in production.

---

## What's NOT Covered by Level 2

| Concern | Status |
|---------|--------|
| Multi-cloud disaster recovery | Out of scope — would require Level 3 |
| Active workload load balancing across clouds | Out of scope |
| Cost arbitrage / spot pricing across clouds | Out of scope |
| Cloud-specific feature parity (e.g. Sentinel UEBA on AWS) | Accept feature gap when switching clouds |
| Zero downtime cloud migration | Out of scope — plan for parallel run periods |

---

## Cross-References

| Information | Document |
|-------------|----------|
| Comprehensive HLD | `docs/hld/GlobalSec-HLD-v1.0.md` |
| Per-agent setup with cloud-specific notes | `docs/lld/GlobalSec-LLD-v1.0.md` |
| Cloud abstraction code | `agents/cloud/` |
| Base agent class (cloud-agnostic) | `agents/base_agent.py` |

---

*GlobalSec CLOUD-PORTABILITY v1.1 · CONFIDENTIAL*
