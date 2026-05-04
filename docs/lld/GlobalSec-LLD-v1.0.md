# GlobalSec — Low Level Design (LLD)

> **Author:** Alvin, Security Architect
> **Version:** 1.0
> **Classification:** CONFIDENTIAL
> **Companion document:** `GlobalSec-HLD-v1.0.md`

---

## Purpose

This LLD provides per-agent implementation specifications for all ~40 agents in the GlobalSec platform. For each agent it documents:

1. Tool integrations with documentation links
2. Authentication mechanism
3. Account / API setup steps (vendor-side)
4. Required secrets (environment variable names)
5. IAM / permission scopes
6. Polling and event behaviour
7. Events published / subscribed
8. Key metrics
9. Scaling and retry strategy
10. Chat commands

---

## Table of Contents

- [Section 1 — Base Agent Class & Multi-Region Pattern](#section-1--base-agent-class--multi-region-pattern)
- [Section 2 — Identity Domain](#section-2--identity-domain)
  - [2.1 Entra ID Agent](#21-entra-id-agent)
  - [2.2 Privileged Identity Management (PIM) Agent](#22-pim-agent)
  - [2.3 PAM Agent (CyberArk)](#23-pam-agent-cyberark)
- [Section 3 — Endpoint Domain](#section-3--endpoint-domain)
  - [3.1 EDR Agent (CrowdStrike Falcon Enterprise)](#31-edr-agent-crowdstrike-falcon-enterprise)
  - [3.2 MDM Agent (Microsoft Intune)](#32-mdm-agent-microsoft-intune)
- [Section 4 — Communication Domain](#section-4--communication-domain)
  - [4.1 Email Security Agent](#41-email-security-agent)
  - [4.2 Teams Security Agent](#42-teams-security-agent)
- [Section 5 — Network Domain](#section-5--network-domain)
  - [5.1 DNS Security Agent](#51-dns-security-agent)
  - [5.2 SSE / Web Proxy Agent (Netskope)](#52-sse--web-proxy-agent-netskope)
  - [5.3 Network Detection Agent (Darktrace + Defender for Identity)](#53-network-detection-agent)
  - [5.4 CDN Security Agent (Cloudflare)](#54-cdn-security-agent)
- [Section 6 — Application Domain](#section-6--application-domain)
  - [6.1 WAF + Bot Agent (Cloudflare Enterprise + Azure Front Door)](#61-waf--bot-agent)
  - [6.2 API Security Agent (Salt Security)](#62-api-security-agent-salt-security)
  - [6.3 SAST Agent (Checkmarx One)](#63-sast-agent-checkmarx-one)
  - [6.4 DAST/SCA Agent (Snyk)](#64-dastsca-agent-snyk)
  - [6.5 Mobile Threat Defense Agent (Lookout)](#65-mobile-threat-defense-agent-lookout)
- [Section 7 — Data Domain](#section-7--data-domain)
  - [7.1 DLP Agent (Microsoft Purview DLP)](#71-dlp-agent-microsoft-purview-dlp)
  - [7.2 Insider Risk Agent (Purview IRM)](#72-insider-risk-agent-purview-irm)
  - [7.3 DSPM Agent (Varonis)](#73-dspm-agent-varonis)
  - [7.4 Data Residency Agent](#74-data-residency-agent)
- [Section 8 — Detection & Response Domain](#section-8--detection--response-domain)
  - [8.1 SIEM Agent (Microsoft Sentinel)](#81-siem-agent-microsoft-sentinel)
  - [8.2 SOAR Agent](#82-soar-agent)
  - [8.3 Incident Response Agent (ServiceNow SecOps + PagerDuty)](#83-incident-response-agent)
- [Section 9 — Cloud Domain](#section-9--cloud-domain)
  - [9.1 CSPM/CNAPP Agent (Wiz)](#91-cspmcnapp-agent-wiz)
  - [9.2 CWPP Agent (Defender for Cloud)](#92-cwpp-agent-defender-for-cloud)
  - [9.3 Container Security Agent](#93-container-security-agent)
- [Section 10 — Threat Intelligence Domain](#section-10--threat-intelligence-domain)
  - [10.1 Threat Intelligence Agent (Recorded Future)](#101-threat-intelligence-agent-recorded-future)
  - [10.2 Brand Protection Agent (ZeroFox)](#102-brand-protection-agent-zerofox)
  - [10.3 Deception Agent (Illusive)](#103-deception-agent-illusive)
- [Section 11 — Governance Domain](#section-11--governance-domain)
  - [11.1 Asset Management Agent (Axonius)](#111-asset-management-agent-axonius)
  - [11.2 Vulnerability Management Agent (Tenable One)](#112-vulnerability-management-agent-tenable-one)
  - [11.3 Compliance / GRC Agent (ServiceNow GRC)](#113-compliance--grc-agent-servicenow-grc)
  - [11.4 Risk Dashboard Agent](#114-risk-dashboard-agent)
  - [11.5 EASM Agent (Defender EASM)](#115-easm-agent-defender-easm)
- [Section 12 — Resilience Domain](#section-12--resilience-domain)
  - [12.1 Backup & Recovery Agent (Veeam + Azure Backup)](#121-backup--recovery-agent-veeam--azure-backup)
  - [12.2 Crisis Communications Agent](#122-crisis-communications-agent)
- [Section 13 — Specialized Domain](#section-13--specialized-domain)
  - [13.1 Third-Party Risk Agent (OneTrust + SecurityScorecard)](#131-third-party-risk-agent-onetrust--securityscorecard)
  - [13.2 OT / IoT Security Agent (Defender for IoT + Claroty)](#132-ot--iot-security-agent)
  - [13.3 ESG / Sustainability Agent](#133-esg--sustainability-agent)
- [Section 14 — Integration Domain](#section-14--integration-domain)
  - [14.1 Chat Interface Agent (Teams + Slack)](#141-chat-interface-agent-teams--slack)
- [Section 15 — Event Bus Catalogue](#section-15--event-bus-catalogue)
- [Section 16 — Data Schema](#section-16--data-schema)
- [Section 17 — Multi-Region Deployment Topology](#section-17--multi-region-deployment-topology)

---

## Section 1 — Base Agent Class & Multi-Region Pattern

### 1.1 Base Agent Class

All ~40 agents inherit from `GlobalSecBaseAgent` defined in `agents/base_agent.py`.

| Method | Purpose |
|--------|---------|
| `start()` | Bootstrap: register with regional Paperclip → metrics loop → call `run()` |
| `run()` | **Abstract** — main polling/event loop |
| `collect_metrics()` | **Abstract** — returns KPI dict |
| `process_event(event)` | **Abstract** — handles inbound events |
| `publish_event(type, payload)` | POST event to Azure Service Bus topic |
| `report_metrics()` | Calls `collect_metrics()` and publishes `metrics_update` every 5 minutes |
| `health_check()` | Returns standard health response |
| `get_secret(env_key)` | Reads from environment (Azure Key Vault-injected via Managed Identity) |
| `register_with_paperclip()` | POST `/agents/register` to regional orchestrator |
| `get_region()` | Returns the agent's deployment region (from environment) |
| `is_global_agent()` | Returns True for agents that run as a single global instance |

### 1.2 Multi-Region Deployment Pattern

Each agent has one of two deployment modes:

| Mode | When | Examples |
|------|------|----------|
| **Regional** | Data residency required | EDR, DLP, Data Residency, DSPM, Email Security |
| **Global** | No residency concern; single source of truth desired | Threat Intel, Brand Protection, EASM, Compliance/GRC |

**Regional agents** are deployed once per region (6 instances) — each connects to that region's tooling endpoint and uses regional Azure Key Vault.

**Global agents** are deployed in the Middle East (control plane region) but consume from regional sources via the event bus.

### 1.3 Event Bus

All inter-agent communication is via **Azure Service Bus** topics:

- **Regional topics** — `globalsec-events-{region}` (apac, emea, amer, gcc, africa, me)
- **Global topic** — `globalsec-events-global` (subscribed by global agents)

### 1.4 Secrets Management

**Azure Key Vault** with Managed Identity:
- Each region has dedicated Key Vault: `kv-globalsec-{region}-prod`
- Global control plane Key Vault: `kv-globalsec-global-prod`
- Agents read secrets via Managed Identity (no credentials in code)
- Key rotation enforced via Azure Policy

---

## Section 2 — Identity Domain

### 2.1 Entra ID Agent

**Module:** `agents/entra-id-agent/` · **Port:** `8001` · **Tier:** T0 · **Mode:** Global

#### Tool Integrations
| Tool | API | Documentation |
|------|-----|---------------|
| Microsoft Entra ID | Microsoft Graph API v1.0 | https://learn.microsoft.com/en-us/graph/api/overview |
| Entra ID Identity Protection | Identity Protection API | https://learn.microsoft.com/en-us/graph/api/resources/identityprotectionroot |
| Entra ID Governance | Access Reviews + Lifecycle Workflows | https://learn.microsoft.com/en-us/entra/id-governance/ |

#### Authentication
Microsoft Entra App Registration with **Application** permissions (admin consented).

#### Setup Steps

1. **Azure Portal → Entra ID → App registrations → New registration**
   - Name: `globalsec-entra-id-agent`
   - Account types: Single tenant
   - No redirect URI

2. **API Permissions** → Add the following Microsoft Graph **Application** permissions:
   - `User.Read.All` — read all user profiles
   - `Directory.Read.All` — read directory data
   - `IdentityRiskyUser.ReadWrite.All` — manage risky user state
   - `IdentityRiskEvent.Read.All` — read risk detections
   - `AuditLog.Read.All` — read sign-in and audit logs
   - `Policy.Read.All` — read Conditional Access policies
   - `Reports.Read.All` — read usage reports
   - `RoleManagement.Read.All` — read role assignments

3. Click **Grant admin consent for [tenant]**

4. **Certificates & secrets → Client secrets → New** (rotation: 12 months)

5. Copy `Tenant ID`, `Client ID`, `Client Secret`

6. Store in Azure Key Vault:
   ```bash
   az keyvault secret set --vault-name kv-globalsec-global-prod \
     --name entra-tenant-id --value "<tenant-id>"
   az keyvault secret set --vault-name kv-globalsec-global-prod \
     --name entra-client-id --value "<client-id>"
   az keyvault secret set --vault-name kv-globalsec-global-prod \
     --name entra-client-secret --value "<client-secret>"
   ```

#### Required Secrets
```
ENTRA_TENANT_ID
ENTRA_CLIENT_ID
ENTRA_CLIENT_SECRET
```

#### Behaviour
- **Polling:** 5-minute risky user poll, 1-minute sign-in log poll
- **Real-time:** Event Grid subscription on Entra audit logs
- **Events published:** `risky_user_detected`, `mfa_disabled_alert`, `legacy_auth_detected`, `unusual_signin`, `privileged_role_assigned`
- **Events subscribed:** `ato_detected` (forces password reset)

#### Metrics Reported
- `risky_users_count` (high / medium / low)
- `mfa_adoption_rate` — % of enabled users with MFA registered
- `legacy_auth_attempts_24h`
- `signin_failure_rate`
- `privileged_role_assignments_active`
- `inactive_users_30d` / `inactive_users_90d`
- `external_users_count`
- `conditional_access_policies_active`

#### Chat Commands
| Command | Action |
|---------|--------|
| `/identity status [user]` | User risk profile |
| `/identity force-reset <user>` | Force password reset |
| `/identity revoke-sessions <user>` | Revoke all active sessions |
| `/identity disable <user>` | Disable account (with audit) |

---

### 2.2 PIM Agent

**Module:** `agents/pim-agent/` · **Port:** `8002` · **Tier:** T0 · **Mode:** Global

#### Tool Integrations
- Microsoft Entra Privileged Identity Management API
- Documentation: https://learn.microsoft.com/en-us/graph/api/resources/privilegedidentitymanagementv3-overview

#### Authentication
Reuses Entra app registration from Section 2.1 with additional permissions.

#### Setup Steps
1. On the existing `globalsec-entra-id-agent` app, add additional Microsoft Graph **Application** permissions:
   - `RoleManagement.Read.Directory`
   - `RoleManagement.ReadWrite.Directory`
   - `PrivilegedAccess.Read.AzureAD`
   - `PrivilegedAccess.ReadWrite.AzureAD`
2. Grant admin consent
3. Configure PIM in Entra:
   - **Entra ID → PIM → Azure AD roles → Settings**
   - For each role (especially Global Admin, Privileged Role Admin, Security Admin):
     - Activation max duration: 8 hours (4 hours for Tier 0 roles)
     - Require approval: Yes (for Tier 0)
     - Require MFA: Yes
     - Require justification: Yes
     - Require ticket information: Yes (for Tier 0)
4. Configure approver groups per role tier

#### Required Secrets
Same as Entra ID Agent.

#### Behaviour
- **Polling:** 1-minute active role assignment poll
- **Webhook:** Microsoft Graph subscriptions for role activation events
- **Events published:** `pim_activation_started`, `pim_activation_extended`, `pim_activation_denied`, `pim_role_assigned_permanent_alert` (alerts on permanent assignments)
- **Events subscribed:** `incident_created` (correlates with active PIM sessions)

#### Metrics Reported
- `active_pim_sessions`
- `pim_activations_24h` (by role)
- `permanent_role_assignments` (should be near zero)
- `pim_activations_with_approval`
- `tier0_active_sessions`
- `mean_activation_duration_minutes`

#### Chat Commands
| Command | Action |
|---------|--------|
| `/pim active` | List currently active PIM sessions |
| `/pim deactivate <user> <role>` | Force deactivation |
| `/pim audit <user> <days>` | PIM history for user |

---

### 2.3 PAM Agent (CyberArk)

**Module:** `agents/pam-agent/` · **Port:** `8003` · **Tier:** T1 · **Mode:** Global

#### Tool Integrations
- CyberArk Privilege Cloud REST API
- Documentation: https://docs.cyberark.com/PrivCloud-SS/Latest/en/Content/SDK/Privileged%20Account%20Security%20Web%20Services%20SDK.htm

#### Authentication
CyberArk Application Identity (AAM) for service accounts; OAuth 2.0 for API access.

#### Setup Steps

1. **CyberArk Privilege Cloud admin → Users → Add User**
   - Username: `globalsec-pam-agent`
   - Authentication: API key
2. **Roles → Assign:**
   - `Audit Users` (read access)
   - Custom role with: List accounts, View safe contents (read-only)
3. **Settings → Application IDs → Add**
   - App ID: `globalsec-pam-agent`
   - Authentication method: API key
   - Allowed machines: AKS pod IPs (or use OS user)
4. Generate API key
5. Store in Azure Key Vault:
   ```bash
   az keyvault secret set --vault-name kv-globalsec-global-prod \
     --name cyberark-api-key --value "<api-key>"
   az keyvault secret set --vault-name kv-globalsec-global-prod \
     --name cyberark-pvwa-url --value "https://privilegecloud.cyberark.cloud/PasswordVault"
   az keyvault secret set --vault-name kv-globalsec-global-prod \
     --name cyberark-app-id --value "globalsec-pam-agent"
   ```

#### Required Secrets
```
CYBERARK_PVWA_URL
CYBERARK_APP_ID
CYBERARK_API_KEY
```

#### Behaviour
- **Polling:** 2-minute session activity poll
- **Webhook:** CyberArk SIEM forwarder for real-time session events
- **Events published:** `pam_session_started`, `pam_session_ended`, `pam_unauthorized_access_attempt`, `pam_credential_request`, `pam_session_recording_complete`
- **Events subscribed:** `incident_created`, `tier0_active_sessions`

#### Metrics Reported
- `active_pam_sessions`
- `sessions_24h_count`
- `unique_targets_accessed`
- `failed_access_attempts`
- `session_recording_compliance_rate`
- `mean_session_duration_minutes`

#### Chat Commands
| Command | Action |
|---------|--------|
| `/pam active` | List active PAM sessions |
| `/pam terminate <session-id>` | Force-terminate session |
| `/pam recording <session-id>` | Get recording link |

---

## Section 3 — Endpoint Domain

### 3.1 EDR Agent (CrowdStrike Falcon Enterprise)

**Module:** `agents/edr-agent/` · **Port:** `8010` · **Tier:** T0 · **Mode:** Regional (6 instances)

#### Tool Integrations
- CrowdStrike Falcon REST API
- Documentation: https://developer.crowdstrike.com/crowdstrike/reference/api-overview
- Falcon Streaming API (real-time events)

#### Authentication
OAuth 2.0 client credentials flow.

#### Setup Steps

1. **Falcon Console** → `https://falcon.crowdstrike.com` (or regional console)
2. **Support → API Clients and Keys → Create API Client**
   - Name: `globalsec-edr-agent-{region}` (one per region)
   - Description: "GlobalSec EDR agent for {region}"
3. **Required scopes** (Read + Write where indicated):
   - `Detections (Read, Write)`
   - `Hosts (Read, Write)` — for isolation
   - `Real-time response (Read, Write)` — for `/isolate`
   - `Incidents (Read, Write)`
   - `Streaming (Read)` — for real-time events
   - `Alerts (Read, Write)`
   - `Falcon Discover (Read)` — for asset discovery
4. Copy `Client ID` and `Client Secret` (shown once)
5. Determine your CrowdStrike Cloud:
   - US-1: `https://api.crowdstrike.com`
   - US-2: `https://api.us-2.crowdstrike.com`
   - EU-1: `https://api.eu-1.crowdstrike.com`
   - US-GOV-1: `https://api.laggar.gcw.crowdstrike.com` (not used here)
6. Per-region storage in regional Key Vault:
   ```bash
   for region in apac emea amer gcc africa me; do
     az keyvault secret set --vault-name kv-globalsec-${region}-prod \
       --name crowdstrike-client-id --value "<client-id-${region}>"
     az keyvault secret set --vault-name kv-globalsec-${region}-prod \
       --name crowdstrike-client-secret --value "<client-secret-${region}>"
     az keyvault secret set --vault-name kv-globalsec-${region}-prod \
       --name crowdstrike-base-url --value "https://api.eu-1.crowdstrike.com"
   done
   ```

#### Required Secrets (per region)
```
CROWDSTRIKE_CLIENT_ID
CROWDSTRIKE_CLIENT_SECRET
CROWDSTRIKE_BASE_URL
GLOBALSEC_REGION                          # apac, emea, amer, gcc, africa, me
```

#### Behaviour
- **Streaming:** Falcon Streaming API connection for real-time detections
- **Polling:** 60-second fallback poll for detections
- **Events published:** `critical_endpoint_alert`, `endpoint_isolated`, `falcon_indicator_match`, `host_offline_alert`
- **Events subscribed:** `isolate_endpoint`, `threat_intel_ioc`, `siem_correlation_hit`

#### Metrics Reported
- `total_detections_24h`
- `by_severity` (critical/high/medium/low)
- `endpoints_protected_count`
- `endpoints_offline_24h`
- `mttd_minutes`
- `mttr_minutes`
- `top_detected_techniques` (MITRE)
- `auto_resolved_percentage`

#### Scaling
- One regional instance per CrowdStrike tenant region
- Stateless except Streaming API connection
- Falcon offers ~5,000 events/min limit per Streaming connection

#### Retry Strategy
- Streaming reconnect: exponential backoff 1s → 60s
- API calls: 3x retry with backoff
- Dead-letter queue for failed event processing

#### Chat Commands
| Command | Action |
|---------|--------|
| `/edr status [region]` | EDR coverage stats |
| `/edr isolate <hostname>` | Isolate endpoint via RTR |
| `/edr unisolate <hostname>` | Restore network |
| `/edr scan <hostname>` | On-demand scan |

---

### 3.2 MDM Agent (Microsoft Intune)

**Module:** `agents/mdm-agent/` · **Port:** `8011` · **Tier:** T1 · **Mode:** Global

#### Tool Integrations
- Microsoft Intune via Microsoft Graph API
- Documentation: https://learn.microsoft.com/en-us/graph/api/resources/intune-graph-overview

#### Authentication
Reuses Entra app registration with additional Intune permissions.

#### Setup Steps
1. On `globalsec-entra-id-agent` Entra app, add Graph **Application** permissions:
   - `DeviceManagementApps.Read.All`
   - `DeviceManagementConfiguration.Read.All`
   - `DeviceManagementManagedDevices.Read.All`
   - `DeviceManagementManagedDevices.PrivilegedOperations.All` (for retire/wipe)
2. Grant admin consent
3. Verify Intune licenses cover all 115K users (typically M365 E5 inclusive)
4. Configure compliance policies in Intune (out of scope for this agent — SecOps consumption only)

#### Required Secrets
Same as Entra ID Agent.

#### Behaviour
- **Polling:** 10-minute device compliance poll
- **Events published:** `device_non_compliant`, `device_jailbroken`, `device_wiped`, `device_lost_alert`
- **Events subscribed:** `lost_device_reported`

#### Metrics Reported
- `total_managed_devices`
- `compliant_devices_percentage`
- `non_compliant_by_reason`
- `jailbroken_rooted_devices`
- `devices_pending_enrollment`
- `os_version_distribution`

#### Chat Commands
| Command | Action |
|---------|--------|
| `/mdm status` | Compliance overview |
| `/mdm wipe <device-id>` | Remote wipe (requires approval) |
| `/mdm retire <device-id>` | Retire (corp data only) |
| `/mdm sync <user>` | Force sync of user's devices |

---

## Section 4 — Communication Domain

### 4.1 Email Security Agent

**Module:** `agents/email-security-agent/` · **Port:** `8020` · **Tier:** T0 · **Mode:** Regional (4 instances — APAC, EMEA, AMER, GCC; ME piggybacks on GCC)

#### Tool Integrations
- Microsoft Defender for Office 365 P2 via Graph Security API
- Proofpoint TAP REST API (advanced threat layer)

#### Authentication
- **Defender:** Reuses Entra app with additional permissions
- **Proofpoint:** Service Principal with API key

#### Setup Steps

**Defender for O365:**
1. On `globalsec-entra-id-agent`, add Graph **Application** permissions:
   - `SecurityAlert.Read.All`
   - `ThreatHunting.Read.All`
   - `ThreatIntelligence.Read.All`
   - `Mail.Read` (for BEC analysis)
2. Grant admin consent

**Proofpoint TAP:**
1. **Proofpoint TAP Dashboard → Settings → Connected Applications → Create credentials**
2. Service principal name: `globalsec-email-security`
3. Permissions: `Read events, Read campaigns`
4. Copy Service Principal + Secret

5. Store in regional Key Vaults:
   ```bash
   for region in apac emea amer gcc; do
     az keyvault secret set --vault-name kv-globalsec-${region}-prod \
       --name proofpoint-sp --value "<sp>"
     az keyvault secret set --vault-name kv-globalsec-${region}-prod \
       --name proofpoint-secret --value "<secret>"
   done
   ```

#### Required Secrets
```
ENTRA_TENANT_ID                           # reused
ENTRA_CLIENT_ID                           # reused
ENTRA_CLIENT_SECRET                       # reused
PROOFPOINT_SP
PROOFPOINT_SECRET
```

#### Behaviour
- **Polling:** 5-minute Defender poll, 5-minute Proofpoint poll
- **Events published:** `phishing_detected`, `bec_attempt_blocked`, `dmarc_failure`, `email_attachment_malicious`, `qr_phishing_detected`
- **Events subscribed:** `threat_intel_ioc`, `block_indicator`

#### Metrics Reported
- `phishing_blocked_24h` (per region)
- `bec_attempts_blocked`
- `dmarc_pass_rate`, `spf_pass_rate`, `dkim_pass_rate`
- `attachment_sandboxing_verdicts`
- `safe_links_blocks`
- `top_targeted_users` (BEC targets)
- `qr_phishing_detected`

---

### 4.2 Teams Security Agent

**Module:** `agents/teams-security-agent/` · **Port:** `8021` · **Tier:** T1 · **Mode:** Global

#### Tool Integrations
- Microsoft Defender for Cloud Apps (formerly MCAS)
- Microsoft Graph (Teams API for governance)

#### Authentication
Reuses Entra app with additional permissions.

#### Setup Steps
1. Add Graph **Application** permissions:
   - `ChannelMessage.Read.All`
   - `ChatMessage.Read.All`
   - `Team.ReadBasic.All`
   - `Files.Read.All`
2. Onboard Microsoft Defender for Cloud Apps
3. Configure file policies for Teams (sensitive content detection)

#### Behaviour
- **Polling:** 10-minute Teams activity poll via Cloud App Security
- **Events published:** `teams_external_share_alert`, `teams_sensitive_content_shared`, `teams_unusual_activity`
- **Events subscribed:** `dlp_policy_match`

#### Metrics Reported
- `external_chats_count`
- `sensitive_content_shares`
- `external_guest_access_count`
- `teams_with_guest_users`

---

## Section 5 — Network Domain

### 5.1 DNS Security Agent

**Module:** `agents/dns-security-agent/` · **Port:** `8030` · **Tier:** T0 · **Mode:** Regional (6 instances)

#### Tool Integrations
- Cisco Umbrella (for non-Azure resolution)
- Azure DNS Private Resolver (for Azure VNets)

#### Authentication
Cisco Umbrella API keys (reporting + enforcement).

#### Setup Steps

1. **Umbrella Dashboard** → `https://dashboard.umbrella.com`
2. **Admin → API Keys → Create New Key (Reporting):**
   - Name: `globalsec-dns-reporting-{region}`
3. **Create another (Management/Enforcement):**
   - Name: `globalsec-dns-enforcement-{region}`
4. **Admin → Account Settings** → copy `Org ID`
5. Per-region storage:
   ```bash
   az keyvault secret set --vault-name kv-globalsec-${region}-prod \
     --name umbrella-org-id --value "<org-id>"
   az keyvault secret set --vault-name kv-globalsec-${region}-prod \
     --name umbrella-reporting-key --value "<key>"
   az keyvault secret set --vault-name kv-globalsec-${region}-prod \
     --name umbrella-enforcement-key --value "<key>"
   ```

#### Required Secrets (per region)
```
UMBRELLA_ORG_ID
UMBRELLA_REPORTING_KEY
UMBRELLA_REPORTING_SECRET
UMBRELLA_ENFORCEMENT_KEY
UMBRELLA_ENFORCEMENT_SECRET
```

#### Behaviour
- **Polling:** 60-second DNS query log poll
- **Real-time:** Push to Umbrella enforcement on `block_indicator` event
- **Events published:** `dns_c2_callback`, `dns_tunneling_detected`, `malicious_domain_blocked`, `newly_seen_domain_alert`
- **Events subscribed:** `block_indicator`, `threat_intel_ioc`

#### Metrics Reported
- `blocked_malicious_domains_24h`
- `c2_callbacks_prevented`
- `dns_tunneling_attempts`
- `top_blocked_categories`
- `query_volume_per_hour`
- `newly_seen_domains_count`

---

### 5.2 SSE / Web Proxy Agent (Netskope)

**Module:** `agents/sse-agent/` · **Port:** `8031` · **Tier:** T1 · **Mode:** Regional (3 instances — APAC, EMEA, AMER)

#### Tool Integrations
- Netskope ONE Platform API
- Documentation: https://docs.netskope.com/en/netskope-help/admin-console/rest-api/

#### Authentication
Netskope API token (per tenant).

#### Setup Steps
1. **Netskope Tenant Admin → Settings → Tools → REST API v2**
2. Create API token with scopes:
   - `Read events`
   - `Read alerts`
   - `Read policies`
   - `Read incidents`
3. Store in regional Key Vaults
4. For multi-region tenants: separate API token per Netskope tenant

#### Required Secrets
```
NETSKOPE_TENANT_URL                       # https://yourtenant.goskope.com
NETSKOPE_API_TOKEN
```

#### Behaviour
- **Polling:** 5-minute event poll
- **Events published:** `cloud_app_risk_alert`, `dlp_violation`, `unmanaged_device_access`, `policy_violation`, `malware_blocked`
- **Events subscribed:** `block_indicator`, `dlp_policy_update`

#### Metrics Reported
- `cloud_apps_in_use_count`
- `risky_cloud_apps_blocked`
- `dlp_violations_24h`
- `bandwidth_consumed_gb`
- `users_active_count`
- `policy_violations_per_user_top10`

---

### 5.3 Network Detection Agent (Darktrace + Defender for Identity)

**Module:** `agents/network-detection-agent/` · **Port:** `8032` · **Tier:** T1 · **Mode:** Regional (6 instances)

#### Tool Integrations
- Darktrace Enterprise Immune System (EIS) API
- Microsoft Defender for Identity API

#### Authentication
- **Darktrace:** API key + private key
- **Defender for Identity:** Reuses Entra app

#### Setup Steps

**Darktrace:**
1. **Darktrace Threat Visualizer → System Config → API**
2. Generate API key (private + public components)
3. Store both components

**Defender for Identity:**
1. Add Graph **Application** permissions:
   - `SecurityIncident.Read.All`
   - `SecurityActions.Read.All`
2. Grant consent

#### Required Secrets (per region)
```
DARKTRACE_API_KEY
DARKTRACE_PRIVATE_KEY
DARKTRACE_HOST                            # https://your-instance.darktrace.com
```

#### Behaviour
- **Polling:** 60-second model breach poll (Darktrace), 5-minute Defender for Identity alerts
- **Events published:** `network_anomaly_detected`, `lateral_movement_alert`, `data_exfil_attempt`, `unusual_internal_traffic`
- **Events subscribed:** `endpoint_isolated`, `threat_intel_ioc`

#### Metrics Reported
- `model_breaches_24h`
- `breach_score_distribution`
- `top_internal_devices_breaching`
- `lateral_movement_indicators`

---

### 5.4 CDN Security Agent

**Module:** `agents/cdn-security-agent/` · **Port:** `8033` · **Tier:** T2 · **Mode:** Global

Reuses Cloudflare API token from WAF Agent (Section 6.1) with additional CDN-specific permissions.

#### Setup Steps
On the Cloudflare API token, ensure these scopes:
- `Zone → Cache Purge → Edit`
- `Zone → SSL and Certificates → Read`
- `Zone → Analytics → Read`

#### Behaviour
- **Polling:** 30-minute CDN config audit
- **Events published:** `cdn_misconfiguration`, `cache_poisoning_attempt`, `weak_tls_detected`
- **Events subscribed:** `waf_rule_updated`

#### Metrics Reported
- Same as EcomSec CDN Security Agent
- Plus: `multi_region_consistency_score`

---

## Section 6 — Application Domain

### 6.1 WAF + Bot Agent

**Module:** `agents/waf-bot-agent/` · **Port:** `8040` · **Tier:** T0 · **Mode:** Global

#### Tool Integrations
- Cloudflare Enterprise WAF + Bot Management
- Azure Front Door WAF (for Azure-hosted apps)

#### Authentication
- **Cloudflare:** API token
- **Azure Front Door:** Managed Identity

#### Setup Steps

**Cloudflare:**
1. **Cloudflare Dashboard → My Profile → API Tokens → Create Token**
2. Custom token permissions:
   - `Zone → Firewall Services → Edit`
   - `Zone → Bot Management → Edit`
   - `Zone → Analytics → Read`
   - `Zone → Page Rules → Edit`
3. Zone resources: All zones (or specify enterprise zones)
4. Account resources: Specific account ID
5. Copy token + Account ID

**Azure Front Door:**
- Use Managed Identity assigned to AKS pod
- Grant `Reader` + `Front Door WAF Contributor` on Front Door resource

#### Required Secrets
```
CLOUDFLARE_API_TOKEN
CLOUDFLARE_ACCOUNT_ID
CLOUDFLARE_ZONE_IDS                       # comma-separated
AZURE_FRONT_DOOR_RG                       # resource group
AZURE_FRONT_DOOR_NAME
```

#### Behaviour
- **Polling:** 60-second event poll (Cloudflare GraphQL Analytics)
- **Events published:** `waf_attack_detected`, `bot_traffic_spike`, `ddos_mitigated`, `rate_limit_exceeded`, `firewall_rule_breach`
- **Events subscribed:** `block_indicator`, `threat_intel_ioc`

#### Metrics Reported
- `attacks_blocked_24h` (by category)
- `bot_traffic_percentage`
- `top_attack_vectors` (SQLi, XSS, RCE, path traversal)
- `top_attacking_countries`
- `false_positive_rate`
- `requests_per_second_peak`

---

### 6.2 API Security Agent (Salt Security)

**Module:** `agents/api-security-agent/` · **Port:** `8041` · **Tier:** T1 · **Mode:** Global

#### Tool Integrations
- Salt Security Platform API
- Documentation: https://docs.salt.security/

#### Authentication
Salt Security API key.

#### Setup Steps
1. **Salt Security Console → Settings → API Tokens → Create**
2. Permissions: `Read incidents, Read endpoints, Read API discovery`
3. Store token

#### Required Secrets
```
SALT_API_TOKEN
SALT_API_BASE_URL                         # https://app.salt.security
```

#### Behaviour
- **Polling:** 5-minute incident poll
- **Events published:** `api_attack_detected`, `api_anomaly_detected`, `shadow_api_discovered`, `api_token_abuse`
- **Events subscribed:** `block_indicator`, `waf_attack_detected`

#### Metrics Reported
- `apis_discovered_count`
- `shadow_apis`
- `api_attacks_24h`
- `api_attack_categories`
- `top_abused_endpoints`

---

### 6.3 SAST Agent (Checkmarx One)

**Module:** `agents/sast-agent/` · **Port:** `8042` · **Tier:** T1 · **Mode:** Global

#### Tool Integrations
- Checkmarx One REST API
- Documentation: https://docs.checkmarx.com/en/34965-99002-checkmarx-one-rest-api---authentication.html

#### Setup Steps
1. **Checkmarx One web UI → Settings → API Keys**
2. Generate API key with `Engine User` role
3. Configure CI/CD integration (GitHub Actions / Azure DevOps Pipelines)

#### Required Secrets
```
CHECKMARX_API_KEY
CHECKMARX_HOST                            # https://ast.checkmarx.net
CHECKMARX_TENANT
```

#### Behaviour
- **Triggered:** On every PR via webhook
- **Events published:** `sast_critical_finding`, `release_blocked`, `new_high_finding`
- **Events subscribed:** `new_pr_opened`

#### Metrics Reported
- `vulnerabilities_by_severity`
- `code_coverage_percentage`
- `mean_remediation_time_days`
- `false_positive_rate`

---

### 6.4 DAST/SCA Agent (Snyk)

**Module:** `agents/snyk-agent/` · **Port:** `8043` · **Tier:** T1 · **Mode:** Global

#### Tool Integrations
- Snyk REST API v1
- Documentation: https://docs.snyk.io/snyk-api

#### Setup Steps
1. **Snyk app.snyk.io → Settings → General → Auth Token**
2. Use service account for production
3. Get organization ID

#### Required Secrets
```
SNYK_API_TOKEN
SNYK_ORG_ID
```

#### Behaviour
- **Triggered:** On every PR + 24-hour scheduled scan
- **Events published:** `dependency_vuln_found`, `license_violation`, `code_quality_issue`
- **Events subscribed:** `new_pr_opened`, `new_release_candidate`

#### Metrics Reported
- `dependency_health_score`
- `vulnerabilities_by_severity`
- `licenses_in_use`
- `outdated_dependencies_count`

---

### 6.5 Mobile Threat Defense Agent (Lookout)

**Module:** `agents/mtd-agent/` · **Port:** `8044` · **Tier:** T2 · **Mode:** Global

#### Tool Integrations
- Lookout Mobile Endpoint Security API
- Documentation: https://api.lookout.com/

#### Setup Steps
1. **Lookout Tenant → Settings → API → Create Application**
2. Scopes: `Read threats, Read devices`
3. Generate API key

#### Required Secrets
```
LOOKOUT_API_KEY
LOOKOUT_TENANT_ID
```

#### Behaviour
- **Polling:** 10-minute threat poll
- **Events published:** `mobile_malware_detected`, `mobile_jailbreak_detected`, `mobile_unsafe_network`, `mobile_phishing_detected`
- **Events subscribed:** `device_lost_alert`

#### Metrics Reported
- `mobile_devices_protected_count`
- `mobile_threats_detected_24h`
- `jailbroken_rooted_count`
- `os_compliance_rate`

---

## Section 7 — Data Domain

### 7.1 DLP Agent (Microsoft Purview DLP)

**Module:** `agents/dlp-agent/` · **Port:** `8050` · **Tier:** T0 · **Mode:** Regional (6 instances)

#### Tool Integrations
- Microsoft Purview Compliance Center via Graph API
- Microsoft Purview eDiscovery (premium)

#### Authentication
Reuses Entra app + dedicated Compliance role.

#### Setup Steps
1. **Microsoft Purview Compliance Portal → Roles**
2. Create role group: `globalsec-dlp-readers`
   - Add roles: `Compliance Administrator`, `Information Protection Reader`
3. Add the `globalsec-entra-id-agent` service principal as member
4. Add Graph **Application** permissions:
   - `InformationProtectionPolicy.Read.All`
   - `ThreatAssessment.ReadWrite.All`
5. Grant consent

#### Required Secrets
Reuses `ENTRA_*` secrets.

#### Behaviour
- **Polling:** 10-minute incident poll
- **Real-time:** webhook from Purview on policy match
- **Events published:** `dlp_policy_match`, `pii_exfil_attempt`, `payment_data_exposed`, `health_data_exposure`
- **Events subscribed:** `cross_border_transfer_detected`

#### Metrics Reported
- `dlp_incidents_24h` (per region)
- `incidents_by_data_type` (PII / PCI / PHI / IP)
- `policy_violations_by_user`
- `top_violating_apps`
- `data_at_risk_volume_mb`

---

### 7.2 Insider Risk Agent (Purview IRM)

**Module:** `agents/insider-risk-agent/` · **Port:** `8051` · **Tier:** T1 · **Mode:** Global

#### Tool Integrations
- Microsoft Purview Insider Risk Management
- Documentation: https://learn.microsoft.com/en-us/purview/insider-risk-management

#### Authentication
Reuses Entra app + Insider Risk Management Admin role.

#### Setup Steps
1. **Purview → Roles → Insider Risk Management**
2. Add service principal to: `Insider Risk Management Investigators` role group
3. Configure IRM policies (out of scope — admin-driven)
4. Add Graph **Application** permissions:
   - `InsiderRiskManagement.Read.All`

#### Behaviour
- **Polling:** 30-minute alert poll
- **Events published:** `insider_risk_high_alert`, `data_theft_indicator`, `disgruntled_employee_signal`, `unusual_access_pattern`
- **Events subscribed:** `employee_termination_event` (from HR system)

#### Metrics Reported
- `high_risk_users_count`
- `medium_risk_users_count`
- `risk_indicators_24h`
- `cases_open` / `cases_closed`

---

### 7.3 DSPM Agent (Varonis)

**Module:** `agents/dspm-agent/` · **Port:** `8052` · **Tier:** T1 · **Mode:** Regional (where data lives)

#### Tool Integrations
- Varonis Data Security Platform API
- Documentation: https://www.varonis.com/products/data-security-platform

#### Setup Steps
1. **Varonis DatAdvantage → Configuration → API Access → Create Service Account**
2. Permissions: Read access to all data sources
3. Generate API token

#### Required Secrets (per region)
```
VARONIS_API_TOKEN
VARONIS_API_HOST
```

#### Behaviour
- **Polling:** 1-hour data risk scan
- **Events published:** `sensitive_data_overexposed`, `stale_data_alert`, `permission_drift`, `data_access_anomaly`
- **Events subscribed:** `dlp_policy_match`

#### Metrics Reported
- `sensitive_data_volume_tb`
- `overexposed_data_percentage`
- `stale_data_volume_tb` (>3 years no access)
- `permission_anomalies_count`
- `data_owners_assigned_percentage`

---

### 7.4 Data Residency Agent

**Module:** `agents/data-residency-agent/` · **Port:** `8053` · **Tier:** T0 · **Mode:** Global (orchestrates regional checks)

#### Tool Integrations
- Azure Resource Graph
- Azure Policy
- Microsoft Purview Data Map

#### Setup Steps
1. Service Principal with **Reader** role at Tenant Root Group
2. Enable Azure Policy for resource location compliance
3. Configure Purview Data Map with regional classification rules

#### Required Secrets
```
AZURE_TENANT_ID                           # global
AZURE_CLIENT_ID                           # global service principal
AZURE_CLIENT_SECRET
APPROVED_REGIONS_PER_GEO                  # JSON config
```

#### Behaviour
- **Polling:** 1-hour Azure Resource Graph scan
- **Real-time:** Event Grid on resource creation
- **Events published:** `data_residency_violation`, `cross_border_transfer_detected`, `prohibited_region_resource`
- **Events subscribed:** `new_cloud_resource_created`

#### Metrics Reported
- `resources_by_region_count`
- `residency_violations_24h`
- `cross_border_transfers_blocked`
- `compliance_percentage_per_regulation`

---

## Section 8 — Detection & Response Domain

### 8.1 SIEM Agent (Microsoft Sentinel)

**Module:** `agents/siem-agent/` · **Port:** `8060` · **Tier:** T0 · **Mode:** Global control plane + regional workspaces

#### Tool Integrations
- Microsoft Sentinel via Log Analytics REST API
- Sentinel Management API
- Microsoft Defender XDR API

#### Authentication
Entra app + Reader on each Log Analytics workspace.

#### Setup Steps
1. Sentinel architecture:
   - Global workspace: `law-globalsec-global-prod` (in Middle East)
   - Regional workspaces: `law-globalsec-{region}-prod` (one per region)
2. Enable Sentinel on global workspace + each regional
3. Configure cross-workspace queries (Sentinel multi-workspace view)
4. Grant Entra app:
   - `Microsoft Sentinel Reader` on each workspace
   - `Microsoft Sentinel Responder` on each workspace (for alert mgmt)
5. Add Graph **Application** permissions:
   - `SecurityAlert.Read.All`
   - `SecurityIncident.Read.All`
   - `ThreatHunting.Read.All`

#### Required Secrets
Reuses Entra. Plus:
```
SENTINEL_GLOBAL_WORKSPACE_ID
SENTINEL_REGIONAL_WORKSPACE_IDS           # JSON: {"apac": "...", "emea": "...", ...}
SENTINEL_RESOURCE_GROUP                   # rg-globalsec-global
```

#### Behaviour
- **Polling:** 30-second incident poll
- **Events published:** `siem_critical_alert`, `correlation_hit`, `trigger_incident_response`, `threat_hunt_finding`
- **Events subscribed:** **All agent events** (correlates everything)

#### Metrics Reported
- `total_alerts_24h` (per region + global)
- `incidents_open_count`
- `true_positive_rate`
- `mttd_minutes`
- `coverage_per_data_source`
- `analytic_rules_active_count`

---

### 8.2 SOAR Agent

**Module:** `agents/soar-agent/` · **Port:** `8061` · **Tier:** T1 · **Mode:** Global

#### Tool Integrations
- Microsoft Sentinel SOAR (built-in)
- Azure Logic Apps (playbooks)
- ServiceNow SecOps

#### Authentication
Managed Identity for Logic Apps.

#### Setup Steps
1. Deploy Azure Logic Apps in `rg-globalsec-soar`
2. For each playbook, configure:
   - Sentinel trigger (incident or alert)
   - Approval flow (Teams card)
   - Action steps (call agent APIs)
3. Reference playbooks from Sentinel automation rules

#### Behaviour
- **Triggered:** Sentinel incidents
- **Events published:** `playbook_executed`, `automation_action_completed`
- **Events subscribed:** `siem_critical_alert`, `run_playbook`

#### Metrics Reported
- `playbooks_executed_24h`
- `playbook_success_rate`
- `mean_playbook_duration_seconds`
- `automation_coverage_percentage` (% of incidents with auto-response)

---

### 8.3 Incident Response Agent

**Module:** `agents/incident-response-agent/` · **Port:** `8062` · **Tier:** T0 · **Mode:** Global

#### Tool Integrations
- ServiceNow Security Incident Response (SecOps)
- PagerDuty for paging
- Microsoft Teams for war room

#### Authentication
- ServiceNow: OAuth 2.0
- PagerDuty: API token

#### Setup Steps

**ServiceNow:**
1. **System OAuth → Application Registry → New OAuth API endpoint**
2. Name: `globalsec-ir-agent`
3. Scope: `read+write` on `sn_si_*` (SecOps tables)

**PagerDuty:**
1. **Profile → API Access Keys → Create**
2. Description: `globalsec-ir-agent`

#### Required Secrets
```
SERVICENOW_INSTANCE                       # https://acme.service-now.com
SERVICENOW_CLIENT_ID
SERVICENOW_CLIENT_SECRET
PAGERDUTY_API_KEY
PAGERDUTY_SERVICE_ID                      # default escalation policy
```

#### Behaviour
- **Triggered:** SIEM critical alerts, EDR alerts, PCI violations
- **Events published:** `incident_created`, `incident_escalated`, `incident_resolved`
- **Events subscribed:** `siem_critical_alert`, `critical_endpoint_alert`, `ato_detected`, `data_residency_violation`

#### Metrics Reported
- `incidents_by_severity`
- `mttr_minutes`
- `incidents_open_count`
- `escalations_to_tier3`
- `regional_incident_distribution`

---

## Section 9 — Cloud Domain

### 9.1 CSPM/CNAPP Agent (Wiz)

**Module:** `agents/cspm-agent/` · **Port:** `8070` · **Tier:** T0 · **Mode:** Global

#### Tool Integrations
- Wiz Platform API (GraphQL)
- Documentation: https://docs.wiz.io/wiz-docs/docs/api

#### Setup Steps
1. **Wiz Portal → Settings → Service Accounts → Create**
2. Name: `globalsec-cspm-agent`
3. Scope: `read:all`
4. Copy `Client ID` and `Client Secret`

#### Required Secrets
```
WIZ_CLIENT_ID
WIZ_CLIENT_SECRET
WIZ_API_ENDPOINT                          # https://api.us27.app.wiz.io/graphql
```

#### Behaviour
- **Polling:** 30-minute issue poll
- **Events published:** `cloud_misconfiguration`, `attack_path_detected`, `iac_violation`, `secret_in_code_detected`
- **Events subscribed:** `new_cloud_resource_created`

#### Metrics Reported
- `cloud_misconfigs_total`
- `cis_benchmark_compliance_percentage`
- `critical_attack_paths`
- `iac_violations_24h`

---

### 9.2 CWPP Agent (Defender for Cloud)

**Module:** `agents/cwpp-agent/` · **Port:** `8071` · **Tier:** T1 · **Mode:** Global

#### Tool Integrations
- Microsoft Defender for Cloud via Azure Resource Manager + Graph API

#### Authentication
Reuses Entra app with additional Defender for Cloud permissions.

#### Setup Steps
1. Add Graph **Application** permissions:
   - `SecurityRecommendations.Read.All`
   - `SecuritySolutions.Read.All`
2. Grant `Security Reader` on Tenant Root Group
3. Enable Defender for Cloud plans on all subscriptions

#### Behaviour
- **Polling:** 30-minute recommendation poll
- **Events published:** `defender_recommendation`, `secure_score_changed`, `regulatory_compliance_drift`

---

### 9.3 Container Security Agent

**Module:** `agents/container-security-agent/` · **Port:** `8072` · **Tier:** T1 · **Mode:** Global

#### Tool Integrations
- Wiz (container findings) — reuses CSPM credentials
- Microsoft Defender for Containers — reuses Entra app
- AKS Audit Logs

#### Behaviour
- **Polling:** 30-minute scan
- **Events published:** `container_critical_cve`, `runtime_anomaly`, `image_signature_invalid`

---

## Section 10 — Threat Intelligence Domain

### 10.1 Threat Intelligence Agent (Recorded Future)

**Module:** `agents/threat-intel-agent/` · **Port:** `8080` · **Tier:** T1 · **Mode:** Global

#### Setup Steps
1. **Recorded Future → User Settings → API Tokens → Generate**
2. Connect API access (paid feature)
3. Store token

#### Required Secrets
```
RECORDED_FUTURE_API_TOKEN
```

#### Behaviour
- **Polling:** 15-minute IOC sync
- **Events published:** `threat_intel_ioc`, `new_ttp_observed`, `threat_actor_activity`, `vulnerability_intelligence_alert`

---

### 10.2 Brand Protection Agent (ZeroFox)

**Module:** `agents/brand-protection-agent/` · **Port:** `8081` · **Tier:** T2 · **Mode:** Global

#### Setup Steps
1. **ZeroFox dashboard → API Keys → Create**
2. Permissions: `Read alerts, Initiate takedowns`

#### Required Secrets
```
ZEROFOX_API_TOKEN
ZEROFOX_ACCOUNT_ID
```

#### Behaviour
- **Polling:** 1-hour brand scan
- **Events published:** `lookalike_domain_detected`, `brand_abuse_found`, `dark_web_mention`, `executive_impersonation`

---

### 10.3 Deception Agent (Illusive)

**Module:** `agents/deception-agent/` · **Port:** `8082` · **Tier:** T2 · **Mode:** Global

#### Setup Steps
1. **Illusive Management Server → Settings → API**
2. Generate API key for SecOps integration

#### Required Secrets
```
ILLUSIVE_API_KEY
ILLUSIVE_HOST
```

#### Behaviour
- **Real-time:** Webhook on deception touch
- **Events published:** `deception_triggered` (HIGH severity always — no false positives)

---

## Section 11 — Governance Domain

### 11.1 Asset Management Agent (Axonius)

**Module:** `agents/asset-management-agent/` · **Port:** `8090` · **Tier:** T0 · **Mode:** Global

#### Setup Steps
1. **Axonius → My Account → API Key → Generate**
2. Store API Key + Secret

#### Required Secrets
```
AXONIUS_HOST
AXONIUS_API_KEY
AXONIUS_API_SECRET
```

#### Behaviour
- **Polling:** 30-minute reconciliation
- **Events published:** `new_asset_discovered`, `shadow_it_detected`, `asset_drift_alert`, `unmanaged_device`

---

### 11.2 Vulnerability Management Agent (Tenable One)

**Module:** `agents/vulnerability-agent/` · **Port:** `8091` · **Tier:** T0 · **Mode:** Global

#### Setup Steps
1. **Tenable.io → Settings → My Account → API Keys → Generate**
2. Save Access Key + Secret Key

#### Required Secrets
```
TENABLE_ACCESS_KEY
TENABLE_SECRET_KEY
```

#### Behaviour
- **Polling:** 1-hour scan result poll
- **Events published:** `critical_cve_found`, `patch_sla_breach`, `exposure_score_changed`

---

### 11.3 Compliance / GRC Agent (ServiceNow GRC)

**Module:** `agents/compliance-grc-agent/` · **Port:** `8092` · **Tier:** T1 · **Mode:** Global

#### Setup Steps
1. **ServiceNow GRC module deployed**
2. OAuth credentials with `sn_grc_*` scope read+write

#### Required Secrets
Reuses ServiceNow IR credentials.

#### Behaviour
- **Polling:** 6-hour evidence collection cycle
- **Events published:** `compliance_control_failed`, `audit_evidence_missing`, `framework_drift`

---

### 11.4 Risk Dashboard Agent

**Module:** `agents/risk-dashboard-agent/` · **Port:** `8093` · **Tier:** T0 · **Mode:** Global

#### Tool Integrations
- Internal aggregator from PostgreSQL + Sentinel
- Power BI embedded dashboards
- WeasyPrint for PDF reports

#### Setup Steps
1. PostgreSQL Flexible Server (geo-redundant) for metrics
2. Power BI Pro license per consumer
3. Embedded Power BI in Teams via custom tab

---

### 11.5 EASM Agent (Defender EASM)

**Module:** `agents/easm-agent/` · **Port:** `8094` · **Tier:** T1 · **Mode:** Global

Uses Microsoft Defender EASM via Azure Resource Manager.

#### Setup Steps
1. Provision Defender EASM resource in Azure
2. Configure inventory scope (domains, IP ranges, ASNs)
3. Service Principal with `Defender EASM Reader`

#### Required Secrets
```
DEFENDER_EASM_RG
DEFENDER_EASM_RESOURCE
```

---

## Section 12 — Resilience Domain

### 12.1 Backup & Recovery Agent (Veeam + Azure Backup)

**Module:** `agents/backup-recovery-agent/` · **Port:** `8100` · **Tier:** T1 · **Mode:** Regional

#### Setup Steps
**Veeam:**
1. Veeam Enterprise Manager → Users → Add `globalsec-backup-agent`
2. Role: Restore Operator
3. Generate REST token

**Azure Backup:**
- Reuse Entra app with `Backup Reader` role on Recovery Services Vaults

#### Required Secrets
```
VEEAM_API_TOKEN
VEEAM_HOST
```

---

### 12.2 Crisis Communications Agent

**Module:** `agents/crisis-comms-agent/` · **Port:** `8101` · **Tier:** T2 · **Mode:** Global

#### Tool Integrations
- Microsoft Teams (Live Meetings)
- Email (SendGrid for breach notification emails)
- ServiceNow Mass Notification

#### Behaviour
- **Triggered:** `regulatory_breach_detected` event
- **Actions:**
  - Create war room Teams meeting
  - Page CISO + Legal + Comms via PagerDuty
  - Draft regulator notification within 72-hour GDPR window
  - Track notification timeline in ServiceNow

---

## Section 13 — Specialized Domain

### 13.1 Third-Party Risk Agent (OneTrust + SecurityScorecard)

**Module:** `agents/third-party-risk-agent/` · **Port:** `8110` · **Tier:** T1 · **Mode:** Global

#### Setup Steps
**OneTrust:**
1. **OneTrust admin → Integration Hub → API Keys**
2. Generate token with `Read TPRM, Read Assessments` scope

**SecurityScorecard:**
1. **SSC → My Account → API**
2. Generate token

#### Required Secrets
```
ONETRUST_API_TOKEN
ONETRUST_HOST
SECURITYSCORECARD_API_TOKEN
```

#### Behaviour
- **Polling:** 1-hour vendor re-score
- **Events published:** `vendor_risk_alert`, `assessment_overdue`, `vendor_score_drop`

---

### 13.2 OT / IoT Security Agent

**Module:** `agents/ot-iot-agent/` · **Port:** `8111` · **Tier:** T2 · **Mode:** Regional (where OT exists)

#### Setup Steps
- Microsoft Defender for IoT deployed via on-prem sensors
- Claroty xDome for industrial visibility (if applicable)

---

### 13.3 ESG / Sustainability Agent

**Module:** `agents/esg-agent/` · **Port:** `8112` · **Tier:** T2 · **Mode:** Global

Custom agent that aggregates:
- Azure Sustainability Calculator data (cyber-related compute carbon)
- Diversity in security team (anonymized)
- Power usage of security tooling
- E-waste from device replacement programs

---

## Section 14 — Integration Domain

### 14.1 Chat Interface Agent (Teams + Slack)

**Module:** `agents/chat-interface/` · **Port:** `8120` · **Tier:** T0 · **Mode:** Global

Same architecture as EcomSec Chat Interface, but:
- **Microsoft Teams is primary** (Bot Framework + Graph API)
- **Slack is secondary** (engineering channels only)
- **40 dedicated channels** in the GlobalSec Team
- **6 regional channels** for Regional Leads
- **Setup wizard** localised per region

#### Required Secrets
```
TEAMS_TENANT_ID                           # reused
TEAMS_CLIENT_ID
TEAMS_CLIENT_SECRET
TEAMS_BOT_FRAMEWORK_APP_ID
TEAMS_BOT_FRAMEWORK_PASSWORD
SLACK_BOT_TOKEN
SLACK_APP_TOKEN
SLACK_SIGNING_SECRET
```

---

## Section 15 — Event Bus Catalogue

GlobalSec extends the EcomSec event catalogue. Key new events:

| Event Type | Source Agent | Subscribers / Purpose |
|------------|--------------|----------------------|
| `risky_user_detected` | Entra ID | SOAR, IR, Chat |
| `pim_activation_started` | PIM | SIEM, Chat |
| `pam_session_started` | PAM | SIEM, Risk Dashboard |
| `cloud_app_risk_alert` | SSE/Netskope | DLP, IR |
| `model_breach_detected` | Network Detection | SIEM, IR |
| `api_attack_detected` | Salt Security | WAF, SIEM, IR |
| `insider_risk_high_alert` | Insider Risk | SIEM, IR, HR |
| `attack_path_detected` | Wiz CSPM | IR, Risk Dashboard |
| `regulatory_breach_detected` | DLP / Data Residency | Crisis Comms, Compliance |
| `executive_impersonation` | Brand Protection | Email Security, IR |
| `deception_triggered` | Deception | SIEM, IR (HIGH severity) |
| `assessment_overdue` | TPRM | Compliance, Risk Dashboard |

---

## Section 16 — Data Schema

PostgreSQL Flexible Server, geo-redundant, in Middle East primary region.

| Table | Purpose |
|-------|---------|
| `agents` | Agent registry with region |
| `agent_metrics` | Time-series metrics with regional partitioning |
| `alerts` | All alerts with regional + framework tags |
| `events` | Immutable event log |
| `posture_scores` | Daily posture per region + global |
| `reports` | Generated reports by tier (board / SOC / regional) |
| `chat_commands` | Audit log of chat commands |
| `wizard_sessions` | Active setup sessions |
| `compliance_evidence` | Evidence per framework × region |
| `vendor_scores` | TPRM vendor scoring history |
| `incidents` | Major incident tracking with regional impact |
| `regulatory_notifications` | Breach notification tracking per regulator |

---

## Section 17 — Multi-Region Deployment Topology

### Azure Resource Naming
```
Subscription: sub-globalsec-prod
├── Management Group: mg-globalsec
│   ├── mg-globalsec-global (Middle East — control plane)
│   │   ├── rg-globalsec-orchestration
│   │   ├── rg-globalsec-sentinel-global
│   │   ├── rg-globalsec-spog
│   │   └── rg-globalsec-keyvault-global
│   ├── mg-globalsec-apac (Singapore)
│   │   ├── rg-globalsec-agents-apac
│   │   ├── rg-globalsec-sentinel-apac
│   │   └── rg-globalsec-keyvault-apac
│   ├── mg-globalsec-emea (Amsterdam)
│   ├── mg-globalsec-amer (Virginia)
│   ├── mg-globalsec-gcc (Dubai)
│   └── mg-globalsec-africa (Johannesburg)
```

### AKS Clusters
- One AKS cluster per region: `aks-globalsec-{region}-prod`
- Workload Identity Federation for pod authentication
- Each agent runs as a Deployment with HPA

### Network Topology
- Azure Virtual WAN with 6 hubs
- Each hub: Azure Firewall Premium + ExpressRoute gateway
- Inter-hub via Microsoft backbone (encrypted)
- Private Endpoints for all PaaS

---

*GlobalSec LLD v1.0 · Author: Alvin, Security Architect · CONFIDENTIAL*
