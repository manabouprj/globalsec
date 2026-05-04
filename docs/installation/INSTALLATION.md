# GlobalSec — Installation Guide

> **Author:** Alvin, Security Architect
> **Version:** 1.0
> **Audience:** Cloud Architects, Security Engineers, DevOps

This guide walks through deploying GlobalSec from zero to production-ready Phase 1 in a centralized Azure environment.

---

## Prerequisites

Before starting, confirm the following are in place:

### Azure
- [ ] Azure tenant with Global Administrator access
- [ ] One Azure subscription dedicated to GlobalSec (`sub-globalsec-prod`)
- [ ] Microsoft Cloud Adoption Framework (CAF) landing zones deployed
- [ ] ExpressRoute connectivity to major regional offices
- [ ] Azure DevOps or GitHub Enterprise for CI/CD

### Microsoft 365
- [ ] M365 E5 licenses for all 115K users (or equivalent with Sentinel + Defender + Purview + Intune + Entra entitlements)
- [ ] Microsoft Teams deployed enterprise-wide
- [ ] Defender XDR products enabled (Defender for Endpoint, Defender for Office 365 P2, Defender for Identity, Defender for Cloud Apps, Defender for Cloud)

### Tooling Procurement (per Phase)
Phase 1 minimum:
- [ ] CrowdStrike Falcon Enterprise contract signed (25K seats minimum for pilot)
- [ ] Microsoft Sentinel + Log Analytics namespaces budgeted
- [ ] CyberArk evaluation for Phase 3

### Skills / Headcount
- [ ] CISO appointed
- [ ] Head of SOC hired
- [ ] At least 2 Cloud Security Architects on staff
- [ ] At least 4 SOC analysts ready to start Tier 1 operations

---

## 1 — Foundational Azure Setup

### 1.1 Management Group Hierarchy

Create the management group hierarchy:

```bash
# Tenant root → mg-globalsec → 6 regional MGs

az account management-group create --name mg-globalsec --display-name "GlobalSec"

for region in apac emea amer gcc me africa; do
  az account management-group create \
    --name mg-globalsec-${region} \
    --display-name "GlobalSec ${region}" \
    --parent mg-globalsec
done

# Move the GlobalSec subscription under mg-globalsec
az account management-group subscription add \
  --name mg-globalsec --subscription <sub-id>
```

### 1.2 Resource Groups (per region)

```bash
declare -A REGIONS=(
  ["apac"]="southeastasia"
  ["emea"]="westeurope"
  ["amer"]="eastus2"
  ["gcc"]="uaenorth"
  ["me"]="qatarcentral"
  ["africa"]="southafricanorth"
)

for region in "${!REGIONS[@]}"; do
  az_region="${REGIONS[$region]}"
  for rg in agents sentinel keyvault networking; do
    az group create -n rg-globalsec-${rg}-${region} -l ${az_region}
  done
done

# Global control plane (in Middle East)
for rg in orchestration sentinel-global spog keyvault-global; do
  az group create -n rg-globalsec-${rg} -l qatarcentral
done
```

### 1.3 Azure Policy — Resource Location Enforcement

Apply Azure Policy to ensure resources only deploy in approved regions per management group:

```bash
# Example for APAC management group — only allow approved APAC regions
az policy assignment create \
  --name apac-allowed-locations \
  --scope /providers/Microsoft.Management/managementGroups/mg-globalsec-apac \
  --policy "/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c" \
  --params '{"listOfAllowedLocations":{"value":["southeastasia","eastasia","japaneast","australiaeast","koreacentral"]}}'

# Repeat for each regional MG with appropriate locations
```

---

## 2 — Networking (Azure Virtual WAN Hub-and-Spoke)

### 2.1 Create vWAN

```bash
az network vwan create \
  --name vwan-globalsec-prod \
  --resource-group rg-globalsec-networking-me \
  --location qatarcentral \
  --type Standard
```

### 2.2 Regional Hubs

```bash
for region in "${!REGIONS[@]}"; do
  az_region="${REGIONS[$region]}"
  az network vhub create \
    --name vhub-globalsec-${region} \
    --resource-group rg-globalsec-networking-${region} \
    --location ${az_region} \
    --vwan vwan-globalsec-prod \
    --address-prefix 10.${HUB_PREFIX[$region]}.0.0/23
  
  # Azure Firewall Premium per hub
  az network firewall create \
    --name azfw-globalsec-${region} \
    --resource-group rg-globalsec-networking-${region} \
    --tier Premium \
    --vhub vhub-globalsec-${region}
done
```

### 2.3 Private Endpoints

Configure Private Endpoints for all PaaS services to avoid public exposure:
- Key Vault
- Service Bus
- PostgreSQL Flexible Server
- Redis Cache
- Sentinel Log Analytics workspaces

---

## 3 — Identity (Entra ID)

### 3.1 Conditional Access Policies (Baseline)

Apply baseline CA policies via Microsoft Graph PowerShell:

```powershell
# Block legacy authentication
New-MgIdentityConditionalAccessPolicy -BodyParameter @{
  displayName = "GS-CA-001 Block Legacy Auth"
  state = "enabled"
  conditions = @{
    clientAppTypes = @("exchangeActiveSync","other")
    users = @{ includeUsers = @("All") }
  }
  grantControls = @{
    operator = "OR"
    builtInControls = @("block")
  }
}

# Require MFA for all users
New-MgIdentityConditionalAccessPolicy -BodyParameter @{
  displayName = "GS-CA-002 Require MFA All Users"
  state = "enabled"
  conditions = @{
    users = @{ includeUsers = @("All"); excludeGroups = @("<break-glass-group-id>") }
    applications = @{ includeApplications = @("All") }
  }
  grantControls = @{
    operator = "OR"
    builtInControls = @("mfa")
  }
}

# Require compliant device for accessing Microsoft 365
New-MgIdentityConditionalAccessPolicy -BodyParameter @{
  displayName = "GS-CA-003 Require Compliant Device for M365"
  state = "enabled"
  conditions = @{
    users = @{ includeUsers = @("All") }
    applications = @{ includeApplications = @("Office365") }
  }
  grantControls = @{
    operator = "OR"
    builtInControls = @("compliantDevice","mfa")
  }
}
```

### 3.2 Privileged Identity Management

For each privileged role (Global Admin, Privileged Role Admin, Security Admin, etc.):
- Maximum activation duration: **8 hours** (4 hours for Global Admin)
- Require MFA on activation: **Yes**
- Require approval: **Yes for Tier 0 roles**
- Require justification: **Yes**
- Require ticket: **Yes for Tier 0**

### 3.3 Break-Glass Accounts

Create at least 2 break-glass accounts:
- Excluded from all Conditional Access policies (only this group)
- Stored credentials in physical safe
- 256-character random password
- FIDO2 hardware key attached
- Sign-in alerts to CISO + Head of SOC

---

## 4 — Azure Key Vaults (Per Region)

### 4.1 Create Key Vaults

```bash
for region in "${!REGIONS[@]}"; do
  az_region="${REGIONS[$region]}"
  az keyvault create \
    --name kv-globalsec-${region}-prod \
    --resource-group rg-globalsec-keyvault-${region} \
    --location ${az_region} \
    --enable-rbac-authorization true \
    --enabled-for-deployment false \
    --enabled-for-disk-encryption true \
    --enabled-for-template-deployment false \
    --enable-purge-protection true \
    --retention-days 90 \
    --sku premium  # premium for HSM-backed keys
done

# Global Key Vault
az keyvault create \
  --name kv-globalsec-global-prod \
  --resource-group rg-globalsec-keyvault-global \
  --location qatarcentral \
  --enable-rbac-authorization true \
  --enable-purge-protection true \
  --retention-days 90 \
  --sku premium
```

### 4.2 Configure Network Restriction

```bash
# Deny public access; allow only from AKS subnets
az keyvault update --name kv-globalsec-${region}-prod \
  --default-action Deny \
  --bypass AzureServices

# Add Private Endpoint
az network private-endpoint create \
  --name pe-kv-globalsec-${region} \
  --resource-group rg-globalsec-keyvault-${region} \
  --vnet-name vnet-globalsec-${region} \
  --subnet snet-globalsec-pe \
  --private-connection-resource-id $(az keyvault show -n kv-globalsec-${region}-prod --query id -o tsv) \
  --connection-name kv-conn \
  --group-id vault
```

---

## 5 — AKS Clusters (Per Region)

### 5.1 Provision AKS

```bash
for region in "${!REGIONS[@]}"; do
  az_region="${REGIONS[$region]}"
  az aks create \
    --name aks-globalsec-${region}-prod \
    --resource-group rg-globalsec-agents-${region} \
    --location ${az_region} \
    --enable-managed-identity \
    --enable-workload-identity \
    --enable-oidc-issuer \
    --network-plugin azure \
    --enable-azure-rbac \
    --node-count 3 \
    --node-vm-size Standard_D4s_v5 \
    --min-count 3 \
    --max-count 10 \
    --enable-cluster-autoscaler \
    --enable-private-cluster
done
```

### 5.2 Workload Identity Federation

For each agent that needs Azure resources access, create a federated credential:

```bash
# Example for EDR agent
az identity create -n mi-globalsec-edr-${region} -g rg-globalsec-agents-${region}

OIDC_ISSUER=$(az aks show -n aks-globalsec-${region}-prod \
  -g rg-globalsec-agents-${region} \
  --query oidcIssuerProfile.issuerUrl -o tsv)

az identity federated-credential create \
  --name fc-edr-${region} \
  --identity-name mi-globalsec-edr-${region} \
  --resource-group rg-globalsec-agents-${region} \
  --issuer ${OIDC_ISSUER} \
  --subject system:serviceaccount:globalsec:edr-agent

# Grant Key Vault access
KV_ID=$(az keyvault show -n kv-globalsec-${region}-prod --query id -o tsv)
az role assignment create \
  --assignee $(az identity show -n mi-globalsec-edr-${region} -g rg-globalsec-agents-${region} --query principalId -o tsv) \
  --role "Key Vault Secrets User" \
  --scope ${KV_ID}
```

---

## 6 — Microsoft Sentinel

### 6.1 Global Sentinel Workspace

```bash
# Global workspace (in Middle East)
az monitor log-analytics workspace create \
  --name law-globalsec-global-prod \
  --resource-group rg-globalsec-sentinel-global \
  --location qatarcentral \
  --retention-time 90

# Enable Sentinel
az sentinel workspace-setting create \
  --resource-group rg-globalsec-sentinel-global \
  --workspace-name law-globalsec-global-prod
```

### 6.2 Regional Workspaces

```bash
for region in "${!REGIONS[@]}"; do
  az_region="${REGIONS[$region]}"
  az monitor log-analytics workspace create \
    --name law-globalsec-${region}-prod \
    --resource-group rg-globalsec-sentinel-${region} \
    --location ${az_region} \
    --retention-time 90
  az sentinel workspace-setting create \
    --resource-group rg-globalsec-sentinel-${region} \
    --workspace-name law-globalsec-${region}-prod
done
```

### 6.3 Connect Data Sources

In Sentinel UI for each workspace:
- **Microsoft Entra ID** connector
- **Microsoft 365** connector (Office activity, Teams, SharePoint)
- **Microsoft Defender XDR** connector
- **Azure Activity** connector
- **Microsoft Defender for Cloud** connector
- **CrowdStrike Falcon Data Replicator** (for EDR data)

---

## 7 — Microsoft Teams (Chat Interface)

### 7.1 Create the GlobalSec Team

In Teams admin:
1. Create new team: **GlobalSec Security Operations**
2. Add channels per the catalogue in HLD §11.1
3. Create the central SOC channel: `#soc-central`
4. Create regional channels: `#soc-apac`, `#soc-emea`, etc.
5. Create per-agent channels: `#agent-edr`, `#agent-siem`, etc.

### 7.2 Bot Framework Registration

1. **Azure Portal → Create Resource → Azure Bot**
2. Name: `bot-globalsec-chat`
3. Pricing tier: F0 (free) for non-prod, S1 for prod
4. Microsoft App ID: Auto-create
5. Save App ID + password
6. **Channels → Microsoft Teams** → Enable
7. **Configuration → Messaging endpoint:** `https://chat-interface.globalsec.internal/api/messages`

### 7.3 Slash Commands Manifest

Create `manifest.json` for the Teams app:
```json
{
  "manifestVersion": "1.16",
  "id": "globalsec-bot-app-id",
  "name": { "short": "GlobalSec", "full": "GlobalSec Security Operations" },
  "description": {
    "short": "GlobalSec security operations bot",
    "full": "Provides command access to all GlobalSec security agents"
  },
  "bots": [{
    "botId": "<bot-app-id>",
    "scopes": ["personal", "team", "groupchat"],
    "commandLists": [{
      "scopes": ["team", "groupchat"],
      "commands": [
        {"title": "status", "description": "Get agent health and metrics"},
        {"title": "alert list", "description": "List active alerts"},
        {"title": "isolate", "description": "Isolate an endpoint"},
        {"title": "block", "description": "Block IP or domain"},
        {"title": "incident create", "description": "Create incident"}
      ]
    }]
  }]
}
```

Upload via Teams Admin Center → Manage Apps.

---

## 8 — Deploy Phase 1 Agents

### 8.1 Build Container Images

```bash
# Login to Azure Container Registry
az acr login --name globalsecregistry

# Build and push each Phase 1 agent
for agent in entra-id-agent pim-agent edr-agent email-security-agent siem-agent risk-dashboard-agent chat-interface asset-management-agent; do
  docker build -t globalsecregistry.azurecr.io/${agent}:1.0.0 \
    -f agents/${agent}/Dockerfile .
  docker push globalsecregistry.azurecr.io/${agent}:1.0.0
done
```

### 8.2 Deploy via Helm

For each region's AKS cluster:
```bash
kubectl config use-context aks-globalsec-${region}-prod

# Create namespace
kubectl create namespace globalsec

# Deploy regional agents
helm install edr-agent ./charts/edr-agent \
  --namespace globalsec \
  --set region=${region} \
  --set image.tag=1.0.0 \
  --set keyvaultUrl=https://kv-globalsec-${region}-prod.vault.azure.net

helm install email-security-agent ./charts/email-security-agent \
  --namespace globalsec \
  --set region=${region} \
  --set image.tag=1.0.0
```

For global agents, deploy only to `me` (Middle East) cluster:
```bash
kubectl config use-context aks-globalsec-me-prod

helm install entra-id-agent ./charts/entra-id-agent --namespace globalsec --set image.tag=1.0.0
helm install pim-agent ./charts/pim-agent --namespace globalsec --set image.tag=1.0.0
helm install siem-agent ./charts/siem-agent --namespace globalsec --set image.tag=1.0.0
helm install risk-dashboard-agent ./charts/risk-dashboard-agent --namespace globalsec --set image.tag=1.0.0
helm install chat-interface ./charts/chat-interface --namespace globalsec --set image.tag=1.0.0
helm install asset-management-agent ./charts/asset-management-agent --namespace globalsec --set image.tag=1.0.0
```

---

## 9 — Verify Phase 1 Health

```bash
# Check all agents are running
kubectl get pods -n globalsec

# Check agent registration in Paperclip
curl https://paperclip.globalsec.internal/agents | jq

# Verify chat interface
# In Teams: type "/status" in #soc-central — should respond with health summary

# Verify SIEM ingestion
# In Sentinel: Logs blade → run query
# AzureActivity | where TimeGenerated > ago(15m) | take 10
```

---

## 10 — Next Phases

Phase 1 deployment is complete. Continue with:
- **Phase 2** — see [`PHASED-DEPLOYMENT.md`](../deployment-phases/PHASED-DEPLOYMENT.md)

---

*GlobalSec INSTALLATION v1.0 · CONFIDENTIAL*
