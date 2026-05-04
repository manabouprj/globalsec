"""
GlobalSec — Cloud Abstraction Layer
====================================

Provides cloud-agnostic interfaces for the four cloud-coupled concerns:

    1. SecretProvider    — secret storage (Azure Key Vault / AWS Secrets Mgr / Vault)
    2. EventBus          — async messaging (Azure Service Bus / Kafka / AWS SNS+SQS)
    3. ObjectStore       — blob storage (Azure Blob / S3 / GCS)
    4. IdentityProvider  — workload identity (Managed Identity / IRSA / Workload ID)

Concrete implementations live in `agents/cloud/<provider>/`. The active provider is
selected at runtime via the GLOBALSEC_CLOUD_PROVIDER environment variable.

Supported values:
    - "azure"  (default)
    - "aws"
    - "gcp"
    - "kubernetes" (cloud-neutral — uses Vault + Kafka + MinIO + K8s ServiceAccounts)

Design principle: agents NEVER import azure.*, boto3, or google.cloud.* directly.
They consume these abstractions only.

Author: Alvin, Security Architect
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import Any, AsyncIterator


# ============================================================================
# Interfaces
# ============================================================================


class SecretProvider(ABC):
    """Abstract secret store. Implementations: Azure KV, AWS SM, HashiCorp Vault, GCP Secret Mgr."""

    @abstractmethod
    async def get(self, secret_name: str) -> str:
        """Return secret value. Raise KeyError if absent."""

    @abstractmethod
    async def list_names(self, prefix: str = "") -> list[str]:
        """List secret names, optionally filtered by prefix."""

    @abstractmethod
    async def close(self) -> None:
        """Release any held resources."""


class EventBus(ABC):
    """Abstract pub/sub. Implementations: Azure Service Bus, Kafka, AWS SNS+SQS, GCP Pub/Sub."""

    @abstractmethod
    async def publish(self, topic: str, message: dict[str, Any]) -> None:
        """Publish message to topic."""

    @abstractmethod
    async def subscribe(
        self, topic: str, subscription: str
    ) -> AsyncIterator[dict[str, Any]]:
        """Yield messages from subscription. Caller iterates with `async for`."""

    @abstractmethod
    async def close(self) -> None:
        """Release any held resources."""


class ObjectStore(ABC):
    """Abstract blob storage. Implementations: Azure Blob, S3, GCS, MinIO."""

    @abstractmethod
    async def put(self, bucket: str, key: str, data: bytes, content_type: str | None = None) -> None:
        """Store object."""

    @abstractmethod
    async def get(self, bucket: str, key: str) -> bytes:
        """Retrieve object."""

    @abstractmethod
    async def exists(self, bucket: str, key: str) -> bool:
        """Check object existence."""

    @abstractmethod
    async def close(self) -> None:
        """Release any held resources."""


class IdentityProvider(ABC):
    """Abstract workload identity. Used to obtain credentials for cloud APIs.

    Note: this is for the workload's *own* identity (so the agent can authenticate
    to its cloud resources). It is NOT for end-user identity — that is Entra/Okta/etc.,
    which is a domain-level concern handled by the Entra ID agent.
    """

    @abstractmethod
    async def get_token(self, audience: str) -> str:
        """Return a token suitable for `audience` (e.g. 'https://vault.azure.net')."""

    @abstractmethod
    async def get_principal_id(self) -> str:
        """Return the workload's principal/identity ID."""


# ============================================================================
# Provider Factory
# ============================================================================


def get_provider() -> str:
    """Read GLOBALSEC_CLOUD_PROVIDER from env. Default: 'azure'."""
    return os.getenv("GLOBALSEC_CLOUD_PROVIDER", "azure").lower()


async def make_secret_provider() -> SecretProvider:
    """Factory: instantiate the configured secret provider."""
    provider = get_provider()
    if provider == "azure":
        from agents.cloud.azure_impl import AzureKeyVaultSecretProvider
        return await AzureKeyVaultSecretProvider.create()
    elif provider == "aws":
        from agents.cloud.aws_impl import AwsSecretsManagerProvider
        return await AwsSecretsManagerProvider.create()
    elif provider == "gcp":
        from agents.cloud.gcp_impl import GcpSecretManagerProvider
        return await GcpSecretManagerProvider.create()
    elif provider == "kubernetes":
        from agents.cloud.k8s_impl import HashiCorpVaultProvider
        return await HashiCorpVaultProvider.create()
    raise ValueError(f"Unknown cloud provider: {provider}")


async def make_event_bus() -> EventBus:
    """Factory: instantiate the configured event bus."""
    provider = get_provider()
    if provider == "azure":
        from agents.cloud.azure_impl import AzureServiceBusEventBus
        return await AzureServiceBusEventBus.create()
    elif provider == "aws":
        from agents.cloud.aws_impl import AwsSnsSqsEventBus
        return await AwsSnsSqsEventBus.create()
    elif provider == "gcp":
        from agents.cloud.gcp_impl import GcpPubSubEventBus
        return await GcpPubSubEventBus.create()
    elif provider == "kubernetes":
        from agents.cloud.k8s_impl import KafkaEventBus
        return await KafkaEventBus.create()
    raise ValueError(f"Unknown cloud provider: {provider}")


async def make_object_store() -> ObjectStore:
    """Factory: instantiate the configured object store."""
    provider = get_provider()
    if provider == "azure":
        from agents.cloud.azure_impl import AzureBlobObjectStore
        return await AzureBlobObjectStore.create()
    elif provider == "aws":
        from agents.cloud.aws_impl import S3ObjectStore
        return await S3ObjectStore.create()
    elif provider == "gcp":
        from agents.cloud.gcp_impl import GcsObjectStore
        return await GcsObjectStore.create()
    elif provider == "kubernetes":
        from agents.cloud.k8s_impl import MinIOObjectStore
        return await MinIOObjectStore.create()
    raise ValueError(f"Unknown cloud provider: {provider}")


async def make_identity_provider() -> IdentityProvider:
    """Factory: instantiate the configured workload identity provider."""
    provider = get_provider()
    if provider == "azure":
        from agents.cloud.azure_impl import AzureManagedIdentity
        return AzureManagedIdentity()
    elif provider == "aws":
        from agents.cloud.aws_impl import AwsIRSAIdentity
        return AwsIRSAIdentity()
    elif provider == "gcp":
        from agents.cloud.gcp_impl import GcpWorkloadIdentity
        return GcpWorkloadIdentity()
    elif provider == "kubernetes":
        from agents.cloud.k8s_impl import K8sServiceAccountIdentity
        return K8sServiceAccountIdentity()
    raise ValueError(f"Unknown cloud provider: {provider}")


# ============================================================================
# Configuration helpers — cloud-neutral env vars consumed by all implementations
# ============================================================================


class CloudConfig:
    """Cloud-neutral configuration read from environment."""

    @staticmethod
    def secret_namespace() -> str:
        """Logical bucket/path for secrets, e.g. 'globalsec-apac-prod'."""
        return os.getenv("GLOBALSEC_SECRET_NAMESPACE", "globalsec")

    @staticmethod
    def event_bus_namespace() -> str:
        """Logical namespace for event topics."""
        return os.getenv("GLOBALSEC_EVENT_NAMESPACE", "globalsec")

    @staticmethod
    def object_store_bucket() -> str:
        """Default bucket for reports, evidence, etc."""
        return os.getenv("GLOBALSEC_OBJECT_BUCKET", "globalsec-artifacts")

    @staticmethod
    def region() -> str:
        return os.getenv("GLOBALSEC_REGION", "global")

    @staticmethod
    def deployment_mode() -> str:
        return os.getenv("GLOBALSEC_DEPLOYMENT_MODE", "regional")
