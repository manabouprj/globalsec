"""
Azure implementations of the cloud abstraction interfaces.

Each implementation is created via `await ClassName.create()` so that async setup
(credential acquisition, client construction) happens during creation rather than
in `__init__`.
"""

from __future__ import annotations

import os
from typing import Any, AsyncIterator

from azure.identity.aio import DefaultAzureCredential
from azure.keyvault.secrets.aio import SecretClient
from azure.servicebus.aio import ServiceBusClient
from azure.servicebus import ServiceBusMessage
from azure.storage.blob.aio import BlobServiceClient

from agents.cloud import (
    EventBus,
    IdentityProvider,
    ObjectStore,
    SecretProvider,
    CloudConfig,
)
import json


# ============================================================================
# Azure Key Vault
# ============================================================================


class AzureKeyVaultSecretProvider(SecretProvider):
    def __init__(self, client: SecretClient, credential: DefaultAzureCredential) -> None:
        self._client = client
        self._credential = credential

    @classmethod
    async def create(cls) -> "AzureKeyVaultSecretProvider":
        vault_url = os.environ["AZURE_KEYVAULT_URL"]
        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=vault_url, credential=credential)
        return cls(client, credential)

    async def get(self, secret_name: str) -> str:
        secret = await self._client.get_secret(secret_name)
        return secret.value

    async def list_names(self, prefix: str = "") -> list[str]:
        names = []
        async for prop in self._client.list_properties_of_secrets():
            if prop.name.startswith(prefix):
                names.append(prop.name)
        return names

    async def close(self) -> None:
        await self._client.close()
        await self._credential.close()


# ============================================================================
# Azure Service Bus
# ============================================================================


class AzureServiceBusEventBus(EventBus):
    def __init__(self, client: ServiceBusClient, credential: DefaultAzureCredential) -> None:
        self._client = client
        self._credential = credential

    @classmethod
    async def create(cls) -> "AzureServiceBusEventBus":
        ns = os.environ["AZURE_SERVICEBUS_NAMESPACE"]
        credential = DefaultAzureCredential()
        client = ServiceBusClient(fully_qualified_namespace=ns, credential=credential)
        return cls(client, credential)

    async def publish(self, topic: str, message: dict[str, Any]) -> None:
        async with self._client.get_topic_sender(topic) as sender:
            await sender.send_messages(ServiceBusMessage(json.dumps(message)))

    async def subscribe(self, topic: str, subscription: str) -> AsyncIterator[dict[str, Any]]:
        async with self._client.get_subscription_receiver(
            topic_name=topic, subscription_name=subscription
        ) as receiver:
            async for msg in receiver:
                try:
                    yield json.loads(str(msg))
                    await receiver.complete_message(msg)
                except Exception:
                    await receiver.abandon_message(msg)

    async def close(self) -> None:
        await self._client.close()
        await self._credential.close()


# ============================================================================
# Azure Blob Storage
# ============================================================================


class AzureBlobObjectStore(ObjectStore):
    def __init__(self, client: BlobServiceClient, credential: DefaultAzureCredential) -> None:
        self._client = client
        self._credential = credential

    @classmethod
    async def create(cls) -> "AzureBlobObjectStore":
        account_url = os.environ["AZURE_STORAGE_ACCOUNT_URL"]
        credential = DefaultAzureCredential()
        client = BlobServiceClient(account_url=account_url, credential=credential)
        return cls(client, credential)

    async def put(self, bucket: str, key: str, data: bytes, content_type: str | None = None) -> None:
        from azure.storage.blob import ContentSettings
        cs = ContentSettings(content_type=content_type) if content_type else None
        blob = self._client.get_blob_client(container=bucket, blob=key)
        await blob.upload_blob(data, overwrite=True, content_settings=cs)

    async def get(self, bucket: str, key: str) -> bytes:
        blob = self._client.get_blob_client(container=bucket, blob=key)
        downloader = await blob.download_blob()
        return await downloader.readall()

    async def exists(self, bucket: str, key: str) -> bool:
        blob = self._client.get_blob_client(container=bucket, blob=key)
        return await blob.exists()

    async def close(self) -> None:
        await self._client.close()
        await self._credential.close()


# ============================================================================
# Azure Managed Identity
# ============================================================================


class AzureManagedIdentity(IdentityProvider):
    def __init__(self) -> None:
        self._credential = DefaultAzureCredential()
        self._principal_id_cache: str | None = None

    async def get_token(self, audience: str) -> str:
        # audience example: 'https://vault.azure.net/.default'
        token = await self._credential.get_token(audience)
        return token.token

    async def get_principal_id(self) -> str:
        if self._principal_id_cache:
            return self._principal_id_cache
        # In Azure, the principal id comes from the federated token claims.
        # Read from IMDS or env var injected by AKS workload identity.
        self._principal_id_cache = os.environ.get("AZURE_CLIENT_ID", "unknown")
        return self._principal_id_cache
