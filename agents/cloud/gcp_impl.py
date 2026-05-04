"""
GCP implementations of the cloud abstraction interfaces.

Uses google-cloud-* libraries with Workload Identity for authentication.
"""

from __future__ import annotations

import json
import os
from typing import Any, AsyncIterator

from agents.cloud import (
    EventBus,
    IdentityProvider,
    ObjectStore,
    SecretProvider,
)


class GcpSecretManagerProvider(SecretProvider):
    def __init__(self, project_id: str) -> None:
        from google.cloud import secretmanager_v1
        self._client = secretmanager_v1.SecretManagerServiceAsyncClient()
        self._project_id = project_id

    @classmethod
    async def create(cls) -> "GcpSecretManagerProvider":
        project_id = os.environ["GCP_PROJECT_ID"]
        return cls(project_id)

    async def get(self, secret_name: str) -> str:
        name = f"projects/{self._project_id}/secrets/{secret_name}/versions/latest"
        response = await self._client.access_secret_version(request={"name": name})
        return response.payload.data.decode("UTF-8")

    async def list_names(self, prefix: str = "") -> list[str]:
        parent = f"projects/{self._project_id}"
        names = []
        async for secret in await self._client.list_secrets(request={"parent": parent}):
            short_name = secret.name.split("/")[-1]
            if short_name.startswith(prefix):
                names.append(short_name)
        return names

    async def close(self) -> None:
        await self._client.transport.close()


class GcpPubSubEventBus(EventBus):
    def __init__(self, project_id: str) -> None:
        from google.cloud import pubsub_v1
        self._publisher = pubsub_v1.PublisherClient()
        self._subscriber = pubsub_v1.SubscriberClient()
        self._project_id = project_id

    @classmethod
    async def create(cls) -> "GcpPubSubEventBus":
        project_id = os.environ["GCP_PROJECT_ID"]
        return cls(project_id)

    async def publish(self, topic: str, message: dict[str, Any]) -> None:
        topic_path = self._publisher.topic_path(self._project_id, topic)
        future = self._publisher.publish(topic_path, json.dumps(message).encode())
        future.result()

    async def subscribe(self, topic: str, subscription: str) -> AsyncIterator[dict[str, Any]]:
        sub_path = self._subscriber.subscription_path(self._project_id, subscription)
        while True:
            response = self._subscriber.pull(
                request={"subscription": sub_path, "max_messages": 10}, timeout=20.0
            )
            ack_ids = []
            for received in response.received_messages:
                try:
                    yield json.loads(received.message.data.decode())
                    ack_ids.append(received.ack_id)
                except Exception:
                    pass
            if ack_ids:
                self._subscriber.acknowledge(
                    request={"subscription": sub_path, "ack_ids": ack_ids}
                )

    async def close(self) -> None:
        self._publisher.transport.close()
        self._subscriber.transport.close()


class GcsObjectStore(ObjectStore):
    def __init__(self) -> None:
        from google.cloud import storage
        self._client = storage.Client()

    @classmethod
    async def create(cls) -> "GcsObjectStore":
        return cls()

    async def put(self, bucket: str, key: str, data: bytes, content_type: str | None = None) -> None:
        b = self._client.bucket(bucket)
        blob = b.blob(key)
        blob.upload_from_string(data, content_type=content_type)

    async def get(self, bucket: str, key: str) -> bytes:
        b = self._client.bucket(bucket)
        blob = b.blob(key)
        return blob.download_as_bytes()

    async def exists(self, bucket: str, key: str) -> bool:
        b = self._client.bucket(bucket)
        return b.blob(key).exists()

    async def close(self) -> None:
        return


class GcpWorkloadIdentity(IdentityProvider):
    async def get_token(self, audience: str) -> str:
        from google.auth import default
        from google.auth.transport.requests import Request
        creds, _ = default()
        creds.refresh(Request())
        return creds.token

    async def get_principal_id(self) -> str:
        return os.environ.get("GCP_SERVICE_ACCOUNT", "unknown")
