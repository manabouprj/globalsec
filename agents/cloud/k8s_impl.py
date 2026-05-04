"""
Cloud-neutral Kubernetes-only implementations.

Used when the platform must run on bare Kubernetes (on-prem, OpenShift, etc.) with
no cloud provider dependencies.

- Secrets:    HashiCorp Vault
- Events:     Apache Kafka
- Objects:    MinIO (S3-compatible)
- Identity:   Kubernetes ServiceAccount tokens (projected volume)
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


# ============================================================================
# HashiCorp Vault
# ============================================================================


class HashiCorpVaultProvider(SecretProvider):
    def __init__(self, vault_addr: str, token: str, path_prefix: str = "secret/data/globalsec") -> None:
        import aiohttp
        self._addr = vault_addr
        self._token = token
        self._prefix = path_prefix
        self._session: aiohttp.ClientSession | None = None

    @classmethod
    async def create(cls) -> "HashiCorpVaultProvider":
        import aiohttp
        addr = os.environ["VAULT_ADDR"]
        # Use Kubernetes auth method
        sa_token = open("/var/run/secrets/kubernetes.io/serviceaccount/token").read().strip()
        role = os.environ["VAULT_ROLE"]
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{addr}/v1/auth/kubernetes/login",
                json={"role": role, "jwt": sa_token},
            ) as resp:
                data = await resp.json()
                vault_token = data["auth"]["client_token"]
        instance = cls(addr, vault_token)
        instance._session = aiohttp.ClientSession()
        return instance

    async def get(self, secret_name: str) -> str:
        async with self._session.get(
            f"{self._addr}/v1/{self._prefix}/{secret_name}",
            headers={"X-Vault-Token": self._token},
        ) as resp:
            data = await resp.json()
            return data["data"]["data"]["value"]

    async def list_names(self, prefix: str = "") -> list[str]:
        async with self._session.request(
            "LIST",
            f"{self._addr}/v1/{self._prefix}",
            headers={"X-Vault-Token": self._token},
        ) as resp:
            data = await resp.json()
            keys = data.get("data", {}).get("keys", [])
            return [k for k in keys if k.startswith(prefix)]

    async def close(self) -> None:
        if self._session:
            await self._session.close()


# ============================================================================
# Apache Kafka
# ============================================================================


class KafkaEventBus(EventBus):
    def __init__(self, bootstrap: str) -> None:
        self._bootstrap = bootstrap
        self._producer = None

    @classmethod
    async def create(cls) -> "KafkaEventBus":
        from aiokafka import AIOKafkaProducer
        bootstrap = os.environ["KAFKA_BOOTSTRAP_SERVERS"]
        instance = cls(bootstrap)
        instance._producer = AIOKafkaProducer(bootstrap_servers=bootstrap)
        await instance._producer.start()
        return instance

    async def publish(self, topic: str, message: dict[str, Any]) -> None:
        await self._producer.send_and_wait(topic, json.dumps(message).encode())

    async def subscribe(self, topic: str, subscription: str) -> AsyncIterator[dict[str, Any]]:
        from aiokafka import AIOKafkaConsumer
        consumer = AIOKafkaConsumer(
            topic,
            bootstrap_servers=self._bootstrap,
            group_id=subscription,
            auto_offset_reset="earliest",
        )
        await consumer.start()
        try:
            async for msg in consumer:
                try:
                    yield json.loads(msg.value.decode())
                except Exception:
                    continue
        finally:
            await consumer.stop()

    async def close(self) -> None:
        if self._producer:
            await self._producer.stop()


# ============================================================================
# MinIO (S3-compatible)
# ============================================================================


class MinIOObjectStore(ObjectStore):
    def __init__(self, endpoint: str, access_key: str, secret_key: str, secure: bool = True) -> None:
        from miniopy_async import Minio
        self._client = Minio(endpoint, access_key=access_key, secret_key=secret_key, secure=secure)

    @classmethod
    async def create(cls) -> "MinIOObjectStore":
        endpoint = os.environ["MINIO_ENDPOINT"]
        access_key = os.environ["MINIO_ACCESS_KEY"]
        secret_key = os.environ["MINIO_SECRET_KEY"]
        secure = os.environ.get("MINIO_SECURE", "true").lower() == "true"
        return cls(endpoint, access_key, secret_key, secure)

    async def put(self, bucket: str, key: str, data: bytes, content_type: str | None = None) -> None:
        from io import BytesIO
        await self._client.put_object(
            bucket, key, BytesIO(data), len(data), content_type=content_type or "application/octet-stream"
        )

    async def get(self, bucket: str, key: str) -> bytes:
        resp = await self._client.get_object(bucket, key)
        try:
            return await resp.read()
        finally:
            resp.close()
            resp.release_conn()

    async def exists(self, bucket: str, key: str) -> bool:
        try:
            await self._client.stat_object(bucket, key)
            return True
        except Exception:
            return False

    async def close(self) -> None:
        return


# ============================================================================
# Kubernetes ServiceAccount Identity
# ============================================================================


class K8sServiceAccountIdentity(IdentityProvider):
    """ServiceAccount token from projected volume."""

    TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"

    async def get_token(self, audience: str) -> str:
        # Standard SA token (not audience-bound). For audience-bound, use a
        # projected service account token volume with a specific audience.
        with open(self.TOKEN_PATH) as f:
            return f.read().strip()

    async def get_principal_id(self) -> str:
        return os.environ.get("K8S_SERVICE_ACCOUNT", "unknown")
