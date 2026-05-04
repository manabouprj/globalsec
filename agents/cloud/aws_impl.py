"""
AWS implementations of the cloud abstraction interfaces.

Uses aioboto3 for async AWS SDK calls.
Authenticates via IRSA (IAM Roles for Service Accounts) on EKS.
"""

from __future__ import annotations

import json
import os
from typing import Any, AsyncIterator

import aioboto3

from agents.cloud import (
    EventBus,
    IdentityProvider,
    ObjectStore,
    SecretProvider,
)


# ============================================================================
# AWS Secrets Manager
# ============================================================================


class AwsSecretsManagerProvider(SecretProvider):
    def __init__(self, session: aioboto3.Session, region: str) -> None:
        self._session = session
        self._region = region

    @classmethod
    async def create(cls) -> "AwsSecretsManagerProvider":
        region = os.environ.get("AWS_REGION", "us-east-1")
        session = aioboto3.Session()
        return cls(session, region)

    async def get(self, secret_name: str) -> str:
        async with self._session.client("secretsmanager", region_name=self._region) as client:
            resp = await client.get_secret_value(SecretId=secret_name)
            return resp["SecretString"]

    async def list_names(self, prefix: str = "") -> list[str]:
        names = []
        async with self._session.client("secretsmanager", region_name=self._region) as client:
            paginator = client.get_paginator("list_secrets")
            async for page in paginator.paginate():
                for secret in page.get("SecretList", []):
                    if secret["Name"].startswith(prefix):
                        names.append(secret["Name"])
        return names

    async def close(self) -> None:
        # aioboto3 manages client lifecycle within `async with`, nothing to close
        return


# ============================================================================
# AWS SNS + SQS event bus
# ============================================================================


class AwsSnsSqsEventBus(EventBus):
    """SNS topic for fan-out, SQS subscription per consumer."""

    def __init__(self, session: aioboto3.Session, region: str) -> None:
        self._session = session
        self._region = region

    @classmethod
    async def create(cls) -> "AwsSnsSqsEventBus":
        region = os.environ.get("AWS_REGION", "us-east-1")
        session = aioboto3.Session()
        return cls(session, region)

    def _topic_arn(self, topic: str) -> str:
        account = os.environ["AWS_ACCOUNT_ID"]
        return f"arn:aws:sns:{self._region}:{account}:{topic}"

    def _queue_url(self, subscription: str) -> str:
        account = os.environ["AWS_ACCOUNT_ID"]
        return f"https://sqs.{self._region}.amazonaws.com/{account}/{subscription}"

    async def publish(self, topic: str, message: dict[str, Any]) -> None:
        async with self._session.client("sns", region_name=self._region) as sns:
            await sns.publish(
                TopicArn=self._topic_arn(topic),
                Message=json.dumps(message),
            )

    async def subscribe(self, topic: str, subscription: str) -> AsyncIterator[dict[str, Any]]:
        # The queue must already exist and be subscribed to the SNS topic.
        async with self._session.client("sqs", region_name=self._region) as sqs:
            queue_url = self._queue_url(subscription)
            while True:
                resp = await sqs.receive_message(
                    QueueUrl=queue_url,
                    MaxNumberOfMessages=10,
                    WaitTimeSeconds=20,
                )
                for msg in resp.get("Messages", []):
                    try:
                        # SNS-delivered messages are wrapped — unwrap
                        body = json.loads(msg["Body"])
                        if "Message" in body:
                            yield json.loads(body["Message"])
                        else:
                            yield body
                        await sqs.delete_message(
                            QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"]
                        )
                    except Exception:
                        # Leave message in queue for retry
                        pass

    async def close(self) -> None:
        return


# ============================================================================
# AWS S3
# ============================================================================


class S3ObjectStore(ObjectStore):
    def __init__(self, session: aioboto3.Session, region: str) -> None:
        self._session = session
        self._region = region

    @classmethod
    async def create(cls) -> "S3ObjectStore":
        region = os.environ.get("AWS_REGION", "us-east-1")
        session = aioboto3.Session()
        return cls(session, region)

    async def put(self, bucket: str, key: str, data: bytes, content_type: str | None = None) -> None:
        async with self._session.client("s3", region_name=self._region) as s3:
            kwargs: dict[str, Any] = {"Bucket": bucket, "Key": key, "Body": data}
            if content_type:
                kwargs["ContentType"] = content_type
            await s3.put_object(**kwargs)

    async def get(self, bucket: str, key: str) -> bytes:
        async with self._session.client("s3", region_name=self._region) as s3:
            resp = await s3.get_object(Bucket=bucket, Key=key)
            return await resp["Body"].read()

    async def exists(self, bucket: str, key: str) -> bool:
        async with self._session.client("s3", region_name=self._region) as s3:
            try:
                await s3.head_object(Bucket=bucket, Key=key)
                return True
            except Exception:
                return False

    async def close(self) -> None:
        return


# ============================================================================
# AWS IRSA Identity
# ============================================================================


class AwsIRSAIdentity(IdentityProvider):
    """IAM Roles for Service Accounts — EKS workload identity."""

    async def get_token(self, audience: str) -> str:
        # IRSA tokens are auto-refreshed by the EKS pod identity webhook
        token_file = os.environ.get(
            "AWS_WEB_IDENTITY_TOKEN_FILE", "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
        )
        with open(token_file) as f:
            return f.read().strip()

    async def get_principal_id(self) -> str:
        return os.environ.get("AWS_ROLE_ARN", "unknown")
