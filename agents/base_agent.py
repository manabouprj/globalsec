"""
GlobalSec Base Agent
====================

Abstract base class for all GlobalSec agents. Inherit from this and implement
`run()`, `collect_metrics()`, and `process_event()`.

Multi-region awareness:
- Each agent reads GLOBALSEC_REGION env var (apac/emea/amer/gcc/africa/me/global)
- Secrets are fetched from the region-appropriate Azure Key Vault
- Events are published to regional or global Service Bus topics

Author: Alvin, Security Architect
"""

import asyncio
import json
import logging
import os
import signal
import sys
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

import aiohttp
from azure.identity.aio import DefaultAzureCredential
from azure.keyvault.secrets.aio import SecretClient
from azure.servicebus.aio import ServiceBusClient
from azure.servicebus import ServiceBusMessage

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","agent":"%(name)s","msg":"%(message)s"}',
)


class GlobalSecBaseAgent(ABC):
    """Multi-region-aware base agent for the GlobalSec platform."""

    # Override in subclass
    AGENT_ID: str = "base-agent"
    AGENT_PORT: int = 8000
    DEPLOYMENT_MODE: str = "regional"  # "regional" or "global"

    def __init__(self) -> None:
        self.log = logging.getLogger(self.AGENT_ID)
        self.region = os.getenv("GLOBALSEC_REGION", "global")
        self.paperclip_url = os.getenv("PAPERCLIP_URL", "http://paperclip:9000")
        self.servicebus_namespace = os.getenv("AZURE_SERVICEBUS_NAMESPACE")
        self.keyvault_url = self._derive_keyvault_url()
        self._credential: DefaultAzureCredential | None = None
        self._secret_client: SecretClient | None = None
        self._sb_client: ServiceBusClient | None = None
        self._running = False

    def _derive_keyvault_url(self) -> str:
        """Each region has its own Key Vault. Global agents use the global vault."""
        if self.DEPLOYMENT_MODE == "global" or self.region == "global":
            kv_name = "kv-globalsec-global-prod"
        else:
            kv_name = f"kv-globalsec-{self.region}-prod"
        return os.getenv("AZURE_KEYVAULT_URL", f"https://{kv_name}.vault.azure.net")

    async def __aenter__(self):
        self._credential = DefaultAzureCredential()
        self._secret_client = SecretClient(
            vault_url=self.keyvault_url, credential=self._credential
        )
        self._sb_client = ServiceBusClient(
            fully_qualified_namespace=self.servicebus_namespace,
            credential=self._credential,
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._sb_client:
            await self._sb_client.close()
        if self._secret_client:
            await self._secret_client.close()
        if self._credential:
            await self._credential.close()

    async def get_secret(self, secret_name: str) -> str:
        """Fetch a secret from the region-appropriate Azure Key Vault."""
        if not self._secret_client:
            raise RuntimeError("Agent not initialized — use 'async with' context")
        secret = await self._secret_client.get_secret(secret_name)
        return secret.value

    async def publish_event(self, event_type: str, payload: dict[str, Any]) -> None:
        """Publish an event to the regional or global Service Bus topic."""
        topic_name = (
            "globalsec-events-global"
            if self.DEPLOYMENT_MODE == "global"
            else f"globalsec-events-{self.region}"
        )
        event = {
            "source_agent": self.AGENT_ID,
            "event_type": event_type,
            "region": self.region,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "1.0",
            "payload": payload,
        }
        async with self._sb_client.get_topic_sender(topic_name) as sender:
            msg = ServiceBusMessage(json.dumps(event))
            await sender.send_messages(msg)
        self.log.info(f"Published {event_type} to {topic_name}")

    async def register_with_paperclip(self) -> None:
        """Register this agent with the regional Paperclip orchestrator."""
        registration = {
            "agent_id": self.AGENT_ID,
            "region": self.region,
            "deployment_mode": self.DEPLOYMENT_MODE,
            "port": self.AGENT_PORT,
            "status": "running",
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
        for attempt in range(3):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        f"{self.paperclip_url}/agents/register",
                        json=registration,
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as resp:
                        if resp.status == 200:
                            self.log.info("Registered with Paperclip")
                            return
                        self.log.warning(f"Registration returned {resp.status}")
            except Exception as exc:
                self.log.error(f"Registration attempt {attempt + 1} failed: {exc}")
                await asyncio.sleep(2**attempt)
        self.log.error("Failed to register with Paperclip after 3 attempts")

    async def health_check(self) -> dict[str, Any]:
        """Standard health response."""
        return {
            "agent_id": self.AGENT_ID,
            "region": self.region,
            "status": "running" if self._running else "stopped",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    async def report_metrics_loop(self) -> None:
        """Continuously report metrics every 5 minutes."""
        while self._running:
            try:
                metrics = await self.collect_metrics()
                await self.publish_event("metrics_update", metrics)
            except Exception as exc:
                self.log.error(f"Metrics reporting failed: {exc}")
            await asyncio.sleep(300)

    async def start(self) -> None:
        """Bootstrap: register, start metrics loop, run main loop."""
        self._running = True
        await self.register_with_paperclip()
        loop = asyncio.get_event_loop()
        loop.add_signal_handler(signal.SIGTERM, lambda: setattr(self, "_running", False))
        await asyncio.gather(self.report_metrics_loop(), self.run())

    @abstractmethod
    async def run(self) -> None:
        """Main agent loop — implement in subclass."""
        raise NotImplementedError

    @abstractmethod
    async def collect_metrics(self) -> dict[str, Any]:
        """Return current KPI dict — implement in subclass."""
        raise NotImplementedError

    @abstractmethod
    async def process_event(self, event: dict[str, Any]) -> None:
        """Handle inbound events — implement in subclass."""
        raise NotImplementedError


def run_agent(agent_class: type[GlobalSecBaseAgent]) -> None:
    """Helper to run an agent from `__main__`."""
    async def _runner():
        async with agent_class() as agent:
            await agent.start()

    try:
        asyncio.run(_runner())
    except KeyboardInterrupt:
        sys.exit(0)
