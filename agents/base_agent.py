"""
GlobalSec Base Agent — Cloud-Agnostic (Level 2 Multi-Cloud Capable)
====================================================================

Abstract base class for all GlobalSec agents.

Cloud agnosticism design:
- Agents NEVER directly import azure.*, boto3, or google.cloud.*
- All cloud-coupled concerns flow through the abstractions in `agents.cloud`:
    SecretProvider, EventBus, ObjectStore, IdentityProvider
- The active cloud is selected at runtime via GLOBALSEC_CLOUD_PROVIDER env var
  (azure | aws | gcp | kubernetes)
- The same agent code runs unchanged on Azure / AWS / GCP / bare K8s

Multi-region awareness:
- Each agent reads GLOBALSEC_REGION env var
- Secrets, events, and storage are scoped per region by namespace conventions
- Events are published to regional or global topics based on DEPLOYMENT_MODE

Author: Alvin, Security Architect
"""

from __future__ import annotations

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

from agents.cloud import (
    CloudConfig,
    EventBus,
    IdentityProvider,
    ObjectStore,
    SecretProvider,
    get_provider,
    make_event_bus,
    make_identity_provider,
    make_object_store,
    make_secret_provider,
)


logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","agent":"%(name)s","msg":"%(message)s"}',
)


class GlobalSecBaseAgent(ABC):
    """Cloud-agnostic, multi-region-aware base agent."""

    # Override in subclass
    AGENT_ID: str = "base-agent"
    AGENT_PORT: int = 8000
    DEPLOYMENT_MODE: str = "regional"  # "regional" | "global"

    def __init__(self) -> None:
        self.log = logging.getLogger(self.AGENT_ID)
        self.region = CloudConfig.region()
        self.cloud_provider = get_provider()
        self.paperclip_url = os.getenv("PAPERCLIP_URL", "http://paperclip:9000")

        # Cloud abstraction handles — populated in __aenter__
        self.secrets: SecretProvider | None = None
        self.events: EventBus | None = None
        self.objects: ObjectStore | None = None
        self.identity: IdentityProvider | None = None

        self._running = False

    async def __aenter__(self):
        self.log.info(
            f"Initializing {self.AGENT_ID} on cloud={self.cloud_provider} region={self.region}"
        )
        self.secrets = await make_secret_provider()
        self.events = await make_event_bus()
        self.objects = await make_object_store()
        self.identity = await make_identity_provider()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        for component in (self.events, self.secrets, self.objects):
            if component:
                try:
                    await component.close()
                except Exception as exc:
                    self.log.warning(f"Error closing component: {exc}")

    # ------------------------------------------------------------------
    # Cloud-agnostic helpers
    # ------------------------------------------------------------------

    async def get_secret(self, secret_name: str) -> str:
        """Fetch a secret from the configured secret provider."""
        if not self.secrets:
            raise RuntimeError("Agent not initialized — use 'async with' context")
        return await self.secrets.get(secret_name)

    def _topic_for(self, kind: str = "events") -> str:
        """Build the topic name for this agent's events."""
        ns = CloudConfig.event_bus_namespace()
        scope = "global" if self.DEPLOYMENT_MODE == "global" else self.region
        return f"{ns}-{kind}-{scope}"

    async def publish_event(self, event_type: str, payload: dict[str, Any]) -> None:
        """Publish an event to the regional or global event bus."""
        if not self.events:
            raise RuntimeError("Agent not initialized — use 'async with' context")
        envelope = {
            "source_agent": self.AGENT_ID,
            "event_type": event_type,
            "region": self.region,
            "cloud_provider": self.cloud_provider,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "1.0",
            "payload": payload,
        }
        await self.events.publish(self._topic_for("events"), envelope)
        self.log.info(f"Published {event_type}")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def register_with_paperclip(self) -> None:
        """Register this agent with the regional Paperclip orchestrator."""
        registration = {
            "agent_id": self.AGENT_ID,
            "region": self.region,
            "deployment_mode": self.DEPLOYMENT_MODE,
            "cloud_provider": self.cloud_provider,
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
        return {
            "agent_id": self.AGENT_ID,
            "region": self.region,
            "cloud_provider": self.cloud_provider,
            "status": "running" if self._running else "stopped",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    async def report_metrics_loop(self) -> None:
        while self._running:
            try:
                metrics = await self.collect_metrics()
                await self.publish_event("metrics_update", metrics)
            except Exception as exc:
                self.log.error(f"Metrics reporting failed: {exc}")
            await asyncio.sleep(300)

    async def start(self) -> None:
        self._running = True
        await self.register_with_paperclip()
        loop = asyncio.get_event_loop()
        loop.add_signal_handler(signal.SIGTERM, lambda: setattr(self, "_running", False))
        await asyncio.gather(self.report_metrics_loop(), self.run())

    # ------------------------------------------------------------------
    # Subclass contract
    # ------------------------------------------------------------------

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
