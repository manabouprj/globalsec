"""
GlobalSec EDR Agent — CrowdStrike Falcon Enterprise
====================================================

Regional agent (one instance per region: apac, emea, amer, gcc, africa, me).
Polls Falcon for detections, publishes alerts to regional Service Bus topic.

Required secrets in regional Key Vault:
- crowdstrike-client-id
- crowdstrike-client-secret
- crowdstrike-base-url
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

import aiohttp

from agents.base_agent import GlobalSecBaseAgent, run_agent


class EDRAgent(GlobalSecBaseAgent):
    AGENT_ID = "edr-agent"
    AGENT_PORT = 8010
    DEPLOYMENT_MODE = "regional"

    def __init__(self) -> None:
        super().__init__()
        self._access_token: str | None = None
        self._token_expires: datetime | None = None
        self._client_id: str | None = None
        self._client_secret: str | None = None
        self._base_url: str | None = None
        self._detection_count_24h = 0
        self._severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    async def _load_credentials(self) -> None:
        self._client_id = await self.get_secret("crowdstrike-client-id")
        self._client_secret = await self.get_secret("crowdstrike-client-secret")
        self._base_url = await self.get_secret("crowdstrike-base-url")

    async def _get_token(self) -> str:
        if self._access_token and self._token_expires and datetime.now(timezone.utc) < self._token_expires:
            return self._access_token
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self._base_url}/oauth2/token",
                data={
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()
                self._access_token = data["access_token"]
                self._token_expires = datetime.now(timezone.utc) + timedelta(
                    seconds=data["expires_in"] - 60
                )
                return self._access_token

    async def _poll_detections(self) -> list[dict[str, Any]]:
        token = await self._get_token()
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self._base_url}/detects/queries/detects/v1",
                headers={"Authorization": f"Bearer {token}"},
                params={"filter": "status:'new'", "limit": 100, "sort": "created_timestamp.desc"},
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()
                detection_ids = data.get("resources", [])
                if not detection_ids:
                    return []

            async with session.post(
                f"{self._base_url}/detects/entities/summaries/GET/v1",
                headers={"Authorization": f"Bearer {token}"},
                json={"ids": detection_ids},
            ) as resp:
                resp.raise_for_status()
                return (await resp.json()).get("resources", [])

    async def _process_detection(self, detection: dict[str, Any]) -> None:
        severity = detection.get("max_severity_displayname", "medium").lower()
        self._severity_counts[severity] = self._severity_counts.get(severity, 0) + 1
        self._detection_count_24h += 1

        if severity in {"critical", "high"}:
            await self.publish_event("critical_endpoint_alert", {
                "detection_id": detection.get("detection_id"),
                "hostname": detection.get("device", {}).get("hostname"),
                "user": detection.get("behaviors", [{}])[0].get("user_name"),
                "severity": severity,
                "tactic": detection.get("behaviors", [{}])[0].get("tactic"),
                "technique": detection.get("behaviors", [{}])[0].get("technique"),
                "description": detection.get("behaviors", [{}])[0].get("description"),
            })
            self.log.info(f"Published critical_endpoint_alert for {detection.get('detection_id')}")

    async def run(self) -> None:
        await self._load_credentials()
        self.log.info(f"EDR Agent started in region {self.region}")
        while self._running:
            try:
                detections = await self._poll_detections()
                for d in detections:
                    await self._process_detection(d)
            except Exception as exc:
                self.log.error(f"Polling failed: {exc}")
            await asyncio.sleep(60)

    async def collect_metrics(self) -> dict[str, Any]:
        return {
            "total_detections_24h": self._detection_count_24h,
            "by_severity": dict(self._severity_counts),
            "region": self.region,
            "agent": self.AGENT_ID,
        }

    async def process_event(self, event: dict[str, Any]) -> None:
        if event["event_type"] == "isolate_endpoint":
            hostname = event["payload"].get("hostname")
            self.log.info(f"Isolation requested for {hostname}")
            # Implement RTR isolation call here


if __name__ == "__main__":
    run_agent(EDRAgent)
