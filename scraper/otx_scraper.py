"""
Eye of Horus — AlienVault OTX Threat Intelligence Scraper
Pulls structured Indicator of Compromise (IoC) pulse data
from AlienVault Open Threat Exchange and streams it to Kafka.

Key data:
    - Threat campaigns (Pulses) with tags and TLP
    - IoC type: IP, domain, URL, file hash, CVE
    - Adversary groupings and attack techniques (ATT&CK)

Free account: https://otx.alienvault.com (no credit card)
API docs: https://otx.alienvault.com/api
"""

import sys
import time
import schedule
import requests
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Iterator

from loguru import logger
from tenacity import retry, stop_after_attempt, wait_exponential

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scraper.base_scraper import BaseScraper
from config.settings import kafka as kafka_cfg

# ══════════════════════════════════════════════════════════════════════════════
#  OTX API Client
# ══════════════════════════════════════════════════════════════════════════════

OTX_BASE_URL   = "https://otx.alienvault.com/api/v1"
OTX_API_KEY    = None   # Injected from settings at runtime


class OtxApiClient:
    """Thin wrapper around the OTX REST API."""

    def __init__(self, api_key: str) -> None:
        self._session = requests.Session()
        self._session.headers.update({
            "X-OTX-API-KEY": api_key,
            "Content-Type": "application/json",
            "User-Agent": "EyeOfHorus-OSINT/1.0",
        })

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=15))
    def get(self, endpoint: str, params: dict | None = None) -> dict:
        url = f"{OTX_BASE_URL}{endpoint}"
        response = self._session.get(url, params=params, timeout=15)
        response.raise_for_status()
        return response.json()

    def get_subscribed_pulses(self, modified_since: datetime) -> list[dict]:
        """Return all pulses modified since the given datetime."""
        pulses = []
        endpoint = "/pulses/subscribed"
        params = {
            "modified_since": modified_since.strftime("%Y-%m-%dT%H:%M:%S"),
            "limit": 20,
            "page": 1,
        }

        while True:
            data = self.get(endpoint, params=params)
            results = data.get("results", [])
            pulses.extend(results)

            if not data.get("next"):
                break
            params["page"] += 1

            # Respect rate limit (free tier: ~10 req/min)
            time.sleep(1)

        return pulses

    def get_recent_pulses(self, hours_back: int = 24) -> list[dict]:
        """Shortcut: get pulses from the last N hours."""
        since = datetime.now(timezone.utc) - timedelta(hours=hours_back)
        return self.get_subscribed_pulses(modified_since=since)


# ══════════════════════════════════════════════════════════════════════════════
#  AlienVault OTX Scraper
# ══════════════════════════════════════════════════════════════════════════════

class OtxScraper(BaseScraper):
    """
    Fetches threat intelligence Pulses from AlienVault OTX.
    Each Pulse becomes one OSINT record in our pipeline.

    A Pulse represents a threat campaign and contains:
      - Title & description of the threat
      - IoC indicators (IPs, domains, hashes, CVEs)
      - ATT&CK tactics & techniques
      - Tags and TLP classification
    """

    @property
    def source_name(self) -> str:
        return "alienvault_otx"

    def __init__(self, api_key: str, hours_back: int = 24) -> None:
        if not api_key or api_key == "your_otx_api_key_here":
            raise ValueError(
                "OTX_API_KEY is not set. "
                "Get a free key at https://otx.alienvault.com/api"
            )
        self._client    = OtxApiClient(api_key)
        self._hours_back = hours_back
        logger.info(f"[otx] Initialized. Looking back {hours_back}h.")

    # ── Fetch ─────────────────────────────────────────────────────────────────

    def fetch(self) -> Iterator[dict[str, Any]]:
        """Fetch recent OTX pulses and yield raw pulse dicts."""
        logger.info(f"[otx] Fetching pulses (last {self._hours_back}h)...")
        try:
            pulses = self._client.get_recent_pulses(hours_back=self._hours_back)
            logger.info(f"[otx] {len(pulses)} pulse(s) fetched.")
            for pulse in pulses:
                yield pulse
        except requests.HTTPError as e:
            logger.error(f"[otx] API error: {e}")
        except Exception as exc:
            logger.error(f"[otx] Unexpected error: {exc}")

    # ── Transform ─────────────────────────────────────────────────────────────

    def _transform(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Map an OTX Pulse to the standard OSINT record schema."""

        # ── Parse date ───────────────────────────────────────────────────────
        published_at = datetime.now(timezone.utc)
        for date_field in ("created", "modified"):
            val = raw.get(date_field)
            if val:
                try:
                    published_at = datetime.fromisoformat(
                        val.replace("Z", "+00:00")
                    )
                    break
                except Exception:
                    pass

        # ── Extract IoC summary ───────────────────────────────────────────────
        indicators     = raw.get("indicators", [])
        ioc_types      = list({i.get("type", "") for i in indicators})
        ioc_count      = len(indicators)
        cve_refs       = [
            i.get("indicator", "")
            for i in indicators
            if i.get("type", "").upper() == "CVE"
        ]
        malware_families = raw.get("malware_families", [])
        attack_ids       = [
            a.get("id", "")
            for a in raw.get("attack_ids", [])
        ]

        # ── Build description text for NLP ───────────────────────────────────
        description = raw.get("description", "") or ""
        tags        = raw.get("tags", [])
        text_body   = f"{raw.get('name', '')} {description} {' '.join(tags)}"

        return self.build_record(
            post_id=f"otx_{raw.get('id', '')}",
            title=raw.get("name", "Unnamed Pulse"),
            text=text_body,
            author=raw.get("author_name", "alienvault"),
            url=f"https://otx.alienvault.com/pulse/{raw.get('id', '')}",
            published_at=published_at,
            extra={
                "pulse_id":         raw.get("id"),
                "tlp":              raw.get("tlp", "white"),
                "adversary":        raw.get("adversary", ""),
                "targeted_countries": raw.get("targeted_countries", []),
                "industries":       raw.get("industries", []),
                "attack_ids":       attack_ids,
                "malware_families": malware_families,
                "ioc_count":        ioc_count,
                "ioc_types":        ioc_types,
                "cve_refs":         cve_refs,
                "tags":             tags,
                "source_type":      "threat_pulse",
            },
        )


# ── Standalone entry point ────────────────────────────────────────────────────
if __name__ == "__main__":
    import os
    from dotenv import load_dotenv
    from kafka.producer import OsintProducer

    load_dotenv()
    logger.add("logs/scraper_otx.log", rotation="10 MB", retention="7 days")

    api_key = os.getenv("OTX_API_KEY", "")
    scraper = OtxScraper(api_key=api_key, hours_back=24)

    with OsintProducer() as producer:

        def scrape_and_push():
            logger.info("━" * 60)
            logger.info("🛡️  Starting AlienVault OTX scrape cycle...")
            count = scraper.run(
                callback=lambda record: producer.send(
                    data=record,
                    topic=kafka_cfg.TOPIC_RAW,
                    key="otx",
                )
            )
            logger.info(f"✅ Cycle complete — {count} pulses pushed to Kafka.")

        scrape_and_push()
        schedule.every(1).hours.do(scrape_and_push)
        logger.info("⏱  Polling hourly. Press Ctrl+C to stop.")

        while True:
            schedule.run_pending()
            time.sleep(1)
