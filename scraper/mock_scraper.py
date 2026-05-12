"""
Eye of Horus — Mock Test Generator
Generates realistic, high-severity mock cyber events and injects them
into the Kafka pipeline to test downstream processing and alerting.
"""

import sys
import time
import uuid
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from loguru import logger

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scraper.base_scraper import BaseScraper
from broker.producer import OsintProducer
from config.settings import kafka as kafka_cfg


class MockScraper(BaseScraper):
    """Generates synthetic cybersecurity events for testing the alert pipeline."""

    @property
    def source_name(self) -> str:
        return "mock_generator"

    def fetch(self) -> Iterator[dict[str, Any]]:
        """Yield a batch of synthetic high-severity mock events."""
        logger.info("[mock] Generating 5 synthetic threat events...")

        events = [
            {
                "title": "🚨 MASSIVE RANSOMWARE DEPLOYMENT DETECTED",
                "text": "CRITICAL ALERT: LockBit ransomware payload detected across 50+ internal hosts. Systems are being actively compromised, encrypted, and data is being stolen. Dangerous malware exploit in progress.",
                "type": "ransomware",
                "cvss": 10.0,
                "comments": 1200,
            },
            {
                "title": "🚨 MULTIPLE SUSPICIOUS LOGINS (BRUTE FORCE)",
                "text": "WARNING: Unauthorized backdoor access detected on primary domain controller. Critical breach of administrative credentials. Attackers are attempting to infiltrate the network.",
                "type": "unauthorized_access",
                "cvss": 9.5,
                "comments": 850,
            },
            {
                "title": "🚨 VOLUMETRIC DDOS ATTACK IN PROGRESS",
                "text": "CRITICAL: Malicious flood of traffic hitting the external firewall. Distributed Denial of Service (DDoS) attack is overwhelming the gateway. Infrastructure is vulnerable and under severe threat.",
                "type": "ddos",
                "cvss": 8.5,
                "comments": 920,
            },
            {
                "title": "🚨 ZERO-DAY EXPLOIT ACTIVELY EXPLOITED",
                "text": "URGENT: New critical zero-day exploit discovered in edge router firmware. Attackers are injecting malicious payloads and establishing command-and-control. Immediate patch required.",
                "type": "zero_day",
                "cvss": 10.0,
                "comments": 2500,
            },
            {
                "title": "🚨 MASSIVE DATA LEAK FOUND ON DARK WEB",
                "text": "CRITICAL: Database dump containing 5 million customer records found on a dark web forum. The stolen data includes passwords and PII. This is a severe breach of security.",
                "type": "data_leak",
                "cvss": 9.0,
                "comments": 1500,
            }
        ]

        for i, event in enumerate(events):
            # Generate realistic fake IPs
            src_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            
            raw_event = {
                "id": f"MOCK-{uuid.uuid4().hex[:8].upper()}",
                "title": event["title"],
                "description": event["text"],
                "author": "MockTestSystem",
                "url": f"https://mock-soc-alert.local/event/{i+1}",
                "created_utc": time.time(),
                "threat_type": event["type"],
                "source_ip": src_ip,
                "cvss": event["cvss"],
                "comments": event["comments"]
            }
            yield raw_event

    def _transform(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Convert the raw mock event into the standard OSINT record schema."""
        return self.build_record(
            post_id=raw["id"],
            title=raw["title"],
            text=raw["description"],
            author=raw["author"],
            url=raw["url"],
            published_at=datetime.fromtimestamp(raw["created_utc"], tz=timezone.utc),
            extra={
                "source_type": "mock_alert",
                "threat_type": raw["threat_type"],
                "source_ip": raw["source_ip"],
                "cvss_score": raw["cvss"],
                "num_comments": raw["comments"],
                "upvote_ratio": 1.0,
            },
        )


if __name__ == "__main__":
    logger.add("logs/mock_scraper.log", rotation="10 MB")
    scraper = MockScraper()

    with OsintProducer() as producer:
        logger.info("━" * 60)
        logger.info("🧪 Starting CONTINUOUS MOCK MODE Injection... (Press Ctrl+C to stop)")
        
        try:
            while True:
                count = scraper.run(
                    callback=lambda record: producer.send(
                        data=record,
                        topic=kafka_cfg.TOPIC_RAW,
                        key="mock",
                    )
                )
                logger.info(f"✅ Injected {count} fake events. Waiting 5 seconds before next wave...")
                time.sleep(5)
        except KeyboardInterrupt:
            logger.info("🛑 Mock injection stopped by user.")
