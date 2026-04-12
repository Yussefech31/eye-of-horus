"""
Eye of Horus — RSS Cyber News Scraper
Polls multiple cybersecurity RSS/Atom feeds and streams
breaking threat news into the Kafka raw-osint topic.

Sources:
    - BleepingComputer
    - The Hacker News
    - CISA US-CERT Alerts
    - KrebsOnSecurity
    - Threatpost
    - CyberScoop
    - Dark Reading

No authentication required.
"""

import sys
import hashlib
import feedparser
import time
import schedule
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from loguru import logger

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scraper.base_scraper import BaseScraper
from config.settings import kafka as kafka_cfg, scraper as scraper_cfg

# ══════════════════════════════════════════════════════════════════════════════
#  Feed Registry — add/remove feeds here only
# ══════════════════════════════════════════════════════════════════════════════
RSS_FEEDS = [
    {
        "name": "bleepingcomputer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "category": "news",
    },
    {
        "name": "thehackernews",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "category": "news",
    },
    {
        "name": "cisa_alerts",
        "url": "https://www.cisa.gov/uscert/ncas/alerts.xml",
        "category": "government",
    },
    {
        "name": "krebsonsecurity",
        "url": "https://krebsonsecurity.com/feed/",
        "category": "investigative",
    },
    {
        "name": "darkreading",
        "url": "https://www.darkreading.com/rss.xml",
        "category": "news",
    },
    {
        "name": "cyberscoop",
        "url": "https://cyberscoop.com/feed/",
        "category": "news",
    },
    {
        "name": "securityweek",
        "url": "https://www.securityweek.com/feed/",
        "category": "news",
    },
    {
        "name": "naked_security",
        "url": "https://nakedsecurity.sophos.com/feed/",
        "category": "vendor",
    },
]


class RssScraper(BaseScraper):
    """
    Polls a registry of cybersecurity RSS/Atom feeds.
    Deduplicates via SHA-256 hash of the article URL.
    Yields one record per article entry.
    """

    @property
    def source_name(self) -> str:
        return "rss"

    def __init__(self, feeds: list[dict] | None = None) -> None:
        self._feeds = feeds or RSS_FEEDS
        self._seen: set[str] = set()   # In-memory dedup cache per run cycle
        logger.info(f"[rss] Initialized with {len(self._feeds)} feeds.")

    # ── Deduplication ─────────────────────────────────────────────────────────

    @staticmethod
    def _url_hash(url: str) -> str:
        return hashlib.sha256(url.encode()).hexdigest()[:16]

    # ── Fetch ─────────────────────────────────────────────────────────────────

    def fetch(self) -> Iterator[dict[str, Any]]:
        """Parse each registered RSS feed and yield raw entry dicts."""
        for feed_meta in self._feeds:
            feed_name = feed_meta["name"]
            feed_url  = feed_meta["url"]

            logger.info(f"[rss] Polling: {feed_name} ({feed_url})")
            try:
                parsed = feedparser.parse(
                    feed_url,
                    agent="EyeOfHorus-OSINT/1.0 (cybersecurity research)",
                    request_headers={"Cache-Control": "no-cache"},
                )

                if parsed.bozo and not parsed.entries:
                    logger.warning(
                        f"[rss] Could not parse {feed_name}: {parsed.bozo_exception}"
                    )
                    continue

                logger.info(
                    f"[rss] {feed_name}: {len(parsed.entries)} entries found."
                )

                for entry in parsed.entries:
                    url = entry.get("link", "")
                    url_hash = self._url_hash(url)

                    # Skip already-seen URLs within this cycle
                    if url_hash in self._seen:
                        continue
                    self._seen.add(url_hash)

                    yield {
                        "entry": entry,
                        "feed_name": feed_name,
                        "feed_category": feed_meta["category"],
                        "url_hash": url_hash,
                    }

            except Exception as exc:
                logger.error(f"[rss] Error fetching {feed_name}: {exc}")
                continue

    # ── Transform ─────────────────────────────────────────────────────────────

    def _transform(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Map a raw feedparser entry to the standard OSINT record schema."""
        entry        = raw["entry"]
        feed_name    = raw["feed_name"]
        url_hash     = raw["url_hash"]

        # ── Parse publication date ───────────────────────────────────────────
        published_at = datetime.now(timezone.utc)  # fallback
        for date_field in ("published_parsed", "updated_parsed", "created_parsed"):
            val = getattr(entry, date_field, None) or entry.get(date_field)
            if val:
                try:
                    published_at = datetime(*val[:6], tzinfo=timezone.utc)
                    break
                except Exception:
                    pass

        # ── Extract text fields ──────────────────────────────────────────────
        title   = entry.get("title", "")
        summary = entry.get("summary", "") or entry.get("description", "")
        url     = entry.get("link", "")
        author  = entry.get("author", feed_name)

        # ── Tags / categories from feed ──────────────────────────────────────
        tags = [
            t.get("term", "") for t in entry.get("tags", [])
            if isinstance(t, dict)
        ]

        return self.build_record(
            post_id=f"rss_{feed_name}_{url_hash}",
            title=title,
            text=f"{title} {summary}",
            author=author,
            url=url,
            published_at=published_at,
            extra={
                "feed_name": feed_name,
                "feed_category": raw["feed_category"],
                "tags": tags,
                "source_type": "rss_article",
            },
        )


# ── Standalone entry point ────────────────────────────────────────────────────
if __name__ == "__main__":
    from kafka.producer import OsintProducer

    logger.add("logs/scraper_rss.log", rotation="10 MB", retention="7 days")

    scraper = RssScraper()

    with OsintProducer() as producer:

        def scrape_and_push():
            # Reset dedup cache each cycle so we re-discover updated articles
            scraper._seen.clear()
            logger.info("━" * 60)
            logger.info("📰 Starting RSS scrape cycle...")
            count = scraper.run(
                callback=lambda record: producer.send(
                    data=record,
                    topic=kafka_cfg.TOPIC_RAW,
                    key="rss",
                )
            )
            logger.info(f"✅ Cycle complete — {count} articles pushed to Kafka.")

        scrape_and_push()
        schedule.every(5).minutes.do(scrape_and_push)
        logger.info("⏱  Polling every 5 minutes. Press Ctrl+C to stop.")

        while True:
            schedule.run_pending()
            time.sleep(1)
