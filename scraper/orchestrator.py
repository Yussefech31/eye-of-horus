"""
Eye of Horus — Scraper Orchestrator
Launches all scrapers concurrently in separate threads and funnels
all collected OSINT records into the Kafka raw-osint topic.

Usage:
    python scraper/orchestrator.py

Scrapers run on their own schedules:
    - RSS feeds    → every 5 minutes
    - Reddit       → every 60 seconds
    - AlienVault   → every 60 minutes
    - NVD CVE      → every 6 hours
"""

import sys
import time
import threading
import schedule
import os
from pathlib import Path
from datetime import datetime, timezone

from loguru import logger
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from kafka.producer import OsintProducer
from config.settings import kafka as kafka_cfg

from scraper.reddit_scraper import RedditScraper
from scraper.rss_scraper    import RssScraper
from scraper.otx_scraper    import OtxScraper
from scraper.nvd_scraper    import NvdScraper

# ══════════════════════════════════════════════════════════════════════════════
#  Logging setup
# ══════════════════════════════════════════════════════════════════════════════

logger.add(
    "logs/orchestrator.log",
    rotation="20 MB",
    retention="14 days",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {thread.name} | {message}",
)


# ══════════════════════════════════════════════════════════════════════════════
#  Scraper Worker
# ══════════════════════════════════════════════════════════════════════════════

class ScraperWorker(threading.Thread):
    """
    Runs a single scraper on a background thread with its own schedule.
    Each worker gets a shared Kafka producer reference (thread-safe send).
    """

    def __init__(
        self,
        name: str,
        scraper,
        producer: OsintProducer,
        interval_seconds: int,
        kafka_key: str,
    ) -> None:
        super().__init__(name=f"Worker-{name}", daemon=True)
        self._scraper          = scraper
        self._producer         = producer
        self._interval_seconds = interval_seconds
        self._kafka_key        = kafka_key
        self._stats            = {"total": 0, "cycles": 0, "errors": 0}
        self._lock             = threading.Lock()

    def _push(self, record: dict) -> None:
        """Thread-safe Kafka send."""
        self._producer.send(
            data=record,
            topic=kafka_cfg.TOPIC_RAW,
            key=self._kafka_key,
        )

    def _run_cycle(self) -> None:
        """Execute one scraping cycle."""
        logger.info(f"[{self.name}] ▶ Starting cycle #{self._stats['cycles'] + 1}")
        try:
            count = self._scraper.run(callback=self._push)
            with self._lock:
                self._stats["total"]  += count
                self._stats["cycles"] += 1
            logger.success(
                f"[{self.name}] ✅ Cycle done — {count} records | "
                f"Total: {self._stats['total']}"
            )
        except Exception as exc:
            with self._lock:
                self._stats["errors"] += 1
            logger.error(f"[{self.name}] ❌ Cycle failed: {exc}")

    def run(self) -> None:
        """Thread entry point: run immediately, then on schedule."""
        self._run_cycle()

        sched = schedule.Scheduler()
        sched.every(self._interval_seconds).seconds.do(self._run_cycle)

        while True:
            sched.run_pending()
            time.sleep(1)

    @property
    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)


# ══════════════════════════════════════════════════════════════════════════════
#  Stats Reporter
# ══════════════════════════════════════════════════════════════════════════════

def stats_reporter(workers: list[ScraperWorker]) -> None:
    """Print a summary table every 10 minutes."""
    while True:
        time.sleep(600)
        logger.info("=" * 60)
        logger.info(f"  EYE OF HORUS — Pipeline Stats @ {datetime.now(timezone.utc).strftime('%H:%M UTC')}")
        logger.info("=" * 60)
        for worker in workers:
            s = worker.stats
            logger.info(
                f"  {worker.name:<22} | cycles={s['cycles']:<5} | "
                f"records={s['total']:<7} | errors={s['errors']}"
            )
        logger.info("=" * 60)


# ══════════════════════════════════════════════════════════════════════════════
#  Main Entry Point
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    logger.info("👁️  Eye of Horus — Scraper Orchestrator starting...")

    # ── Initialize shared Kafka producer ──────────────────────────────────────
    producer = OsintProducer()

    # ── Build scrapers (skip OTX if no key) ───────────────────────────────────
    otx_api_key = os.getenv("OTX_API_KEY", "")

    scrapers_config = [
        {
            "name":     "RSS-News",
            "scraper":  RssScraper(),
            "interval": 5 * 60,         # every 5 minutes
            "key":      "rss",
        },
        {
            "name":     "Reddit",
            "scraper":  RedditScraper(),
            "interval": 60,             # every 60 seconds
            "key":      "reddit",
        },
        {
            "name":     "NVD-CVE",
            "scraper":  NvdScraper(hours_back=24, min_cvss=0.0),
            "interval": 6 * 60 * 60,   # every 6 hours
            "key":      "nvd",
        },
    ]

    # AlienVault OTX — only if API key is provided
    if otx_api_key and otx_api_key != "your_otx_api_key_here":
        try:
            scrapers_config.append({
                "name":     "AlienVault-OTX",
                "scraper":  OtxScraper(api_key=otx_api_key, hours_back=24),
                "interval": 60 * 60,   # every 60 minutes
                "key":      "otx",
            })
        except ValueError as e:
            logger.warning(f"OTX skipped: {e}")
    else:
        logger.warning(
            "⚠️  OTX_API_KEY not set — AlienVault OTX scraper disabled. "
            "Get a free key at https://otx.alienvault.com"
        )

    # ── Start workers ─────────────────────────────────────────────────────────
    workers = []
    for cfg in scrapers_config:
        worker = ScraperWorker(
            name=cfg["name"],
            scraper=cfg["scraper"],
            producer=producer,
            interval_seconds=cfg["interval"],
            kafka_key=cfg["key"],
        )
        workers.append(worker)
        worker.start()
        logger.info(
            f"  ✅ {cfg['name']} worker started "
            f"(interval: {cfg['interval']}s)"
        )
        time.sleep(2)  # Stagger startup to avoid hammering APIs simultaneously

    # ── Start stats reporter ──────────────────────────────────────────────────
    stats_thread = threading.Thread(
        target=stats_reporter, args=(workers,), daemon=True, name="StatsReporter"
    )
    stats_thread.start()

    logger.info("")
    logger.info("🚀 All workers active. Press Ctrl+C to stop.")
    logger.info(f"   Active sources: {[w.name for w in workers]}")
    logger.info("")

    # ── Keep main thread alive ────────────────────────────────────────────────
    try:
        while True:
            # Check that all daemon workers are still alive
            for worker in workers:
                if not worker.is_alive():
                    logger.error(f"❌ Worker {worker.name} died unexpectedly!")
            time.sleep(15)
    except KeyboardInterrupt:
        logger.info("🛑 Shutdown signal received. Flushing Kafka producer...")
        producer.close()
        logger.info("👋 Eye of Horus orchestrator stopped.")


if __name__ == "__main__":
    main()
