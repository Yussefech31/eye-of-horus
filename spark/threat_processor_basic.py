"""
Eye of Horus — Pure Python Threat Processor
Reads raw OSINT posts from MongoDB, applies NLP feature engineering,
computes threat scores, and writes results to MongoDB.

This is the primary processor — runs natively on Python 3.12+ without
any Spark, Java, or Kafka consumer dependency.

Pipeline:
    MongoDB (raw_posts)
        → Text Cleaning
        → Keyword Frequency Scoring
        → Sentiment Analysis
        → Threat Score Computation
        → MongoDB (threat_scores)
        → Alert if score > threshold → MongoDB (alerts)
"""

import sys
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from loguru import logger
from pymongo import MongoClient, UpdateOne

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import mongo as mongo_cfg, threat as threat_cfg

logger.add("logs/processor_basic.log", rotation="10 MB", retention="7 days")

# ══════════════════════════════════════════════════════════════════════════════
#  NLP Functions
# ══════════════════════════════════════════════════════════════════════════════

NEGATIVE_WORDS = {
    "attack", "breach", "hack", "steal", "malicious", "malware",
    "ransomware", "exploit", "leak", "infiltrate", "ddos", "flood",
    "threat", "dangerous", "critical", "vulnerable", "pwned",
    "compromised", "infected", "backdoor", "dump", "stolen",
}


def clean_text(text: str) -> str:
    if not text:
        return ""
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def keyword_score(text: str) -> float:
    if not text:
        return 0.0
    tokens = text.split()
    if not tokens:
        return 0.0
    hits = sum(1 for t in tokens if t in threat_cfg.THREAT_KEYWORDS)
    return round(min(hits / 10.0, 1.0), 4)


def sentiment_score(text: str) -> float:
    if not text:
        return 0.0
    tokens = set(text.split())
    hits = len(tokens & NEGATIVE_WORDS)
    return round(min(hits / 8.0, 1.0), 4)


def compute_threat_score(kw: float, vol: float, sent: float, trend: float) -> float:
    score = (
        threat_cfg.ALPHA * kw
        + threat_cfg.BETA * vol
        + threat_cfg.GAMMA * sent
        + threat_cfg.DELTA * trend
    )
    return round(min(max(score, 0.0), 1.0), 4)


def score_to_severity(score: float) -> str:
    if score >= 0.85:
        return "CRITICAL"
    elif score >= 0.65:
        return "HIGH"
    elif score >= 0.40:
        return "MEDIUM"
    return "LOW"


# ══════════════════════════════════════════════════════════════════════════════
#  Threat Processor — reads from MongoDB raw_posts
# ══════════════════════════════════════════════════════════════════════════════

class ThreatProcessor:
    BATCH_SIZE = 100

    def __init__(self):
        self.mongo_client = MongoClient(mongo_cfg.URI, serverSelectionTimeoutMS=5000)
        self.db = self.mongo_client[mongo_cfg.DB_NAME]
        self.raw_col = self.db[mongo_cfg.COLLECTION_RAW]
        self.threats_col = self.db[mongo_cfg.COLLECTION_THREATS]
        self.alerts_col = self.db[mongo_cfg.COLLECTION_ALERTS]
        logger.info(f"Connected to MongoDB at {mongo_cfg.URI}")
        logger.info("ThreatProcessor initialized.")

    def _score_document(self, doc: dict) -> dict:
        raw_text = doc.get("text", "")
        clean = clean_text(raw_text)
        kw = keyword_score(clean)
        sent = sentiment_score(clean)

        extra = doc.get("extra", {})
        if isinstance(extra, str):
            import ast
            try: extra = ast.literal_eval(extra)
            except: extra = {}

        vol = round(min(float(extra.get("num_comments", 0)) / 500.0, 1.0), 4)
        trend = round(float(extra.get("upvote_ratio", 0.0)), 4)
        if "cvss_score" in extra:
            trend = round(min(float(extra["cvss_score"]) / 10.0, 1.0), 4)

        threat = compute_threat_score(kw, vol, sent, trend)
        now = datetime.now(timezone.utc)

        return {
            "post_id": doc["post_id"],
            "source": doc.get("source"),
            "title": doc.get("title"),
            "url": doc.get("url"),
            "text": raw_text,
            "keyword_score": kw,
            "sentiment_score": sent,
            "volume_score": vol,
            "trend_score": trend,
            "threat_score": threat,
            "is_threat": threat >= threat_cfg.THRESHOLD,
            "severity": score_to_severity(threat),
            "published_at": doc.get("published_at"),
            "processed_at": now,
        }

    def _persist_batch(self, records: list[dict]) -> None:
        if not records:
            return
        threat_ops = [UpdateOne({"post_id": r["post_id"]}, {"$set": r}, upsert=True) for r in records]
        result = self.threats_col.bulk_write(threat_ops, ordered=False)
        logger.info(f"threat_scores: {result.upserted_count} new | {result.modified_count} updated | batch={len(records)}")

        alert_ops = []
        for r in records:
            if r["is_threat"]:
                alert_ops.append(UpdateOne(
                    {"post_id": r["post_id"]},
                    {"$set": {
                        "post_id": r["post_id"], "source": r["source"], "title": r["title"],
                        "url": r["url"], "threat_score": r["threat_score"], "severity": r["severity"],
                        "keyword_score": r["keyword_score"], "sentiment_score": r["sentiment_score"],
                        "acknowledged": False, "created_at": r["processed_at"],
                    }, "$setOnInsert": {"first_seen_at": r["processed_at"]}},
                    upsert=True,
                ))
        if alert_ops:
            ar = self.alerts_col.bulk_write(alert_ops, ordered=False)
            logger.info(f"alerts: {ar.upserted_count} new | {ar.modified_count} updated")

    def process_all(self) -> int:
        """Process all raw_posts that haven't been scored yet."""
        scored_ids = set()
        for doc in self.threats_col.find({}, {"post_id": 1}):
            scored_ids.add(doc["post_id"])

        query = {"post_id": {"$nin": list(scored_ids)}} if scored_ids else {}
        cursor = self.raw_col.find(query)
        total = 0
        batch = []

        for doc in cursor:
            try:
                record = self._score_document(doc)
                batch.append(record)
                total += 1
                if len(batch) >= self.BATCH_SIZE:
                    self._persist_batch(batch)
                    batch = []
            except Exception as e:
                logger.error(f"Error scoring {doc.get('post_id')}: {e}")

        if batch:
            self._persist_batch(batch)

        return total

    def run(self, poll_interval: int = 30) -> None:
        """Continuously poll for new raw_posts and score them."""
        logger.info("🚀 ThreatProcessor started — polling MongoDB for new posts")
        try:
            while True:
                n = self.process_all()
                if n > 0:
                    logger.success(f"✅ Processed {n} new records")
                else:
                    logger.debug("No new records to process")
                time.sleep(poll_interval)
        except KeyboardInterrupt:
            logger.info("Shutting down ThreatProcessor...")
        finally:
            self.mongo_client.close()
            logger.info("Connections closed.")


if __name__ == "__main__":
    processor = ThreatProcessor()
    processor.run()
