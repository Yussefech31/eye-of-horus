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

# ── Source-aware scoring weights ──────────────────────────────────────────────
# CVE entries are dry technical text — VADER sentiment and keyword lexicon
# both return near-zero on them. The CVSS score (captured in the volume
# signal) must dominate. Reddit/RSS keep the original balanced weights.
SCORE_WEIGHTS = {
    "nvd_cve": {
        "alpha": 0.10,  # keyword  — CVE prose doesn't match informal threat lexicon
        "beta":  0.60,  # volume   — CVSS score is the authoritative severity signal
        "gamma": 0.10,  # sentiment— technical advisories read as neutral to VADER
        "delta": 0.20,  # trend    — recency/virality still matters
    },
    "alienvault_otx": {
        "alpha": 0.25,
        "beta":  0.35,  # indicator count + subscriber reach carry more weight
        "gamma": 0.20,
        "delta": 0.20,
    },
    "reddit": {
        "alpha": 0.30,
        "beta":  0.20,
        "gamma": 0.30,  # community tone is a genuine signal on Reddit
        "delta": 0.20,
    },
    "rss": {
        "alpha": 0.30,
        "beta":  0.20,
        "gamma": 0.30,
        "delta": 0.20,
    },
    "default": {
        "alpha": 0.30,
        "beta":  0.20,
        "gamma": 0.30,
        "delta": 0.20,
    },
}

# ── CVSS → severity floor mapping ────────────────────────────────────────────
# NIST's own rating must never be overridden downward by the NLP signals.
# These floors guarantee the composite score reaches the correct severity band.
#
#   CVSS ≥ 9.0  →  CRITICAL floor  (score must reach 0.85)
#   CVSS ≥ 7.0  →  HIGH floor      (score must reach 0.65)
#   CVSS ≥ 4.0  →  MEDIUM floor    (score must reach 0.40)
#
CVSS_FLOORS = [
    (9.0, 0.85),   # CRITICAL
    (7.0, 0.65),   # HIGH
    (4.0, 0.40),   # MEDIUM
]


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


def compute_threat_score(
    source: str,
    kw: float,
    vol: float,
    sent: float,
    trend: float,
    cvss_score: float = None,
) -> tuple[float, dict]:
    """
    Compute a composite threat score in [0, 1] using source-aware weights.

    For NVD CVE records, a CVSS-based floor is applied after the weighted
    sum to ensure NIST's severity rating is never overridden downward by
    the NLP signals (which return near-zero on dry technical text).

    Returns:
        (score, weights_used)
    """
    weights = SCORE_WEIGHTS.get(source, SCORE_WEIGHTS["default"])
    score = (
        weights["alpha"] * kw
        + weights["beta"]  * vol
        + weights["gamma"] * sent
        + weights["delta"] * trend
    )

    # ── CVSS floor override (NVD CVE only) ───────────────────────────────────
    # Apply the highest floor whose CVSS threshold is met.
    # This keeps CVSS 9.8 → CRITICAL, CVSS 7.5 → HIGH, CVSS 5.3 → MEDIUM,
    # regardless of how low the NLP signals score the dry advisory text.
    if source == "nvd_cve" and cvss_score is not None:
        for cvss_threshold, score_floor in CVSS_FLOORS:
            if cvss_score >= cvss_threshold:
                score = max(score, score_floor)
                break   # apply only the highest matching floor

    return round(min(max(score, 0.0), 1.0), 4), weights


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
        self.db           = self.mongo_client[mongo_cfg.DB_NAME]
        self.raw_col      = self.db[mongo_cfg.COLLECTION_RAW]
        self.threats_col  = self.db[mongo_cfg.COLLECTION_THREATS]
        self.alerts_col   = self.db[mongo_cfg.COLLECTION_ALERTS]
        logger.info(f"Connected to MongoDB at {mongo_cfg.URI}")
        logger.info("ThreatProcessor initialized.")

    def _score_document(self, doc: dict) -> dict:
        raw_text = doc.get("text", "")
        clean    = clean_text(raw_text)
        kw       = keyword_score(clean)
        sent     = sentiment_score(clean)

        from services.geolocation.geolocation_fallback import process_geolocation
        geo_data     = process_geolocation(doc.get("post_id", "unknown"), raw_text)
        extracted_loc = geo_data.get("nlp_extracted", "Unknown")

        extra = doc.get("extra", {})
        if isinstance(extra, str):
            import ast
            try:
                extra = ast.literal_eval(extra)
            except Exception:
                extra = {}

        vol  = round(min(float(extra.get("num_comments", 0)) / 500.0, 1.0), 4)
        trend = round(float(extra.get("upvote_ratio", 0.0)), 4)

        # ── CVE-specific volume and trend signals ─────────────────────────────
        # For NVD records, num_comments is always 0 and upvote_ratio is absent.
        # Use the normalised CVSS score as both the volume signal (how severe
        # the vulnerability is technically) and the trend signal (recency proxy).
        # This ensures the 60 % beta weight is actually populated for CVE entries.
        cvss_score = None
        if "cvss_score" in extra:
            cvss_score = float(extra["cvss_score"])
            vol   = round(min(cvss_score / 10.0, 1.0), 4)   # volume  = CVSS / 10
            trend = round(min(cvss_score / 10.0, 1.0), 4)   # trend   = CVSS / 10

        source = doc.get("source", "default")
        threat, weights_used = compute_threat_score(
            source, kw, vol, sent, trend, cvss_score
        )
        now = datetime.now(timezone.utc)

        return {
            "post_id":          doc["post_id"],
            "source":           source,
            "title":            doc.get("title"),
            "url":              doc.get("url"),
            "text":             raw_text,
            "keyword_score":    kw,
            "sentiment_score":  sent,
            "volume_score":     vol,
            "trend_score":      trend,
            "cvss_score":       cvss_score,        # stored for analyst transparency
            "threat_score":     threat,
            "scoring_profile":  source,
            "weights_used":     weights_used,
            "is_threat":        threat >= threat_cfg.THRESHOLD,
            "severity":         score_to_severity(threat),
            "published_at":     doc.get("published_at"),
            "processed_at":     now,
            "extracted_location": extracted_loc,
            "geo_data":         geo_data,
        }

    def _persist_batch(self, records: list[dict]) -> None:
        if not records:
            return

        threat_ops = [
            UpdateOne(
                {"post_id": r["post_id"]},
                {"$set": r},
                upsert=True,
            )
            for r in records
        ]
        result = self.threats_col.bulk_write(threat_ops, ordered=False)
        logger.info(
            f"threat_scores: {result.upserted_count} new | "
            f"{result.modified_count} updated | batch={len(records)}"
        )

        alert_ops = []
        for r in records:
            if r["is_threat"]:
                alert_ops.append(UpdateOne(
                    {"post_id": r["post_id"]},
                    {
                        "$set": {
                            "post_id":         r["post_id"],
                            "source":          r["source"],
                            "title":           r["title"],
                            "url":             r["url"],
                            "threat_score":    r["threat_score"],
                            "severity":        r["severity"],
                            "keyword_score":   r["keyword_score"],
                            "sentiment_score": r["sentiment_score"],
                            "cvss_score":      r["cvss_score"],
                            "acknowledged":    False,
                            "created_at":      r["processed_at"],
                            "geo_data":        r["geo_data"],
                        },
                        "$setOnInsert": {"first_seen_at": r["processed_at"]},
                    },
                    upsert=True,
                ))
        if alert_ops:
            ar = self.alerts_col.bulk_write(alert_ops, ordered=False)
            logger.info(
                f"alerts: {ar.upserted_count} new | {ar.modified_count} updated"
            )

    def process_all(self) -> int:
        """Process all raw_posts that have not been scored yet."""
        scored_ids = {doc["post_id"] for doc in self.threats_col.find({}, {"post_id": 1})}
        query  = {"post_id": {"$nin": list(scored_ids)}} if scored_ids else {}
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
        logger.info("ThreatProcessor started — polling MongoDB for new posts")
        try:
            while True:
                n = self.process_all()
                if n > 0:
                    logger.success(f"Processed {n} new records")
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