"""
Eye of Horus — Central Configuration Loader
Reads all settings from the .env file and exposes them as
typed Python objects to the rest of the application.
"""

import os
from pathlib import Path
from dotenv import load_dotenv
from loguru import logger

# ── Locate and load .env ──────────────────────────────────────────────────────
_ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
if _ENV_PATH.exists():
    load_dotenv(_ENV_PATH)
    logger.info(f"Loaded environment from {_ENV_PATH}")
else:
    logger.warning(
        f".env file not found at {_ENV_PATH}. "
        "Copy .env.example → .env and fill in your credentials."
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  Kafka Settings
# ═══════════════════════════════════════════════════════════════════════════════
class KafkaConfig:
    BOOTSTRAP_SERVERS: str = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    TOPIC_RAW: str = os.getenv("KAFKA_TOPIC_RAW", "raw-osint")
    TOPIC_PROCESSED: str = os.getenv("KAFKA_TOPIC_PROCESSED", "processed-threats")
    TOPIC_ALERTS: str = os.getenv("KAFKA_TOPIC_ALERTS", "threat-alerts")
    GROUP_ID: str = os.getenv("KAFKA_GROUP_ID", "eye-of-horus-consumers")


# ═══════════════════════════════════════════════════════════════════════════════
#  MongoDB Settings
# ═══════════════════════════════════════════════════════════════════════════════
class MongoConfig:
    URI: str = os.getenv(
        "MONGO_URI", "mongodb://eyeadmin:eyeofhorus2024@localhost:27017/"
    )
    DB_NAME: str = os.getenv("MONGO_DB_NAME", "cyber_intel")
    COLLECTION_RAW: str = os.getenv("MONGO_COLLECTION_RAW", "raw_posts")
    COLLECTION_THREATS: str = os.getenv("MONGO_COLLECTION_THREATS", "threat_scores")
    COLLECTION_ALERTS: str = os.getenv("MONGO_COLLECTION_ALERTS", "alerts")


# ═══════════════════════════════════════════════════════════════════════════════
#  Reddit API Settings
# ═══════════════════════════════════════════════════════════════════════════════
class RedditConfig:
    CLIENT_ID: str = os.getenv("", "")
    CLIENT_SECRET: str = os.getenv("", "")
    USER_AGENT: str = os.getenv(
        "REDDIT_USER_AGENT", "eye-of-horus/1.0 by /u/anonymous"
    )
    SUBREDDITS: list[str] = os.getenv(
        "REDDIT_SUBREDDITS",
        "cybersecurity,hacking,netsec,darknet,privacy,DataBreaches",
    ).split(",")
    POST_LIMIT: int = int(os.getenv("REDDIT_POST_LIMIT", "50"))


# ═══════════════════════════════════════════════════════════════════════════════
#  Threat Scoring Weights
# ═══════════════════════════════════════════════════════════════════════════════
class ThreatConfig:
    # Score = α·frequency + β·volume + γ·sentiment + δ·trend
    ALPHA: float = float(os.getenv("THREAT_ALPHA", "0.3"))   # keyword frequency
    BETA: float = float(os.getenv("THREAT_BETA", "0.2"))     # post volume
    GAMMA: float = float(os.getenv("THREAT_GAMMA", "0.3"))   # negative sentiment
    DELTA: float = float(os.getenv("THREAT_DELTA", "0.2"))   # trend spike
    THRESHOLD: float = float(os.getenv("THREAT_SCORE_THRESHOLD", "0.65"))

    # Suspicious keywords that raise the threat score
    THREAT_KEYWORDS: list[str] = [
        "ddos", "ransomware", "exploit", "attack", "breach", "leak",
        "hack", "botnet", "malware", "phishing", "zero-day", "0day",
        "vulnerability", "cve", "backdoor", "credential", "dump",
        "defacement", "apt", "cyberattack", "stolen", "exposed",
        "anon", "anonymous", "opisis", "ophacktivist",
    ]


# ═══════════════════════════════════════════════════════════════════════════════
#  Scraper General Settings
# ═══════════════════════════════════════════════════════════════════════════════
class ScraperConfig:
    INTERVAL_SECONDS: int = int(os.getenv("SCRAPE_INTERVAL_SECONDS", "60"))


# ── Singleton-style access ────────────────────────────────────────────────────
kafka = KafkaConfig()
mongo = MongoConfig()
reddit = RedditConfig()
threat = ThreatConfig()
scraper = ScraperConfig()
