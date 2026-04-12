"""
Eye of Horus — Basic Python Threat Processor (Fallback)
Reads raw OSINT messages from Kafka, applies NLP feature engineering,
computes threat scores, and writes results back to MongoDB.

This is a pure Python replacement for the PySpark processor, making it
compatible with Python 3.14 where PySpark wheels are not yet available.
"""

import sys
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from kafka import KafkaConsumer, KafkaProducer
from loguru import logger
from pymongo import MongoClient, UpdateOne

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import kafka as kafka_cfg, mongo as mongo_cfg, threat as threat_cfg

logger.add("logs/processor_basic.log", rotation="10 MB")

class ThreatProcessor:
    def __init__(self):
        self.consumer = KafkaConsumer(
            kafka_cfg.TOPIC_RAW,
            bootstrap_servers=kafka_cfg.BOOTSTRAP_SERVERS,
            group_id="basic-processor-group",
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            auto_offset_reset="earliest"
        )
        self.producer = KafkaProducer(
            bootstrap_servers=kafka_cfg.BOOTSTRAP_SERVERS,
            value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8")
        )
        self.mongo_client = MongoClient(mongo_cfg.URI)
        self.db = self.mongo_client[mongo_cfg.DB_NAME]
        
    def clean_text(self, text):
        if not text: return ""
        text = text.lower()
        import re
        text = re.sub(r"[^a-z0-9\s]", " ", text)
        return re.sub(r"\s+", " ", text).strip()

    def get_keyword_score(self, text):
        if not text: return 0.0
        tokens = text.split()
        if not tokens: return 0.0
        hits = sum(1 for t in tokens if t in threat_cfg.THREAT_KEYWORDS)
        return min(hits / 10.0, 1.0)

    def get_sentiment_score(self, text):
        NEGATIVE_WORDS = {
            "attack", "breach", "hack", "steal", "malicious", "malware",
            "ransomware", "exploit", "leak", "infiltrate", "ddos", "flood",
            "threat", "dangerous", "critical", "vulnerable", "pwned",
            "compromised", "infected", "backdoor", "dump", "stolen"
        }
        if not text: return 0.0
        tokens = set(text.split())
        hits = len(tokens & NEGATIVE_WORDS)
        return min(hits / 8.0, 1.0)

    def process_message(self, env):
        payload = env.get("payload", {})
        post_id = payload.get("post_id")
        if not post_id: return
        
        raw_text = payload.get("text", "")
        clean = self.clean_text(raw_text)
        kw_score = self.get_keyword_score(clean)
        sent_score = self.get_sentiment_score(clean)
        
        extra = payload.get("extra", {})
        vol_score = min(float(extra.get("num_comments", 0)) / 500.0, 1.0)
        trend_score = float(extra.get("upvote_ratio", 0.0))
        
        # In case of CVEs, boost trend base on CVSS map
        if "cvss_score" in extra:
            trend_score = min(float(extra["cvss_score"]) / 10.0, 1.0)
            
        threat_score = (
            threat_cfg.ALPHA * kw_score + 
            threat_cfg.BETA * vol_score + 
            threat_cfg.GAMMA * sent_score + 
            threat_cfg.DELTA * trend_score
        )
        threat_score = round(min(max(threat_score, 0.0), 1.0), 4)
        is_threat = threat_score >= threat_cfg.THRESHOLD

        processed_record = {
            "post_id": post_id,
            "source": payload.get("source"),
            "title": payload.get("title"),
            "url": payload.get("url"),
            "text": raw_text,
            "keyword_score": kw_score,
            "sentiment_score": sent_score,
            "volume_score": vol_score,
            "trend_score": trend_score,
            "threat_score": threat_score,
            "is_threat": is_threat,
            "published_at": payload.get("published_at"),
            "processed_at": datetime.now(timezone.utc).isoformat()
        }

        # 1. Save to MongoDB threat_scores
        self.db[mongo_cfg.COLLECTION_THREATS].update_one(
            {"post_id": post_id},
            {"$set": processed_record},
            upsert=True
        )

        # 2. If threat, forward to Kafka alerts topic
        if is_threat:
            self.producer.send(kafka_cfg.TOPIC_PROCESSED, processed_record)
            
        logger.info(f"Processed: {post_id} | Score: {threat_score:.3f} | Threat: {is_threat}")

    def run(self):
        logger.info("🚀 Basic Python Threat Processor Started")
        while True:
            records = self.consumer.poll(timeout_ms=1000)
            if not records:
                continue
            for tp, messages in records.items():
                for message in messages:
                    try:
                        self.process_message(message.value)
                    except Exception as e:
                        logger.error(f"Error processing message: {e}")

if __name__ == "__main__":
    processor = ThreatProcessor()
    processor.run()
