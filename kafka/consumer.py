"""
Eye of Horus — Kafka Consumer → MongoDB Persister
Reads messages from the raw-osint topic and writes them to MongoDB.
Acts as the bridge between the streaming layer and the storage layer.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from kafka import KafkaConsumer
from kafka.errors import KafkaError
from loguru import logger
from pymongo import MongoClient, UpdateOne
from pymongo.errors import BulkWriteError, PyMongoError
from tenacity import retry, stop_after_attempt, wait_exponential

# ── Project root on path ──────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import kafka as kafka_cfg, mongo as mongo_cfg

logger.add("logs/consumer_mongodb.log", rotation="10 MB", retention="7 days")


class MongoConsumer:
    """
    Kafka consumer that reads from raw-osint and bulk-upserts
    records into MongoDB's raw_posts collection.
    """

    BATCH_SIZE = 100        # Number of messages per MongoDB bulk write
    POLL_TIMEOUT_MS = 1000  # How long to wait for messages each poll cycle

    def __init__(self) -> None:
        self._consumer = self._build_consumer()
        self._mongo_client = self._build_mongo()
        self._collection = (
            self._mongo_client[mongo_cfg.DB_NAME][mongo_cfg.COLLECTION_RAW]
        )
        logger.info("MongoConsumer initialized and ready.")

    # ── Connections ───────────────────────────────────────────────────────────

    @retry(stop=stop_after_attempt(5), wait=wait_exponential(min=2, max=30))
    def _build_consumer(self) -> KafkaConsumer:
        return KafkaConsumer(
            kafka_cfg.TOPIC_RAW,
            bootstrap_servers=kafka_cfg.BOOTSTRAP_SERVERS,
            group_id=kafka_cfg.GROUP_ID,
            auto_offset_reset="earliest",
            enable_auto_commit=False,       # Manual commit after successful write
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            session_timeout_ms=30000,
            heartbeat_interval_ms=10000,
            max_poll_records=self.BATCH_SIZE,
        )

    @retry(stop=stop_after_attempt(5), wait=wait_exponential(min=2, max=30))
    def _build_mongo(self) -> MongoClient:
        client = MongoClient(mongo_cfg.URI, serverSelectionTimeoutMS=5000)
        client.admin.command("ping")  # Fail fast if unreachable
        logger.info(f"Connected to MongoDB at {mongo_cfg.URI}")
        return client

    # ── Core Loop ─────────────────────────────────────────────────────────────

    def run(self) -> None:
        """Start the consume → persist loop. Runs indefinitely."""
        logger.info(
            f"Consuming from topic: {kafka_cfg.TOPIC_RAW} | "
            f"Group: {kafka_cfg.GROUP_ID}"
        )
        try:
            while True:
                records = self._consumer.poll(timeout_ms=self.POLL_TIMEOUT_MS)
                if not records:
                    continue

                # Flatten all partition records into a single batch
                messages = [
                    msg.value
                    for partition_records in records.values()
                    for msg in partition_records
                ]

                if messages:
                    self._persist_batch(messages)
                    self._consumer.commit()  # Commit offsets only after successful write

        except KeyboardInterrupt:
            logger.info("Shutting down MongoConsumer...")
        finally:
            self._consumer.close()
            self._mongo_client.close()
            logger.info("Connections closed.")

    # ── Persistence ───────────────────────────────────────────────────────────

    def _persist_batch(self, envelopes: list[dict]) -> None:
        """
        Bulk-upsert a batch of Kafka envelope messages into MongoDB.
        Uses post_id as the upsert key to prevent duplicates.
        """
        operations = []
        for envelope in envelopes:
            payload = envelope.get("payload", {})
            post_id = payload.get("post_id")
            if not post_id:
                logger.warning("Skipping envelope with no post_id.")
                continue

            operations.append(
                UpdateOne(
                    filter={"post_id": post_id},
                    update={
                        "$set": payload,
                        "$setOnInsert": {
                            "first_seen_at": datetime.now(timezone.utc).isoformat()
                        },
                    },
                    upsert=True,
                )
            )

        if not operations:
            return

        try:
            result = self._collection.bulk_write(operations, ordered=False)
            logger.info(
                f"MongoDB write: {result.upserted_count} new | "
                f"{result.modified_count} updated | batch={len(operations)}"
            )
        except BulkWriteError as bwe:
            logger.error(f"Bulk write partial failure: {bwe.details}")
        except PyMongoError as exc:
            logger.error(f"MongoDB error: {exc}")
            raise  # Bubble up so Kafka offset is NOT committed


if __name__ == "__main__":
    consumer = MongoConsumer()
    consumer.run()
