"""
Eye of Horus — Kafka Producer
Wraps the kafka-python KafkaProducer with serialization,
retry logic, and structured logging.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from kafka import KafkaProducer
from kafka.errors import KafkaError
from loguru import logger
from tenacity import retry, stop_after_attempt, wait_exponential

# Add root to path so config is importable regardless of cwd
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import kafka as kafka_cfg


class OsintProducer:
    """
    Reusable Kafka producer for the Eye-of-Horus OSINT pipeline.

    Usage:
        producer = OsintProducer()
        producer.send(topic="raw-osint", data={"text": "...", "source": "reddit"})
        producer.close()
    """

    def __init__(self) -> None:
        self._producer = self._connect()
        logger.info(
            f"OsintProducer connected to {kafka_cfg.BOOTSTRAP_SERVERS}"
        )

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        reraise=True,
    )
    def _connect(self) -> KafkaProducer:
        return KafkaProducer(
            bootstrap_servers=kafka_cfg.BOOTSTRAP_SERVERS,
            value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
            key_serializer=lambda k: k.encode("utf-8") if k else None,
            acks="all",                     # Wait for all replicas to acknowledge
            retries=5,
            max_in_flight_requests_per_connection=1,  # Preserve ordering
            compression_type="gzip",
            batch_size=16384,
            linger_ms=10,
        )

    def _build_envelope(self, data: dict[str, Any], topic: str) -> dict[str, Any]:
        """Wrap a raw payload in a standard envelope with metadata."""
        return {
            "envelope_id": str(uuid.uuid4()),
            "topic": topic,
            "ingested_at": datetime.now(timezone.utc).isoformat(),
            "payload": data,
        }

    def send(
        self,
        data: dict[str, Any],
        topic: str | None = None,
        key: str | None = None,
    ) -> None:
        """
        Serialize and publish a message to Kafka.

        Args:
            data:  Raw OSINT payload dictionary.
            topic: Override the default raw topic.
            key:   Optional partition key (e.g., source name).
        """
        target_topic = topic or kafka_cfg.TOPIC_RAW
        envelope = self._build_envelope(data, target_topic)

        future = self._producer.send(
            topic=target_topic,
            value=envelope,
            key=key,
        )

        try:
            record_metadata = future.get(timeout=10)
            logger.debug(
                f"✅ Sent to {record_metadata.topic}/"
                f"partition={record_metadata.partition}/"
                f"offset={record_metadata.offset}"
            )
        except KafkaError as e:
            logger.error(f"❌ Failed to send message to Kafka: {e}")
            raise

    def flush(self) -> None:
        """Flush all pending messages."""
        self._producer.flush()
        logger.debug("Producer flushed.")

    def close(self) -> None:
        """Flush and close the producer connection."""
        self._producer.flush()
        self._producer.close()
        logger.info("OsintProducer closed.")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
