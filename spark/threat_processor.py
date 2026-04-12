"""
Eye of Horus — PySpark Structured Streaming Job
Reads raw OSINT messages from Kafka, applies NLP feature engineering,
computes threat scores, and writes results back to Kafka + MongoDB.

Pipeline:
    Kafka (raw-osint)
        → Text Cleaning
        → TF-IDF Keyword Detection
        → Sentiment Analysis
        → Threat Score Computation
        → Kafka (processed-threats) + MongoDB (threat_scores)
        → Alert if score > threshold → Kafka (threat-alerts)
"""

import sys
import re
import json
from pathlib import Path
from typing import Iterator

# ── PySpark ───────────────────────────────────────────────────────────────────
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import (
    StructType, StructField,
    StringType, FloatType, IntegerType, BooleanType, MapType, ArrayType
)

# ── Project root on path ──────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import kafka as kafka_cfg, mongo as mongo_cfg, threat as threat_cfg

# ══════════════════════════════════════════════════════════════════════════════
#  Schema Definitions
# ══════════════════════════════════════════════════════════════════════════════

# Schema of the Kafka envelope (outer wrapper)
ENVELOPE_SCHEMA = StructType([
    StructField("envelope_id", StringType(), True),
    StructField("topic", StringType(), True),
    StructField("ingested_at", StringType(), True),
    StructField("payload", StructType([
        StructField("post_id", StringType(), True),
        StructField("source", StringType(), True),
        StructField("title", StringType(), True),
        StructField("text", StringType(), True),
        StructField("author", StringType(), True),
        StructField("url", StringType(), True),
        StructField("published_at", StringType(), True),
        StructField("collected_at", StringType(), True),
        StructField("extra", MapType(StringType(), StringType()), True),
    ]), True),
])

# ══════════════════════════════════════════════════════════════════════════════
#  PySpark UDFs — Text Processing & Threat Scoring
# ══════════════════════════════════════════════════════════════════════════════

def _clean_text(text: str) -> str:
    """Lowercase, remove non-alpha characters, collapse whitespace."""
    if not text:
        return ""
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _keyword_score(text: str, keywords: list) -> float:
    """
    Compute normalized keyword frequency score.
    Returns a [0, 1] float: ratio of threat keywords found vs total tokens.
    """
    if not text:
        return 0.0
    tokens = text.split()
    if not tokens:
        return 0.0
    hits = sum(1 for token in tokens if token in keywords)
    # Normalize to [0,1] with a soft cap at 10 hits
    return min(hits / 10.0, 1.0)


def _sentiment_score(text: str) -> float:
    """
    Simple lexicon-based negative sentiment score in [0, 1].
    Higher = more negative / aggressive tone (higher threat).
    For production, replace with a fine-tuned BERT model.
    """
    NEGATIVE_WORDS = {
        "attack", "breach", "hack", "steal", "malicious", "malware",
        "ransomware", "exploit", "leak", "infiltrate", "ddos", "flood",
        "threat", "dangerous", "critical", "vulnerable", "pwned",
        "compromised", "infected", "backdoor", "dump", "stolen",
    }
    if not text:
        return 0.0
    tokens = set(text.lower().split())
    hits = len(tokens & NEGATIVE_WORDS)
    return min(hits / 8.0, 1.0)


def _compute_threat_score(
    keyword_freq: float,
    volume_score: float,
    sentiment: float,
    trend_score: float,
    alpha: float = threat_cfg.ALPHA,
    beta: float  = threat_cfg.BETA,
    gamma: float = threat_cfg.GAMMA,
    delta: float = threat_cfg.DELTA,
) -> float:
    """
    Score = α·frequency + β·volume + γ·sentiment + δ·trend
    All inputs and output are in [0, 1].
    """
    score = alpha * keyword_freq + beta * volume_score + gamma * sentiment + delta * trend_score
    return round(min(max(score, 0.0), 1.0), 4)


# Register UDFs
clean_text_udf        = F.udf(_clean_text, StringType())
keyword_score_udf     = F.udf(
    lambda text: _keyword_score(text, threat_cfg.THREAT_KEYWORDS), FloatType()
)
sentiment_score_udf   = F.udf(_sentiment_score, FloatType())
threat_score_udf      = F.udf(
    lambda kw, vol, sent, trend: _compute_threat_score(kw, vol, sent, trend),
    FloatType()
)


# ══════════════════════════════════════════════════════════════════════════════
#  MongoDB Batch Writer (foreachBatch)
# ══════════════════════════════════════════════════════════════════════════════

def write_to_mongodb(batch_df, batch_id: int) -> None:
    """
    foreachBatch sink: write processed threat records to MongoDB.
    Uses PyMongo inside each executor (not the driver) for efficiency.
    """
    from pymongo import MongoClient, UpdateOne

    records = batch_df.collect()
    if not records:
        return

    client = MongoClient(mongo_cfg.URI)
    collection = client[mongo_cfg.DB_NAME][mongo_cfg.COLLECTION_THREATS]

    operations = [
        UpdateOne(
            {"post_id": row["post_id"]},
            {"$set": row.asDict()},
            upsert=True,
        )
        for row in records
    ]

    try:
        result = collection.bulk_write(operations, ordered=False)
        print(f"[Batch {batch_id}] MongoDB: {result.upserted_count} new, "
              f"{result.modified_count} updated")
    finally:
        client.close()


# ══════════════════════════════════════════════════════════════════════════════
#  Main Spark Streaming Job
# ══════════════════════════════════════════════════════════════════════════════

def create_spark_session() -> SparkSession:
    return (
        SparkSession.builder
        .appName("EyeOfHorus-ThreatProcessor")
        .config("spark.sql.shuffle.partitions", "4")
        .config(
            "spark.jars.packages",
            "org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.1,"
            "org.mongodb.spark:mongo-spark-connector_2.12:10.3.0",
        )
        # Enable Kafka-Spark structured streaming
        .config("spark.streaming.stopGracefullyOnShutdown", "true")
        .getOrCreate()
    )


def run_streaming_job() -> None:
    spark = create_spark_session()
    spark.sparkContext.setLogLevel("WARN")

    # ── Read from Kafka ───────────────────────────────────────────────────────
    raw_stream = (
        spark.readStream
        .format("kafka")
        .option("kafka.bootstrap.servers", kafka_cfg.BOOTSTRAP_SERVERS)
        .option("subscribe", kafka_cfg.TOPIC_RAW)
        .option("startingOffsets", "latest")
        .option("failOnDataLoss", "false")
        .load()
    )

    # ── Parse JSON envelope ───────────────────────────────────────────────────
    parsed = (
        raw_stream
        .select(
            F.from_json(
                F.col("value").cast("string"),
                ENVELOPE_SCHEMA
            ).alias("envelope"),
            F.col("timestamp").alias("kafka_timestamp"),
        )
        .select(
            "envelope.payload.*",
            "kafka_timestamp",
        )
    )

    # ── NLP Feature Engineering ───────────────────────────────────────────────
    enriched = (
        parsed
        .withColumn("clean_text",   clean_text_udf(F.col("text")))
        .withColumn("keyword_score", keyword_score_udf(F.col("clean_text")))
        .withColumn("sentiment_score", sentiment_score_udf(F.col("clean_text")))
        # volume_score: normalized comment/engagement proxy (simplified for streaming)
        .withColumn(
            "volume_score",
            F.least(
                F.coalesce(
                    F.col("extra")["num_comments"].cast(FloatType()),
                    F.lit(0.0)
                ) / F.lit(500.0),
                F.lit(1.0),
            ),
        )
        # trend_score: upvote ratio used as a proxy for virality
        .withColumn(
            "trend_score",
            F.coalesce(
                F.col("extra")["upvote_ratio"].cast(FloatType()),
                F.lit(0.0)
            ),
        )
        # Compute final threat score
        .withColumn(
            "threat_score",
            threat_score_udf(
                F.col("keyword_score"),
                F.col("volume_score"),
                F.col("sentiment_score"),
                F.col("trend_score"),
            ),
        )
        .withColumn("processed_at", F.current_timestamp())
        .withColumn(
            "is_threat",
            F.col("threat_score") >= F.lit(threat_cfg.THRESHOLD)
        )
    )

    # ── Sink 1: Write all processed records to MongoDB ────────────────────────
    mongo_query = (
        enriched
        .writeStream
        .foreachBatch(write_to_mongodb)
        .option("checkpointLocation", "/tmp/eye-of-horus/checkpoints/mongo-sink")
        .trigger(processingTime="15 seconds")
        .start()
    )

    # ── Sink 2: Write high-threat records back to Kafka (processed-threats) ──
    threat_output = (
        enriched
        .filter(F.col("is_threat") == True)
        .select(
            F.col("post_id").alias("key"),
            F.to_json(
                F.struct(
                    "post_id", "source", "title", "url",
                    "threat_score", "keyword_score", "sentiment_score",
                    "published_at", "processed_at",
                )
            ).alias("value"),
        )
    )

    kafka_threat_query = (
        threat_output
        .writeStream
        .format("kafka")
        .option("kafka.bootstrap.servers", kafka_cfg.BOOTSTRAP_SERVERS)
        .option("topic", kafka_cfg.TOPIC_PROCESSED)
        .option("checkpointLocation", "/tmp/eye-of-horus/checkpoints/kafka-threats")
        .trigger(processingTime="15 seconds")
        .start()
    )

    # ── Sink 3: Console debug (remove in production) ──────────────────────────
    debug_query = (
        enriched
        .select("post_id", "source", "threat_score", "is_threat", "title")
        .writeStream
        .format("console")
        .option("truncate", False)
        .trigger(processingTime="15 seconds")
        .start()
    )

    spark.streams.awaitAnyTermination()


if __name__ == "__main__":
    run_streaming_job()
