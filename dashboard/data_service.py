"""
Eye of Horus — Data Service Layer
Centralized MongoDB data access with caching, filtering, and error handling.
All dashboard pages import from here instead of querying MongoDB directly.
"""

import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional

import pandas as pd
import streamlit as st
from pymongo import MongoClient
from loguru import logger

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import mongo as mongo_cfg, threat as threat_cfg, kafka as kafka_cfg


# ═══════════════════════════════════════════════════════════════════════════════
#  MongoDB Connection
# ═══════════════════════════════════════════════════════════════════════════════

@st.cache_resource
def get_mongo_client() -> MongoClient:
    """Cached MongoDB client — shared across all dashboard components."""
    return MongoClient(mongo_cfg.URI, serverSelectionTimeoutMS=3000)


def check_mongo_health() -> dict:
    """Check MongoDB connectivity and return status dict."""
    try:
        client = get_mongo_client()
        client.admin.command("ping")
        return {"status": "online", "message": "Connected"}
    except Exception as e:
        return {"status": "offline", "message": str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _try_parse_datetime(val) -> Optional[datetime]:
    """Attempt to parse a value as a datetime object."""
    if isinstance(val, datetime):
        return val
    if isinstance(val, str):
        try:
            return datetime.fromisoformat(val)
        except (ValueError, TypeError):
            pass
    return None


def _normalize_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Apply standard datetime parsing and numeric coercion to threat data."""
    if df.empty:
        return df

    # Parse datetime columns
    for col in ["processed_at", "published_at", "created_at"]:
        if col in df.columns:
            df[col] = df[col].apply(_try_parse_datetime)
            df[col] = pd.to_datetime(df[col], errors="coerce", utc=True)

    # Ensure numeric score columns
    for col in ["threat_score", "keyword_score", "sentiment_score", "volume_score", "trend_score"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    # Derive severity if missing
    if "severity" not in df.columns and "threat_score" in df.columns:
        df["severity"] = df["threat_score"].apply(
            lambda s: "CRITICAL" if s >= 0.85
            else "HIGH" if s >= 0.65
            else "MEDIUM" if s >= 0.40
            else "LOW"
        )

    return df


# ═══════════════════════════════════════════════════════════════════════════════
#  Data Loading Functions
# ═══════════════════════════════════════════════════════════════════════════════

@st.cache_data(ttl=2)
def load_threats(hours_back: float = 24, sources: tuple = ()) -> pd.DataFrame:
    """
    Load scored threat records from MongoDB.
    Tries datetime query first, falls back to string query, then no filter.
    Sources filter is applied at the DB level for efficiency.
    """
    try:
        client = get_mongo_client()
        col = client[mongo_cfg.DB_NAME][mongo_cfg.COLLECTION_THREATS]
        since = datetime.utcnow() - timedelta(hours=hours_back)

        # Build source filter (applied inside MongoDB, not after)
        source_filter = {}
        if sources:
            source_filter = {"source": {"$in": list(sources)}}

        for base_query in [
            {"processed_at": {"$gte": since}},
            {"processed_at": {"$gte": since.isoformat()}},
            {},
        ]:
            query = {**base_query, **source_filter}
            docs = list(col.find(query, {"_id": 0}).sort("threat_score", -1).limit(5000))
            if docs:
                break

        if not docs:
            return pd.DataFrame()

        df = pd.DataFrame(docs)
        return _normalize_dataframe(df)

    except Exception as e:
        logger.error(f"Failed to load threats: {e}")
        return pd.DataFrame()


@st.cache_data(ttl=2)
def load_alerts(limit: int = 200) -> pd.DataFrame:
    """Load alert records from MongoDB, sorted by creation time desc."""
    try:
        client = get_mongo_client()
        col = client[mongo_cfg.DB_NAME][mongo_cfg.COLLECTION_ALERTS]
        docs = list(col.find({}, {"_id": 0}).sort("created_at", -1).limit(limit))
        if not docs:
            return pd.DataFrame()
        df = pd.DataFrame(docs)
        return _normalize_dataframe(df)
    except Exception:
        return pd.DataFrame()


@st.cache_data(ttl=2)
def load_stats() -> dict:
    """Load pipeline statistics (collection counts)."""
    try:
        client = get_mongo_client()
        db = client[mongo_cfg.DB_NAME]
        return {
            "raw": db[mongo_cfg.COLLECTION_RAW].count_documents({}),
            "threats": db[mongo_cfg.COLLECTION_THREATS].count_documents({}),
            "alerts": db[mongo_cfg.COLLECTION_ALERTS].count_documents({}),
        }
    except Exception:
        return {"raw": 0, "threats": 0, "alerts": 0}


def acknowledge_alert(post_id: str) -> bool:
    """Mark an alert as acknowledged in MongoDB."""
    try:
        client = get_mongo_client()
        col = client[mongo_cfg.DB_NAME][mongo_cfg.COLLECTION_ALERTS]
        result = col.update_one(
            {"post_id": post_id},
            {"$set": {"acknowledged": True, "acknowledged_at": datetime.now(timezone.utc)}},
        )
        return result.modified_count > 0
    except Exception as e:
        logger.error(f"Failed to acknowledge alert {post_id}: {e}")
        return False


# ═══════════════════════════════════════════════════════════════════════════════
#  Config Access (for display in dashboard)
# ═══════════════════════════════════════════════════════════════════════════════

def get_pipeline_config() -> dict:
    """Return pipeline configuration for display."""
    return {
        "kafka_bootstrap": kafka_cfg.BOOTSTRAP_SERVERS,
        "kafka_topic_raw": kafka_cfg.TOPIC_RAW,
        "mongo_db": mongo_cfg.DB_NAME,
        "threshold": threat_cfg.THRESHOLD,
        "scoring_weights": {
            "α (keyword)": threat_cfg.ALPHA,
            "β (volume)": threat_cfg.BETA,
            "γ (sentiment)": threat_cfg.GAMMA,
            "δ (trend)": threat_cfg.DELTA,
        },
    }
