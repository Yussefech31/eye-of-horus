"""
Eye of Horus — Data Cleanup Script
Clears all MongoDB collections so the pipeline can start fresh.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pymongo import MongoClient
from config.settings import mongo as mongo_cfg

def main():
    client = MongoClient(mongo_cfg.URI, serverSelectionTimeoutMS=5000)
    db = client[mongo_cfg.DB_NAME]

    collections = [
        mongo_cfg.COLLECTION_RAW,       # raw_posts
        mongo_cfg.COLLECTION_THREATS,    # threat_scores
        mongo_cfg.COLLECTION_ALERTS,     # alerts
    ]

    print("=" * 50)
    print("  Eye of Horus — Data Cleanup")
    print("=" * 50)
    print(f"  Database: {mongo_cfg.DB_NAME}")
    print()

    # Show current counts
    for name in collections:
        count = db[name].count_documents({})
        print(f"  {name}: {count:,} records")

    print()
    confirm = input("⚠️  Delete ALL data? (yes/no): ").strip().lower()

    if confirm != "yes":
        print("Cancelled.")
        return

    print()
    for name in collections:
        result = db[name].delete_many({})
        print(f"  ✅ {name}: deleted {result.deleted_count:,} records")

    print()
    print("🧹 Cleanup complete! Restart the pipeline with start_project.bat")

    client.close()

if __name__ == "__main__":
    main()
