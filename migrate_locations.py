"""
One-time migration: backfill extracted_location on all threat_scores
that are missing the field.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pymongo import MongoClient, UpdateOne
from spark.udfs import extract_location
from config.settings import mongo as mongo_cfg

c = MongoClient(mongo_cfg.URI, serverSelectionTimeoutMS=5000)
db = c[mongo_cfg.DB_NAME]
col = db[mongo_cfg.COLLECTION_THREATS]

# Find all records missing extracted_location
missing = list(col.find(
    {"extracted_location": {"$exists": False}},
    {"post_id": 1, "text": 1, "title": 1}
))
print(f"Records missing extracted_location: {len(missing)}")

if not missing:
    print("Nothing to do!")
    sys.exit(0)

# Process in batches
BATCH = 500
ops = []
for i, doc in enumerate(missing):
    text = doc.get("text") or doc.get("title") or ""
    loc = extract_location(text)
    ops.append(UpdateOne(
        {"_id": doc["_id"]},
        {"$set": {"extracted_location": loc}}
    ))
    if len(ops) >= BATCH:
        result = col.bulk_write(ops, ordered=False)
        print(f"  Batch {i//BATCH + 1}: updated {result.modified_count} records")
        ops = []

if ops:
    result = col.bulk_write(ops, ordered=False)
    print(f"  Final batch: updated {result.modified_count} records")

print("Migration complete!")
c.close()
