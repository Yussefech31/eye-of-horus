from pymongo import MongoClient
c = MongoClient("mongodb://eyeadmin:eyeofhorus2024@localhost:27017/")
db = c["cyber_intel"]
col = db["threat_scores"]

# Check extracted_location distribution
pipeline = [
    {"$group": {"_id": "$extracted_location", "count": {"$sum": 1}}},
    {"$sort": {"count": -1}},
    {"$limit": 15}
]
print("Top extracted locations:")
for doc in col.aggregate(pipeline):
    loc = doc["_id"]
    cnt = doc["count"]
    print("  %s: %d" % (loc, cnt))

# Check real sources specifically
for src in ["rss", "nvd_cve", "alienvault_otx"]:
    pipeline2 = [
        {"$match": {"source": src}},
        {"$group": {"_id": "$extracted_location", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5}
    ]
    print("\n%s locations:" % src)
    for doc in col.aggregate(pipeline2):
        loc = doc["_id"]
        cnt = doc["count"]
        print("  %s: %d" % (loc, cnt))

# Verify no records are missing extracted_location
missing = col.count_documents({"extracted_location": {"$exists": False}})
print("\n\nRecords STILL missing extracted_location: %d" % missing)

c.close()
