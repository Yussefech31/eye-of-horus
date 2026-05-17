from pymongo import MongoClient

c = MongoClient("mongodb://eyeadmin:eyeofhorus2024@localhost:27017/")
db = c["cyber_intel"]

print("raw_posts by source:")
pipeline = [{"$group": {"_id": "$source", "count": {"$sum": 1}}}]
for doc in db.raw_posts.aggregate(pipeline):
    print(f"  {doc['_id']}: {doc['count']}")

print("\nthreat_scores by source:")
for doc in db.threat_scores.aggregate(pipeline):
    print(f"  {doc['_id']}: {doc['count']}")
