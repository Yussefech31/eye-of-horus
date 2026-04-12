"""
MongoDB initialization script.
Runs once when the container is first started.
Creates collections, indexes, and the initial schema.
"""

// Switch to our database
db = db.getSiblingDB('cyber_intel');

// ── Collections & Indexes ─────────────────────────────────────────────────────

// raw_posts: stores every scraped item as-is
db.createCollection('raw_posts');
db.raw_posts.createIndex({ "source": 1, "published_at": -1 });
db.raw_posts.createIndex({ "post_id": 1 }, { unique: true, sparse: true });
db.raw_posts.createIndex({ "published_at": -1 }, { expireAfterSeconds: 2592000 }); // TTL 30 days

// threat_scores: enriched documents with NLP + threat scoring
db.createCollection('threat_scores');
db.threat_scores.createIndex({ "post_id": 1 }, { unique: true });
db.threat_scores.createIndex({ "threat_score": -1 });
db.threat_scores.createIndex({ "processed_at": -1 });
db.threat_scores.createIndex({ "source": 1, "processed_at": -1 });

// alerts: high-score events that crossed the threshold
db.createCollection('alerts');
db.alerts.createIndex({ "created_at": -1 });
db.alerts.createIndex({ "threat_score": -1 });
db.alerts.createIndex({ "acknowledged": 1 });

print("✅ Eye of Horus — MongoDB initialized successfully.");
print("   Collections: raw_posts, threat_scores, alerts");
