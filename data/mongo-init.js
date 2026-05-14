
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
db.alerts.createIndex({ "status": 1 });
db.alerts.createIndex({ "assigned_to": 1 });
db.alerts.createIndex({ "priority": 1 });

// analyst_notes: user-generated notes for alerts/threats
db.createCollection('analyst_notes');
db.analyst_notes.createIndex({ "post_id": 1 });
db.analyst_notes.createIndex({ "created_at": -1 });

print("✅ Eye of Horus — MongoDB initialized successfully.");
print("   Collections: raw_posts, threat_scores, alerts, analyst_notes");
