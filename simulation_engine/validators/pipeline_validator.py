import os
import sys
from pathlib import Path
from pymongo import MongoClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from config.settings import mongo as mongo_cfg

class PipelineValidator:
    """Validates the health and accuracy of the isolated simulation pipeline."""
    def __init__(self):
        self.client = MongoClient(mongo_cfg.URI, serverSelectionTimeoutMS=2000)
        self.db = self.client[mongo_cfg.DB_NAME]
        
    def get_validation_metrics(self) -> dict:
        try:
            # Check if simulation collections exist and have data
            raw_count = self.db.sim_raw_posts.count_documents({})
            threat_count = self.db.sim_threat_scores.count_documents({})
            alert_count = self.db.sim_alerts.count_documents({})
            
            # Check Anomaly
            # For simplicity, if we have volume_score > 0.8, it's considered anomalous
            high_vol = self.db.sim_threat_scores.count_documents({"volume_score": {"$gt": 0.8}})
            
            # Check Scoring Accuracy
            # Ensure CVSS 9.8 is marked HIGH or CRITICAL
            cve_high_accuracy = True
            cve_docs = list(self.db.sim_threat_scores.find({"source": "mock_generator", "threat_type": "zero_day"}))
            if cve_docs:
                for doc in cve_docs:
                    if doc.get("severity") not in ["HIGH", "CRITICAL"]:
                        cve_high_accuracy = False
                        break
                        
            return {
                "db_connected": True,
                "raw_ingested": raw_count,
                "threats_scored": threat_count,
                "alerts_generated": alert_count,
                "pipeline_active": threat_count > 0,
                "anomaly_detected": high_vol > 0,
                "scoring_accuracy": cve_high_accuracy if cve_docs else None
            }
        except Exception as e:
            return {"db_connected": False, "error": str(e)}

    def close(self):
        self.client.close()
