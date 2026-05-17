"""
Simulation Engine
Orchestrates isolated SOC pipelines and generates synthetic attack scenarios.
"""
import sys
import time
import os
import subprocess
import atexit
from pathlib import Path
from loguru import logger
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import mongo as mongo_cfg

class SimulationEngine:
    """Manages the isolated background processes and attack generation."""
    
    def __init__(self):
        self.consumer_proc: Optional[subprocess.Popen] = None
        self.processor_proc: Optional[subprocess.Popen] = None
        self.is_running = False
        atexit.register(self.stop_pipeline)

    def _get_isolated_env(self) -> dict:
        """Returns environment variables overridden for simulation isolation."""
        env = os.environ.copy()
        env["KAFKA_TOPIC_RAW"] = "sim-raw-osint"
        env["KAFKA_TOPIC_PROCESSED"] = "sim-processed-threats"
        env["KAFKA_TOPIC_ALERTS"] = "sim-threat-alerts"
        env["MONGO_COLLECTION_RAW"] = "sim_raw_posts"
        env["MONGO_COLLECTION_THREATS"] = "sim_threat_scores"
        env["MONGO_COLLECTION_ALERTS"] = "sim_alerts"
        env["SIMULATION_MODE"] = "1"
        return env

    def start_pipeline(self):
        """Spawns isolated consumer and processor processes."""
        if self.is_running:
            return

        logger.info("🚀 Starting Isolated Simulation Pipeline...")
        env = self._get_isolated_env()
        base_dir = Path(__file__).resolve().parent.parent

        # Use the current python executable (assuming running in venv)
        python_exe = sys.executable

        self.consumer_proc = subprocess.Popen(
            [python_exe, str(base_dir / "broker" / "consumer.py")],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        self.processor_proc = subprocess.Popen(
            [python_exe, str(base_dir / "spark" / "threat_processor_basic.py")],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        self.is_running = True
        logger.success("✅ Simulation Pipeline Active.")

    def stop_pipeline(self):
        """Terminates the isolated processes."""
        if self.consumer_proc:
            self.consumer_proc.terminate()
            self.consumer_proc = None
        if self.processor_proc:
            self.processor_proc.terminate()
            self.processor_proc = None
        self.is_running = False
        logger.info("🛑 Simulation Pipeline Stopped.")

    def clean_simulation_collections(self):
        """Drops the isolated MongoDB collections to start fresh."""
        from pymongo import MongoClient
        client = MongoClient(mongo_cfg.URI)
        db = client[mongo_cfg.DB_NAME]
        db.drop_collection("sim_raw_posts")
        db.drop_collection("sim_threat_scores")
        db.drop_collection("sim_alerts")
        client.close()
        logger.info("🧹 Simulation collections cleaned.")

if __name__ == "__main__":
    engine = SimulationEngine()
    engine.clean_simulation_collections()
    engine.start_pipeline()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        engine.stop_pipeline()
