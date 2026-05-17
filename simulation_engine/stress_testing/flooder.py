import sys
import time
from pathlib import Path
from loguru import logger

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

def run_stress_test(events_per_sec: int = 1000, duration_sec: int = 10):
    from simulation_engine.scenario_generators.scenarios import DDoSScenario
    from broker.producer import OsintProducer
    from config.settings import kafka as kafka_cfg
    from datetime import datetime, timezone
    
    logger.info(f"Starting Stress Test: {events_per_sec} evt/s for {duration_sec}s")
    generator = DDoSScenario()
    
    with OsintProducer() as producer:
        for sec in range(duration_sec):
            start = time.time()
            # Generate a batch
            events = list(generator.generate(int(events_per_sec / 2))) # intensity translates to 2x events
            
            for event in events:
                record = {
                    "post_id": event["id"],
                    "title": event["title"],
                    "text": event["description"],
                    "author": event["author"],
                    "url": event["url"],
                    "published_at": datetime.fromtimestamp(event["created_utc"], tz=timezone.utc).isoformat(),
                    "extra": {
                        "source_type": "stress_test",
                        "threat_type": event["threat_type"],
                        "source_ip": event["source_ip"],
                        "cvss_score": event["cvss"],
                        "num_comments": event["comments"],
                        "upvote_ratio": 1.0,
                    }
                }
                producer.send(record, topic="sim-raw-osint", key="stress")
            
            elapsed = time.time() - start
            if elapsed < 1.0:
                time.sleep(1.0 - elapsed)
            logger.info(f"Stress test progress: {sec + 1}/{duration_sec}s")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--rate", type=int, default=500)
    parser.add_argument("--duration", type=int, default=5)
    args = parser.parse_args()
    run_stress_test(args.rate, args.duration)
