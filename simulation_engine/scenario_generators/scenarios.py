import time
import uuid
import random
from typing import Iterator, Dict, Any

class ScenarioGenerator:
    """Base class for generating synthetic attack campaigns."""
    def generate(self, intensity: int = 5) -> Iterator[Dict[str, Any]]:
        raise NotImplementedError

class RansomwareScenario(ScenarioGenerator):
    def generate(self, intensity: int = 5) -> Iterator[Dict[str, Any]]:
        count = max(1, intensity)
        for i in range(count):
            yield {
                "id": f"MOCK-RANSOM-{uuid.uuid4().hex[:8].upper()}",
                "title": f"🚨 LOCKBIT RANSOMWARE OUTBREAK DETECTED (Node {i+1})",
                "description": "CRITICAL: Multiple hosts encrypted with LockBit 3.0. Lateral movement observed over SMB. Data exfiltration in progress.",
                "author": "MockTestSystem",
                "url": f"https://mock-soc-alert.local/ransomware/{i+1}",
                "created_utc": time.time(),
                "threat_type": "ransomware",
                "source_ip": f"10.0.{random.randint(1,255)}.{random.randint(1,255)}",
                "cvss": 9.8,
                "comments": random.randint(500, 2000)
            }

class DDoSScenario(ScenarioGenerator):
    def generate(self, intensity: int = 5) -> Iterator[Dict[str, Any]]:
        count = max(1, intensity * 2) # DDoS generates more events
        for i in range(count):
            yield {
                "id": f"MOCK-DDOS-{uuid.uuid4().hex[:8].upper()}",
                "title": "🚨 VOLUMETRIC DDOS ATTACK IN PROGRESS",
                "description": "WARNING: Massive UDP flood detected targeting the main gateway. Incoming traffic anomaly spike.",
                "author": "MockTestSystem",
                "url": f"https://mock-soc-alert.local/ddos/{i+1}",
                "created_utc": time.time(),
                "threat_type": "ddos",
                "source_ip": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "cvss": 8.5,
                "comments": random.randint(100, 500)
            }

class APTCampaignScenario(ScenarioGenerator):
    def generate(self, intensity: int = 5) -> Iterator[Dict[str, Any]]:
        count = max(1, int(intensity / 2) + 1)
        for i in range(count):
            yield {
                "id": f"MOCK-APT-{uuid.uuid4().hex[:8].upper()}",
                "title": "🚨 APT29 SUSPICIOUS ACTIVITY",
                "description": "CRITICAL: Low-and-slow exfiltration patterns matching APT29 observed. Backdoor installed on domain controller.",
                "author": "MockTestSystem",
                "url": f"https://mock-soc-alert.local/apt/{i+1}",
                "created_utc": time.time(),
                "threat_type": "apt",
                "source_ip": "195.2.14.55", # Static IP for correlation testing
                "cvss": 10.0,
                "comments": random.randint(2000, 5000)
            }

class PhishingScenario(ScenarioGenerator):
    def generate(self, intensity: int = 5) -> Iterator[Dict[str, Any]]:
        count = max(1, intensity)
        for i in range(count):
            yield {
                "id": f"MOCK-PHISH-{uuid.uuid4().hex[:8].upper()}",
                "title": "🚨 SPEAR PHISHING CAMPAIGN",
                "description": "WARNING: Multiple executives targeted by highly sophisticated spear phishing campaign. Fake Office 365 login portals detected.",
                "author": "MockTestSystem",
                "url": f"https://mock-soc-alert.local/phishing/{i+1}",
                "created_utc": time.time(),
                "threat_type": "phishing",
                "source_ip": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "cvss": 7.5,
                "comments": random.randint(50, 300)
            }

class ZeroDayScenario(ScenarioGenerator):
    def generate(self, intensity: int = 5) -> Iterator[Dict[str, Any]]:
        yield {
            "id": f"MOCK-CVE-{uuid.uuid4().hex[:8].upper()}",
            "title": "🚨 NEW ZERO-DAY EXPLOIT IN THE WILD",
            "description": "CRITICAL: Unpatched zero-day vulnerability in popular web framework actively exploited. Remote code execution possible.",
            "author": "MockTestSystem",
            "url": f"https://mock-soc-alert.local/cve/1",
            "created_utc": time.time(),
            "threat_type": "zero_day",
            "source_ip": "0.0.0.0",
            "cvss": 10.0,
            "comments": random.randint(5000, 10000)
        }

SCENARIO_MAP = {
    "Ransomware Campaign": RansomwareScenario(),
    "Coordinated DDoS Attack": DDoSScenario(),
    "Phishing Campaign": PhishingScenario(),
    "Zero-Day Exploit Campaign": ZeroDayScenario(),
    "Multi-Stage APT Campaign": APTCampaignScenario(),
}
