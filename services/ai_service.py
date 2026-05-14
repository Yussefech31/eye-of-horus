"""
Eye of Horus — AI Threat Analyst Service
Provides natural language explanations, mitigation strategies, and threat intelligence
summaries for alerts. Falls back to deterministic templates if no API key is set.
"""

import os
import random
from typing import Dict

# Optional: Add openai to requirements if you want real integration
try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

# Fallback AI templates
MOCK_EXPLANATIONS = {
    "Ransomware": "This alert indicates a high-confidence ransomware payload. It likely attempts to encrypt local volumes and exfiltrate sensitive files. The presence of known malicious domains and cryptocurrency wallets strongly correlates with recent Ransomware-as-a-Service (RaaS) operations.",
    "DDoS": "This threat signature matches a volumetric DDoS attack, specifically a UDP reflection/amplification vector. The sudden spike in traffic volume from geographically distributed IPs suggests a botnet is currently targeting the external infrastructure.",
    "Phishing": "The analyzed text and associated URLs indicate a spear-phishing campaign designed to harvest credentials. The email headers are likely spoofed to appear as an internal executive communication.",
    "Zero-Day": "This is a critical finding matching an unpatched (0-day) vulnerability or recent CVE. The exploit allows unauthenticated remote code execution (RCE). Immediate patching or network-level isolation is required.",
    "General": "The behavioral engine flagged this activity due to anomalous deviations from baseline. Multiple high-severity indicators of compromise (IOCs) were detected in a short time window."
}

MOCK_MITIGATIONS = [
    "- Immediately isolate affected endpoints from the network.",
    "- Block the associated IP addresses and domains at the perimeter firewall.",
    "- Reset credentials for all users involved in this alert.",
    "- Initiate a full AV/EDR scan on the host machines.",
    "- Review DNS and proxy logs to identify lateral movement.",
    "- Apply the latest vendor security patches.",
    "- Report the incident to the internal CSIRT team."
]


class AIAnalystService:
    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.use_mock = not self.api_key or OpenAI is None

        if not self.use_mock:
            self.client = OpenAI(api_key=self.api_key)

    def analyze_alert(self, alert_data: Dict) -> str:
        """
        Generate a detailed AI analysis of a specific threat alert.
        """
        if self.use_mock:
            return self._generate_mock_analysis(alert_data)
        
        try:
            prompt = f"""
            Act as an expert Level 3 SOC Analyst. Review the following cyber threat intelligence alert and provide:
            1. A clear explanation of what this threat is.
            2. Potential impact on the organization.
            3. Recommended immediate mitigation steps.
            
            Alert Data:
            Title: {alert_data.get('title')}
            Source: {alert_data.get('source')}
            Score: {alert_data.get('threat_score')}
            Content: {alert_data.get('text')}
            
            Format your response in Markdown with clear headings.
            """
            
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=600
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"**Error generating AI analysis:** {e}\n\nFalling back to standard analysis...\n\n" + self._generate_mock_analysis(alert_data)

    def _generate_mock_analysis(self, alert_data: Dict) -> str:
        """Generates a deterministic markdown analysis when no API key is present."""
        
        title = str(alert_data.get("title", "")).lower()
        text = str(alert_data.get("text", "")).lower()
        
        if "ransomware" in title or "ransomware" in text:
            exp = MOCK_EXPLANATIONS["Ransomware"]
        elif "ddos" in title or "flood" in text:
            exp = MOCK_EXPLANATIONS["DDoS"]
        elif "phish" in title or "credential" in text:
            exp = MOCK_EXPLANATIONS["Phishing"]
        elif "0-day" in title or "cve" in title:
            exp = MOCK_EXPLANATIONS["Zero-Day"]
        else:
            exp = MOCK_EXPLANATIONS["General"]

        mitigations = random.sample(MOCK_MITIGATIONS, 3)
        mitigation_text = "\n".join(mitigations)
        
        return f"""
### 🧠 Executive Summary
{exp}

### ⚠️ Potential Impact
If left unmitigated, this threat could result in unauthorized access, data exfiltration, or severe disruption of critical services. The threat score of **{alert_data.get('threat_score', 0):.2f}** places this in the **High/Critical** priority queue.

### 🛡️ Recommended Actions
{mitigation_text}

---
*Note: This analysis was generated by the Local AI Engine (Mock Mode) because no API key was provided.*
"""
