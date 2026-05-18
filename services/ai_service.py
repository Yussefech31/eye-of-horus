"""
Eye of Horus — AI Threat Analyst Service
Provides natural language explanations, mitigation strategies, and threat intelligence
summaries for alerts. Falls back to deterministic templates if no API key is set.
"""

import os
import random
from typing import Dict
from dotenv import load_dotenv
from pathlib import Path
import pandas as pd

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
        env_path = Path(__file__).resolve().parent.parent / ".env"
        load_dotenv(env_path, override=True)
        # Support both GROQ_API_KEY and the legacy GEMINI_API_KEY variable name
        self.api_key = os.getenv("GROQ_API_KEY") or os.getenv("GEMINI_API_KEY")
        
        # Fallback: manually parse .env if os.environ caching is stuck
        if not self.api_key and env_path.exists():
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("GROQ_API_KEY="):
                        self.api_key = line.split("=", 1)[1].strip()
                        break
                    if line.startswith("GEMINI_API_KEY="):
                        self.api_key = line.split("=", 1)[1].strip()
                        # keep scanning in case GROQ_API_KEY appears later

    def analyze_alert(self, alert_data: Dict, api_key: str = None) -> str:
        """
        Generate a detailed AI analysis of a specific threat alert.
        Uses the new google-genai SDK.
        """
        key_to_use = api_key or self.api_key

        if not key_to_use:
            return self._generate_mock_analysis(alert_data)
        
        try:
            from groq import Groq
            
            client = Groq(api_key=key_to_use)
            
            prompt = f"""Act as an expert Level 3 SOC Analyst. Review the following cyber threat intelligence alert and provide:
1. A clear explanation of what this threat is.
2. Potential impact on the organization.
3. Recommended immediate mitigation steps with MITRE ATT&CK references.

Alert Data:
Title: {alert_data.get('title')}
Source: {alert_data.get('source')}
Threat Score: {alert_data.get('threat_score')}
Severity: {alert_data.get('severity', 'Unknown')}
Content: {str(alert_data.get('text', ''))[:1500]}

Format your response in Markdown with clear headings."""
            
            chat = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.4,
                max_tokens=1024,
            )
            return chat.choices[0].message.content
        except Exception as e:
            return f"**Error generating AI analysis:** {e}\n\nFalling back to standard analysis...\n\n" + self._generate_mock_analysis(alert_data)

    def generate_report_summary(self, df: pd.DataFrame, api_key: str = None) -> str:
        """
        Generate a high-level executive summary of the current threat landscape based on a dataframe of alerts.
        """
        key_to_use = api_key or self.api_key

        if not key_to_use or df.empty:
            return "Local AI Engine (Mock Mode): Multiple high-severity indicators of compromise were detected across the monitored infrastructure. Recommend immediate review of the top critical threats listed below."
        
        try:
            from groq import Groq
            client = Groq(api_key=key_to_use)
            
            # Prepare a summary of the top threats
            top_threats = df.sort_values(by="threat_score", ascending=False).head(10)
            threat_list_text = "\n".join([
                f"- [{r.get('severity', 'UNK')}] {r.get('title', 'N/A')} (Score: {r.get('threat_score', 0):.2f}, Source: {r.get('source', 'N/A')})"
                for _, r in top_threats.iterrows()
            ])
            
            prompt = f"""Act as a Chief Information Security Officer (CISO). 
Write a highly professional, concise, 2-paragraph Executive Summary for a daily Threat Intelligence Report. 
Analyze the following top threats currently active in our environment and identify key trends or required immediate actions.

Top Threats:
{threat_list_text}

Do not use markdown headers or bullet points. Provide just two well-written paragraphs of text suitable for embedding directly into a PDF report."""
            
            chat = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=500,
            )
            # Clean up the response to just be plain text for the PDF
            content = chat.choices[0].message.content.strip()
            content = content.replace("**", "").replace("##", "")
            return content
            
        except Exception as e:
            return f"Error generating AI summary: {e}. Fallback: Multiple high-severity indicators of compromise were detected."

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
