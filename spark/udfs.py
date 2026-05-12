import re

def clean_text(text: str) -> str:
    """Lowercase, remove non-alpha characters, collapse whitespace."""
    if not text:
        return ""
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    return re.sub(r"\s+", " ", text).strip()

def keyword_score(text: str) -> float:
    from config.settings import threat as threat_cfg
    if not text:
        return 0.0
    tokens = text.split()
    if not tokens:
        return 0.0
    hits = sum(1 for token in tokens if token in threat_cfg.THREAT_KEYWORDS)
    return min(hits / 10.0, 1.0)

def sentiment_score(text: str) -> float:
    NEGATIVE_WORDS = {
        "attack", "breach", "hack", "steal", "malicious", "malware",
        "ransomware", "exploit", "leak", "infiltrate", "ddos", "flood",
        "threat", "dangerous", "critical", "vulnerable", "pwned",
        "compromised", "infected", "backdoor", "dump", "stolen",
    }
    if not text:
        return 0.0
    tokens = set(text.lower().split())
    hits = len(tokens & NEGATIVE_WORDS)
    return min(hits / 8.0, 1.0)

def compute_threat_score(keyword_freq: float, volume_score: float, sentiment: float, trend_score: float) -> float:
    from config.settings import threat as threat_cfg
    score = (threat_cfg.ALPHA * keyword_freq + 
             threat_cfg.BETA * volume_score + 
             threat_cfg.GAMMA * sentiment + 
             threat_cfg.DELTA * trend_score)
    return round(min(max(score, 0.0), 1.0), 4)
