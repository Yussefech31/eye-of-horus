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

def extract_location(text: str) -> str:
    """Extract Geo-Political Entity (GPE) using regex dictionary lookup."""
    if not text or len(text.strip()) < 3:
        return "Unknown"
        
    text_lower = text.lower()
    
    # Common locations to check
    # Note: in a production scenario, this list would be comprehensive
    locations = [
        "Russia", "China", "United States", "US", "USA", "Iran",
        "North Korea", "Brazil", "India", "Nigeria", "Ukraine",
        "Germany", "Romania", "Turkey", "Vietnam", "Indonesia",
        "France", "United Kingdom", "UK", "London", "Paris",
        "Moscow", "Beijing", "Washington", "New York", "Tokyo",
        "Israel"
    ]
    
    
    for loc in locations:
        # Check for whole word match to avoid partial matches like "us" in "virus"
        if re.search(rf'\b{loc.lower()}\b', text_lower):
            # Normalise "US"/"USA" to "United States"
            if loc in ["US", "USA"]:
                return "United States"
            if loc == "UK":
                return "United Kingdom"
            return loc
            
    return "Unknown"
