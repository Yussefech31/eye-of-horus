"""
Generates deterministic mock cyberattack geolocation flows.
"""
import hashlib

MOCK_LOCATIONS = [
    {"country": "United States", "city": "Washington", "lat": 38.90, "lon": -77.04, "isp": "AWS"},
    {"country": "Russia", "city": "Moscow", "lat": 55.75, "lon": 37.62, "isp": "Rostelecom"},
    {"country": "China", "city": "Beijing", "lat": 39.91, "lon": 116.39, "isp": "China Telecom"},
    {"country": "Germany", "city": "Berlin", "lat": 52.52, "lon": 13.41, "isp": "Deutsche Telekom"},
    {"country": "France", "city": "Paris", "lat": 48.86, "lon": 2.35, "isp": "Orange"},
    {"country": "UK", "city": "London", "lat": 51.50, "lon": -0.12, "isp": "BT"},
    {"country": "Morocco", "city": "Rabat", "lat": 34.02, "lon": -6.83, "isp": "Maroc Telecom"},
    {"country": "Brazil", "city": "Brasilia", "lat": -15.79, "lon": -47.88, "isp": "Vivo"},
    {"country": "India", "city": "New Delhi", "lat": 28.61, "lon": 77.21, "isp": "Jio"},
    {"country": "Netherlands", "city": "Amsterdam", "lat": 52.36, "lon": 4.90, "isp": "KPN"},
    {"country": "Singapore", "city": "Singapore", "lat": 1.35, "lon": 103.81, "isp": "Singtel"},
    {"country": "Ukraine", "city": "Kyiv", "lat": 50.45, "lon": 30.52, "isp": "Kyivstar"},
    {"country": "Romania", "city": "Bucharest", "lat": 44.43, "lon": 26.10, "isp": "Digi"},
    {"country": "North Korea", "city": "Pyongyang", "lat": 39.02, "lon": 125.75, "isp": "KPTC"}
]

def generate_mock_geolocation(event_id: str) -> dict:
    """
    Deterministically generate source and destination locations based on event ID.
    This prevents map markers from jumping around when the dashboard auto-refreshes.
    """
    # Use hash of event_id to pick deterministic but pseudo-random src and dst
    h = int(hashlib.md5(str(event_id).encode()).hexdigest(), 16)
    
    src_idx = h % len(MOCK_LOCATIONS)
    dst_idx = (h >> 8) % len(MOCK_LOCATIONS)
    
    if src_idx == dst_idx:
        dst_idx = (dst_idx + 1) % len(MOCK_LOCATIONS)
        
    src = MOCK_LOCATIONS[src_idx]
    dst = MOCK_LOCATIONS[dst_idx]
    
    # Add a tiny bit of jitter to the coordinates based on the hash so points don't perfectly stack
    src_lat_jitter = ((h >> 16) % 100 - 50) / 100.0
    src_lon_jitter = ((h >> 24) % 100 - 50) / 100.0
    
    dst_lat_jitter = ((h >> 32) % 100 - 50) / 100.0
    dst_lon_jitter = ((h >> 40) % 100 - 50) / 100.0

    return {
        "src_country": src["country"],
        "src_city": src["city"],
        "src_isp": src["isp"],
        "src_lat": src["lat"] + src_lat_jitter,
        "src_lon": src["lon"] + src_lon_jitter,
        
        "dst_country": dst["country"],
        "dst_city": dst["city"],
        "dst_isp": dst["isp"],
        "dst_lat": dst["lat"] + dst_lat_jitter,
        "dst_lon": dst["lon"] + dst_lon_jitter,
        
        "mock_geo": True
    }
