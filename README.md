# 👁️ Eye of Horus

> **Automated Cybersecurity Monitoring and Early Detection of Cyber-Activism Campaigns**

A real-time OSINT pipeline that collects data from public sources, processes it through Apache Kafka and PySpark, scores threats using NLP + Machine Learning, and presents results in a live Streamlit dashboard.

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         DATA SOURCES                             │
│   Reddit   │   RSS Feeds   │   AlienVault OTX   │   NVD CVEs    │
└─────────────────────────┬────────────────────────────────────────┘
                          │  scraper/orchestrator.py
                          ▼
              ┌───────────────────────┐
              │    Apache Kafka       │  Topic: raw-osint
              │    raw-osint topic    │
              └──────────┬────────────┘
                         │
           ┌─────────────┼────────────────┐
           ▼             ▼                ▼
    kafka/consumer   spark/threat_processor.py
    (raw storage)    (NLP + ML scoring)
           │             │
     MongoDB:        MongoDB:         Kafka:
     raw_posts     threat_scores   processed-threats
                         │
                   dashboard/app.py
                  (Streamlit UI :8501)
```

---

## 📁 Project Structure

```
eye-of-horus/
├── docker-compose.yml          # Kafka + MongoDB + UI containers
├── requirements.txt            # All Python dependencies
├── .env.example                # Configuration template → copy to .env
├── .gitignore
│
├── config/
│   └── settings.py             # Typed config loader from .env
│
├── scraper/
│   ├── base_scraper.py         # Abstract base class (standard schema)
│   ├── orchestrator.py         # 🚀 Run this — launches all scrapers
│   ├── reddit_scraper.py       # Reddit PRAW (hot + new feeds)
│   ├── rss_scraper.py          # 8 cybersecurity RSS feeds
│   ├── otx_scraper.py          # AlienVault OTX threat pulses
│   └── nvd_scraper.py          # NIST NVD CVE vulnerability feed
│
├── broker/
│   ├── producer.py             # Message publisher with retry + enveloping
│   └── consumer.py             # Kafka → MongoDB raw storage
│
├── spark/
│   └── threat_processor.py     # PySpark streaming: NLP → threat scoring
│
├── models/
│   └── threat_classifier.py    # ML models (LR + RF + Isolation Forest)
│
├── dashboard/
│   └── app.py                  # Streamlit real-time threat dashboard
│
└── data/
    └── mongo-init.js           # MongoDB collection + index setup
```

---

## ⚡ Quick Start

### Step 1 — Configure credentials

```bash
copy .env.example .env
```

Edit `.env` and fill in:
- `REDDIT_CLIENT_ID` / `REDDIT_CLIENT_SECRET` → [reddit.com/prefs/apps](https://www.reddit.com/prefs/apps)
- `OTX_API_KEY` → [otx.alienvault.com](https://otx.alienvault.com) (free account)

### Step 2 — Start infrastructure

```bash
docker-compose up -d
```

| Service | URL |
|---|---|
| Kafka UI | http://localhost:8080 |
| MongoDB UI | http://localhost:8081 |

### Step 3 — Install Python dependencies

```bash
pip install -r requirements.txt
```

### Step 4 — Run the pipeline (3 terminals)

**Terminal 1 — All scrapers (orchestrated):**
```bash
python scraper/orchestrator.py
```

**Terminal 2 — Kafka → MongoDB storage:**
```bash
python broker/consumer.py
```

**Terminal 3 — PySpark threat processing:**
```bash
spark-submit \
  --packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.1 \
  spark/threat_processor.py
```

**Terminal 4 — Dashboard:**
```bash
streamlit run dashboard/app.py
```
→ Open http://localhost:8501

### Step 5 — Train ML models (optional but recommended)

```bash
# Train on synthetic data (fast, for testing)
python models/threat_classifier.py --train

# Test predictions
python models/threat_classifier.py --predict

# Train on real labeled data from MongoDB (production)
python models/threat_classifier.py --train --mongo
```

---

## 📊 Threat Score Formula

```
Score = α·frequency + β·volume + γ·sentiment + δ·trend
```

| Weight | Default | Signal |
|---|---|---|
| α = 0.30 | Keyword frequency | ddos, leak, hack, ransomware... |
| β = 0.20 | Post volume | Comment count / engagement |
| γ = 0.30 | Negative sentiment | Aggressive language detection |
| δ = 0.20 | Trend / virality | Upvote ratio, post velocity |

Scores ≥ `0.65` (configurable) trigger an alert.

---

## 🛠️ Data Sources

| Source | Scraper | Interval | Credentials |
|---|---|---|---|
| Reddit | `reddit_scraper.py` | 60 sec | Free API key |
| RSS Feeds (8 sources) | `rss_scraper.py` | 5 min | None required |
| AlienVault OTX | `otx_scraper.py` | 60 min | Free API key |
| NIST NVD CVEs | `nvd_scraper.py` | 6 hours | None required |

---

## 🧠 ML Models

| Model | Type | Purpose |
|---|---|---|
| Logistic Regression | Classifier | Fast, interpretable threat/benign classification |
| Random Forest | Classifier | Robust non-linear classification |
| Isolation Forest | Anomaly detector | Detect novel threats not in training data |

---

## ⚙️ Configuration

All settings are in `.env`. Key variables:

```env
THREAT_SCORE_THRESHOLD=0.65    # Alert threshold
THREAT_ALPHA=0.3               # Keyword frequency weight
THREAT_BETA=0.2                # Volume weight
THREAT_GAMMA=0.3               # Sentiment weight
THREAT_DELTA=0.2               # Trend weight
SCRAPE_INTERVAL_SECONDS=60     # Reddit poll interval
```

---

## 🔒 Security Notes

- Never commit `.env` to git — it is listed in `.gitignore`
- The MongoDB admin password in `docker-compose.yml` is for **local development only**
- RSS and NVD scrapers contain **no personal data** — safe by design
- AlienVault OTX data is under [CC BY-NC-SA](https://otx.alienvault.com/api) license

---

*Eye of Horus — Watching for threats so you don't have to.*
