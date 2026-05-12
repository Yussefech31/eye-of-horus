# 👁️ Eye of Horus — Cyber Threat Intelligence & SOC Pipeline

> **Automated Cybersecurity Monitoring, OSINT Data Aggregation, and Early Detection of Cyber-Activism Campaigns**

Eye of Horus is a comprehensive, real-time Open-Source Intelligence (OSINT) pipeline. It collects cybersecurity data from public sources (RSS feeds, AlienVault OTX, NVD CVEs, Reddit), processes and scores the data for potential threats using Natural Language Processing (NLP), and presents the findings in a professional, live Streamlit Security Operations Center (SOC) dashboard.

---

## 🏗️ Architecture

```text
┌──────────────────────────────────────────────────────────────────┐
│                         DATA SOURCES                             │
│   Reddit   │   RSS Feeds   │   AlienVault OTX   │   NVD CVEs    │
└─────────────────────────┬────────────────────────────────────────┘
                          │  scraper/orchestrator.py
                          ▼
              ┌───────────────────────┐
              │    Apache Kafka       │  Topic: raw-osint
              │    Message Broker     │
              └──────────┬────────────┘
                         │
                         ▼
                  broker/consumer.py
                  (raw storage bridge)
                         │
                         ▼
        ┌──────────────────────────────────┐
        │             MongoDB              │
        │      Collection: raw_posts       │
        └────────────────┬─────────────────┘
                         │
                         ▼
          spark/threat_processor_basic.py
         (NLP + Threat Scoring + Alerting)
                         │
        ┌────────────────┴─────────────────┐
        ▼                                  ▼
 ┌───────────────┐                  ┌───────────────┐
 │    MongoDB    │                  │    MongoDB    │
 │ threat_scores │                  │    alerts     │
 └──────┬────────┘                  └──────┬────────┘
        │                                  │
        └────────────────┬─────────────────┘
                         ▼
                  dashboard/app.py
          (Streamlit SOC Dashboard :8501)
```

---

## 📁 Project Structure

```text
eye-of-horus/
├── start_project.bat           # 🚀 One-click startup script for Windows
├── docker-compose.yml          # Kafka + Zookeeper + MongoDB + Mongo Express
├── requirements.txt            # Python dependencies
├── .env                        # Environment configuration (API keys, weights)
│
├── config/
│   └── settings.py             # Strongly typed config loader from .env
│
├── scraper/
│   ├── orchestrator.py         # Runs all scrapers concurrently on schedules
│   ├── base_scraper.py         # Abstract base class enforcing standard schema
│   ├── reddit_scraper.py       # Reddit PRAW scraper
│   ├── rss_scraper.py          # 8 cybersecurity RSS feeds (BleepingComputer, Hacker News, etc.)
│   ├── otx_scraper.py          # AlienVault OTX threat pulses
│   └── nvd_scraper.py          # NIST NVD CVE vulnerability feed
│
├── broker/
│   ├── producer.py             # Kafka producer wrapper with retry logic
│   └── consumer.py             # Kafka → MongoDB raw_posts persistence
│
├── spark/
│   ├── threat_processor_basic.py # Pure Python NLP pipeline & threat scoring
│   ├── threat_processor.py     # Legacy PySpark implementation
│   └── udfs.py                 # PySpark User Defined Functions
│
├── models/
│   ├── threat_classifier.py    # Machine Learning models (LR, RF, Isolation Forest)
│   └── *.pkl                   # Serialized trained models
│
├── dashboard/
│   └── app.py                  # Streamlit 5-tab SOC Dashboard
│
└── data/
    └── mongo-init.js           # MongoDB initialization (indexes, collections)
```

---

## ⚙️ Core Components Explained

### 1. Data Ingestion (Scrapers)
The `scraper/orchestrator.py` script runs multiple background threads, each executing a specific scraper on a schedule. 
- **RSS**: Polls every 5 minutes.
- **NVD CVE**: Polls every 5 minutes.
- **AlienVault OTX**: Polls every 60 minutes.
All scraped data is normalized into a standard JSON schema and pushed to the Kafka `raw-osint` topic.

### 2. Message Broker (Kafka)
Kafka acts as the high-throughput buffer. The `broker/consumer.py` (powered by `confluent-kafka` for maximum stability) reads from `raw-osint` and bulk-upserts the raw data into the MongoDB `raw_posts` collection. This decouples data ingestion from data processing.

### 3. Threat Processing (NLP & Scoring)
The `spark/threat_processor_basic.py` continuously polls the MongoDB `raw_posts` collection for unprocessed items. It applies:
- **Text Cleaning**: Normalizes text and removes noise.
- **Keyword Frequency**: Checks for malicious terms (e.g., "ddos", "ransomware").
- **Sentiment Analysis**: Detects aggressive or negative language.
- **Volume & Trend Analysis**: Uses metrics like comment counts or CVSS scores.

It calculates a final `threat_score` (0.0 to 1.0) and saves it to the `threat_scores` collection. If the score exceeds the threshold (default `0.65`), it also generates a record in the `alerts` collection.

### 4. Streamlit SOC Dashboard
A modern, dark-themed dashboard (`dashboard/app.py`) providing a professional SOC interface with 5 tabs:
- **🏠 Overview**: KPI cards, threat timeline charts, and top threats table.
- **🚨 Live Alerts**: A dedicated feed for high-severity alerts.
- **📊 Analytics**: Visualizations of score distributions, source breakdowns, and NLP scatter plots.
- **🔍 Explorer**: A searchable, filterable data grid of all threat intelligence records.
- **⚙️ System Status**: Real-time pipeline health, MongoDB collection counts, and architecture overview.

---

## ⚡ Quick Start Guide

### Step 1: Environment Setup
Ensure you have Python 3.12+ and Docker installed.
Create a Python virtual environment and install dependencies:
```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### Step 2: Configuration
Create a `.env` file in the root directory (copy from `.env.example` if available) and add your API keys:
```env
OTX_API_KEY=your_alienvault_otx_key_here
REDDIT_CLIENT_ID=your_reddit_client_id
REDDIT_CLIENT_SECRET=your_reddit_secret
```

### Step 3: Run the Pipeline (One-Click)
Double-click the **`start_project.bat`** file on Windows. This script will automatically:
1. Start Docker Compose (Kafka, Zookeeper, MongoDB).
2. Launch the Scraper Orchestrator.
3. Launch the Broker Consumer.
4. Launch the Threat Processor.
5. Open the Streamlit Dashboard.

Alternatively, you can run them manually in separate terminals:
```bash
docker-compose up -d
python scraper/orchestrator.py
python broker/consumer.py
python spark/threat_processor_basic.py
streamlit run dashboard/app.py
```

### Step 4: Access the Dashboard
Open your browser and navigate to: **http://localhost:8501**

---

## 📊 Threat Score Formula

The threat score is a weighted sum designed to calculate the severity of an OSINT record:
```
Score = (α * Keyword) + (β * Volume) + (γ * Sentiment) + (δ * Trend)
```

| Variable | Default Weight | Description |
|---|---|---|
| `α` (Alpha) | 0.30 | Keyword frequency (e.g., ddos, exploit, breach) |
| `β` (Beta) | 0.20 | Volume metrics (e.g., number of comments) |
| `γ` (Gamma) | 0.30 | Negative sentiment / aggressive language |
| `δ` (Delta) | 0.20 | Trend / Virality (e.g., upvote ratio, CVSS score) |

Scores map to the following severities:
- `0.85 - 1.00`: **CRITICAL**
- `0.65 - 0.84`: **HIGH** (Triggers Alert)
- `0.40 - 0.64`: **MEDIUM**
- `0.00 - 0.39`: **LOW**

---

## 🛠️ Technology Stack

- **Backend / Processing**: Python 3.14, Pandas, Tenacity, Loguru, Confluent-Kafka
- **Message Broker**: Apache Kafka, Zookeeper
- **Database**: MongoDB
- **Frontend**: Streamlit, Plotly (Interactive Charts)
- **Infrastructure**: Docker, Docker Compose

---

*Eye of Horus — Watching for threats so you don't have to.*
