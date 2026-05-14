# 👁️ Eye of Horus — Cyber Threat Intelligence & SOC Pipeline
 
> **Real-Time OSINT Aggregation, Geospatial Threat Intelligence, AI-Powered Analysis, and Advanced SOC Operations**
 
Eye of Horus is a full-stack, real-time Open-Source Intelligence (OSINT) pipeline engineered for modern Security Operations Centers. It ingests cybersecurity data from public sources (RSS feeds, AlienVault OTX, NVD CVEs, Reddit), enriches it with NLP-based threat scoring and **geolocation attribution**, and presents findings in a professional, live SOC dashboard with 11 specialized operational modules.
 
---
 
## 🏗️ Architecture
 
```text
┌──────────────────────────────────────────────────────────────────────────┐
│                             DATA SOURCES                                 │
│   Reddit   │   RSS Feeds   │   AlienVault OTX   │   NVD CVEs            │
└──────────────────────────────┬───────────────────────────────────────────┘
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
           ┌──────────────────────────────────────┐
           │               MongoDB                │
           │         Collection: raw_posts        │
           └───────────────────┬──────────────────┘
                               │
                               ▼
             spark/threat_processor_basic.py
        (NLP + Threat Scoring + Geo Attribution)
                               │
        ┌──────────────────────┼──────────────────────┐
        ▼                      ▼                      ▼
 ┌─────────────┐       ┌─────────────┐       ┌─────────────┐
 │   MongoDB   │       │   MongoDB   │       │   MongoDB   │
 │threat_scores│       │   alerts    │       │  geo_events │
 └──────┬──────┘       └──────┬──────┘       └──────┬──────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              ▼
                       dashboard/app.py
               (Streamlit SOC Dashboard :8501)
                    11-Module Command Center
```
 
---
 
## 📁 Project Structure
 
```text
eye-of-horus/
├── start_project.bat               # 🚀 One-click startup script for Windows
├── docker-compose.yml              # Kafka + Zookeeper + MongoDB + Mongo Express
├── requirements.txt                # Python dependencies
├── .env                            # Environment configuration (API keys, weights)
│
├── config/
│   └── settings.py                 # Strongly typed config loader from .env
│
├── scraper/
│   ├── orchestrator.py             # Runs all scrapers concurrently on schedules
│   ├── base_scraper.py             # Abstract base class enforcing standard schema
│   ├── reddit_scraper.py           # Reddit PRAW scraper
│   ├── rss_scraper.py              # 8 cybersecurity RSS feeds (BleepingComputer, Hacker News, etc.)
│   ├── otx_scraper.py              # AlienVault OTX threat pulses
│   └── nvd_scraper.py              # NIST NVD CVE vulnerability feed
│
├── broker/
│   ├── producer.py                 # Kafka producer wrapper with retry logic
│   └── consumer.py                 # Kafka → MongoDB raw_posts persistence
│
├── spark/
│   ├── threat_processor_basic.py   # NLP pipeline, threat scoring & geo attribution
│   ├── threat_processor.py         # Legacy PySpark implementation
│   └── udfs.py                     # PySpark User Defined Functions
│
├── nlp/
│   ├── geo_extractor.py            # NLP-based geolocation entity extraction
│   ├── ip_resolver.py              # IP → Country/City/ASN resolution (MaxMind)
│   └── attack_origin.py            # Attack origin classifier & confidence scorer
│
├── models/
│   ├── threat_classifier.py        # ML models (LR, RF, Isolation Forest)
│   └── *.pkl                       # Serialized trained models
│
├── dashboard/
│   └── app.py                      # Streamlit 11-module SOC Dashboard
│
└── data/
    └── mongo-init.js               # MongoDB initialization (indexes, collections)
```
 
---
 
## ⚙️ Core Components
 
### 1. Data Ingestion (Scrapers)
The `scraper/orchestrator.py` script runs multiple background threads, each executing a specific scraper on a schedule.
 
- **RSS**: Polls 8 cybersecurity feeds every 5 minutes.
- **NVD CVE**: Polls every 5 minutes.
- **AlienVault OTX**: Polls every 60 minutes.
All scraped data is normalized into a standard JSON schema and pushed to the Kafka `raw-osint` topic.
 
### 2. Message Broker (Kafka)
Kafka acts as the high-throughput buffer. The `broker/consumer.py` reads from `raw-osint` and bulk-upserts raw data into the MongoDB `raw_posts` collection, fully decoupling ingestion from processing.
 
### 3. NLP Threat Processing + Geolocation Attribution
The `spark/threat_processor_basic.py` pipeline continuously polls MongoDB for unprocessed items and applies a multi-stage enrichment chain:
 
**Threat Scoring:**
- **Text Cleaning**: Normalizes text and removes noise.
- **Keyword Frequency**: Flags malicious terms (e.g., "ddos", "ransomware", "exploit").
- **Sentiment Analysis**: Detects aggressive or negative language.
- **Volume & Trend Analysis**: Uses engagement metrics (comments, CVSS scores, upvote ratios).
**Geolocation Attribution (new):**
- **NER Geolocation Extraction** (`nlp/geo_extractor.py`): Applies Named Entity Recognition to extract country, city, and region mentions from threat text using spaCy.
- **IP-to-Geo Resolution** (`nlp/ip_resolver.py`): Resolves IP addresses embedded in threat data to physical locations using MaxMind GeoLite2, including Country, City, and ASN metadata.
- **Attack Origin Classification** (`nlp/attack_origin.py`): Combines NER output and IP resolution into a confidence-scored attack origin, powering the live Attack Map.
Results are written to the `threat_scores`, `alerts`, and `geo_events` MongoDB collections.
 
### 4. Machine Learning Models
The `models/threat_classifier.py` supports three classifiers trained on historical threat data:
 
- **Logistic Regression**: Fast binary threat classification.
- **Random Forest**: Higher-accuracy multi-class severity classification.
- **Isolation Forest**: Unsupervised anomaly detection for zero-day-style outliers.
### 5. SOC Dashboard — 11 Operational Modules
A dark-themed, professional SOC interface (`dashboard/app.py`) with 11 specialized tabs:
 
| Module | Description |
|---|---|
| 🏠 **Command Center** | KPI cards, threat timeline, top threats table — the primary ops view |
| 🌐 **Attack Map** | Live world map visualizing geolocated attack origins and targets in real time |
| 🔗 **Correlation** | Cross-source event correlation to identify coordinated multi-vector campaigns |
| 📉 **Anomalies** | Isolation Forest-powered anomaly feed surfacing statistical outliers |
| 🤖 **AI Analyst** | Conversational AI interface for on-demand threat analysis and reporting |
| 🎮 **Simulation** | Tabletop exercise simulator for red/blue team scenario generation |
| 🚨 **Live Alerts** | Real-time feed of HIGH and CRITICAL severity alerts with full context |
| 📊 **Analytics** | Score distributions, source breakdowns, NLP scatter plots, and geo heatmaps |
| 🔍 **Explorer** | Searchable, filterable data grid across all collected threat intelligence records |
| 📋 **Reports** | Automated report generation (PDF/HTML) for shift handovers and stakeholder briefings |
| ⚙️ **System** | Pipeline health, MongoDB collection counts, and live architecture overview |
 
---
 
## ⚡ Quick Start
 
### Step 1: Environment Setup
Ensure you have Python 3.12+ and Docker installed. Create a virtual environment and install dependencies:
```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```
 
You will also need to download the MaxMind GeoLite2 database for geolocation features:
```bash
# Place GeoLite2-City.mmdb and GeoLite2-ASN.mmdb in data/maxmind/
```
 
### Step 2: Configuration
Create a `.env` file in the root directory (copy from `.env.example`) and populate your keys:
```env
OTX_API_KEY=your_alienvault_otx_key_here
REDDIT_CLIENT_ID=your_reddit_client_id
REDDIT_CLIENT_SECRET=your_reddit_secret
MAXMIND_DB_PATH=data/maxmind/GeoLite2-City.mmdb
GEO_CONFIDENCE_THRESHOLD=0.70
```
 
### Step 3: Run the Pipeline (One-Click)
Double-click **`start_project.bat`** on Windows. It will automatically:
 
1. Start Docker Compose (Kafka, Zookeeper, MongoDB).
2. Launch the Scraper Orchestrator.
3. Launch the Broker Consumer.
4. Launch the Threat Processor (NLP + Geo).
5. Open the Streamlit Dashboard.
Alternatively, run each component manually in separate terminals:
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
 
The threat score is a weighted sum across four NLP-derived signals:
 
```
Score = (α × Keyword) + (β × Volume) + (γ × Sentiment) + (δ × Trend)
```
 
| Variable | Default Weight | Description |
|---|---|---|
| `α` Alpha | 0.30 | Keyword frequency (ddos, exploit, breach, ransomware, …) |
| `β` Beta | 0.20 | Volume metrics (comment count, CVE references) |
| `γ` Gamma | 0.30 | Negative sentiment / aggressive language intensity |
| `δ` Delta | 0.20 | Trend / virality (upvote ratio, CVSS base score) |
 
Scores map to the following severity levels:
 
| Range | Severity | Behavior |
|---|---|---|
| 0.85 – 1.00 | 🔴 CRITICAL | Alert + Attack Map pin + Report flagging |
| 0.65 – 0.84 | 🟠 HIGH | Alert generated, shown in Live Alerts tab |
| 0.40 – 0.64 | 🟡 MEDIUM | Logged to threat_scores, visible in Explorer |
| 0.00 – 0.39 | 🟢 LOW | Stored for baseline and anomaly modeling |
 
---
 
## 🗺️ Geolocation Pipeline
 
Attack origins are resolved through a three-stage attribution chain:
 
```
Raw Text / IP Address
        │
        ▼
┌───────────────────┐     ┌─────────────────────┐
│  NER Extraction   │     │   IP Geo Resolution  │
│  (spaCy NER)      │     │   (MaxMind GeoLite2) │
│  GPE / LOC tags   │     │   Country/City/ASN   │
└────────┬──────────┘     └──────────┬────────────┘
         │                           │
         └─────────────┬─────────────┘
                       ▼
            Attack Origin Classifier
            (Confidence Score 0–1.0)
                       │
                       ▼
              geo_events collection
                       │
                       ▼
              🌐 Attack Map Tab
```
 
Geo-events are stored with `latitude`, `longitude`, `country_code`, `city`, `asn`, `confidence`, and `linked_threat_id` fields, enabling the Attack Map to render real-time origin pins and arc animations between source and target regions.
 
---
 
## 🛠️ Technology Stack
 
| Layer | Technologies |
|---|---|
| **Data Ingestion** | Python 3.12+, PRAW, FeedParser, Requests, Tenacity |
| **NLP & ML** | spaCy, scikit-learn, NLTK, MaxMind GeoLite2 |
| **Message Broker** | Apache Kafka, Zookeeper, Confluent-Kafka |
| **Database** | MongoDB, PyMongo |
| **Dashboard** | Streamlit, Plotly, Folium (Attack Map) |
| **Infrastructure** | Docker, Docker Compose |
| **Logging** | Loguru |
 
---
 
*Eye of Horus — Watching for threats, tracing their origins, so you don't have to.*
