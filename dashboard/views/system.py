"""
Eye of Horus — System Status Page
Pipeline health monitoring, service status, architecture diagram, and configuration.
"""

import streamlit as st

from dashboard.components import render_section_header, render_status_indicator, render_kpi_row
from dashboard.data_service import load_stats, check_mongo_health, get_pipeline_config


def render():
    """Render the System Status page."""

    render_section_header("System Status", icon="⚙️", subtitle="pipeline health and configuration")

    # ── Service Health ────────────────────────────────────────────────────
    stats = load_stats()
    mongo_health = check_mongo_health()

    render_kpi_row([
        {"value": f"{stats['raw']:,}", "label": "Raw Posts", "icon": "📦", "color": "clr-blue"},
        {"value": f"{stats['threats']:,}", "label": "Threat Scores", "icon": "🎯", "color": "clr-cyan"},
        {"value": f"{stats['alerts']:,}", "label": "Alerts", "icon": "🚨", "color": "clr-red"},
    ])

    st.markdown("")

    # ── Service Status ────────────────────────────────────────────────────
    render_section_header("Service Health", icon="💚")

    col_s1, col_s2, col_s3 = st.columns(3)

    with col_s1:
        mongo_online = mongo_health["status"] == "online"
        render_status_indicator("MongoDB", mongo_online, mongo_health["message"])

    with col_s2:
        render_status_indicator("Kafka Broker", True, "localhost:9092")

    with col_s3:
        render_status_indicator("Streamlit Dashboard", True, "localhost:8501")

    st.markdown("")

    # ── Pipeline Architecture ─────────────────────────────────────────────
    render_section_header("Pipeline Architecture", icon="🏗️")

    st.markdown('''<div class="pipeline-box"><pre style="color:#39d4e0;margin:0;">
    ┌─────────────────┐     ┌─────────────┐     ┌──────────────┐     ┌────────────────┐
    │    Scrapers      │────▶│    Kafka     │────▶│   Consumer   │────▶│    MongoDB      │
    │ RSS/OTX/NVD/     │     │  raw-osint   │     │  raw_posts   │     │   raw_posts     │
    │ Reddit/Mock      │     │              │     │              │     │                 │
    └─────────────────┘     └──────┬───────┘     └──────────────┘     └────────────────┘
                                    │
                                    ▼
                           ┌────────────────┐     ┌────────────────┐
                           │   Threat       │────▶│    MongoDB      │
                           │   Processor    │     │ threat_scores   │
                           │  (NLP + Score) │     │    alerts       │
                           └────────────────┘     └───────┬────────┘
                                                          │
                                                          ▼
                                                 ┌────────────────┐
                                                 │   Streamlit    │
                                                 │   SOC Dashboard│
                                                 └────────────────┘
</pre></div>''', unsafe_allow_html=True)

    st.markdown("")

    # ── Configuration ─────────────────────────────────────────────────────
    render_section_header("Configuration", icon="🔧")

    config = get_pipeline_config()
    st.json(config)

    # ── Collection Details ────────────────────────────────────────────────
    with st.expander("📋 Collection Details", expanded=False):
        st.markdown("""
        | Collection | Purpose | TTL |
        |---|---|---|
        | `raw_posts` | Raw scraped OSINT records | 30 days |
        | `threat_scores` | NLP-processed threat scores | Permanent |
        | `alerts` | High-severity threshold alerts | Permanent |
        """)

    # ── Scoring Formula ───────────────────────────────────────────────────
    with st.expander("📐 Threat Scoring Formula", expanded=False):
        st.markdown("""
        ```
        Score = (α × Keyword) + (β × Volume) + (γ × Sentiment) + (δ × Trend)
        ```

        | Variable | Weight | Description |
        |---|---|---|
        | α (Alpha) | 0.30 | Keyword frequency (ddos, exploit, breach...) |
        | β (Beta) | 0.20 | Volume metrics (comment count, engagement) |
        | γ (Gamma) | 0.30 | Negative sentiment / aggressive language |
        | δ (Delta) | 0.20 | Trend / virality (upvote ratio, CVSS score) |

        **Severity Mapping:**
        - `0.85–1.00` → **CRITICAL** 🔴
        - `0.65–0.84` → **HIGH** 🟠
        - `0.40–0.64` → **MEDIUM** 🔵
        - `0.00–0.39` → **LOW** 🟢
        """)
