"""
Eye of Horus — Streamlit Threat Intelligence Dashboard
Real-time visualization of the cyber threat pipeline.

Displays:
    - Live threat score feed from MongoDB
    - Threat score distribution by source
    - High-threat alerts table
    - Keyword frequency heatmap
    - Timeline trend chart

Run:
    streamlit run dashboard/app.py
"""

import sys
import time
from pathlib import Path
from datetime import datetime, timezone, timedelta

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pymongo import MongoClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import mongo as mongo_cfg, threat as threat_cfg

# ══════════════════════════════════════════════════════════════════════════════
#  Page Configuration
# ══════════════════════════════════════════════════════════════════════════════

st.set_page_config(
    page_title="Eye of Horus — Cyber Threat Intelligence",
    page_icon="👁️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');

    html, body, [class*="css"] { font-family: 'Inter', sans-serif; }

    .stApp { background-color: #0d1117; color: #e6edf3; }

    .metric-card {
        background: linear-gradient(135deg, #161b22 0%, #21262d 100%);
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 20px;
        text-align: center;
    }
    .metric-value { font-size: 2.5rem; font-weight: 700; color: #58a6ff; }
    .metric-label { font-size: 0.85rem; color: #8b949e; margin-top: 4px; }

    .critical { color: #f85149 !important; }
    .high     { color: #d29922 !important; }
    .medium   { color: #58a6ff !important; }
    .low      { color: #3fb950 !important; }

    .alert-badge {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    .badge-critical { background: #3d1f1f; color: #f85149; border: 1px solid #f85149; }
    .badge-high     { background: #2d2008; color: #d29922; border: 1px solid #d29922; }
    .badge-medium   { background: #0d2137; color: #58a6ff; border: 1px solid #58a6ff; }
</style>
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
#  MongoDB Data Loader (cached)
# ══════════════════════════════════════════════════════════════════════════════

@st.cache_resource
def get_mongo_client():
    return MongoClient(mongo_cfg.URI, serverSelectionTimeoutMS=3000)


@st.cache_data(ttl=30)  # Refresh every 30 seconds
def load_threat_data(hours_back: int = 24) -> pd.DataFrame:
    """Load processed threat records from MongoDB."""
    try:
        client = get_mongo_client()
        since  = datetime.now(timezone.utc) - timedelta(hours=hours_back)
        docs   = list(
            client[mongo_cfg.DB_NAME][mongo_cfg.COLLECTION_THREATS]
            .find(
                {"processed_at": {"$gte": since.isoformat()}},
                {
                    "post_id": 1, "source": 1, "title": 1, "url": 1,
                    "threat_score": 1, "keyword_score": 1, "sentiment_score": 1,
                    "is_threat": 1, "published_at": 1, "processed_at": 1,
                }
            )
            .sort("threat_score", -1)
            .limit(2000)
        )
        if not docs:
            return pd.DataFrame()
        df = pd.DataFrame(docs)
        df["processed_at"] = pd.to_datetime(df["processed_at"], errors="coerce", utc=True)
        df["published_at"]  = pd.to_datetime(df["published_at"],  errors="coerce", utc=True)
        return df
    except Exception as e:
        st.error(f"MongoDB connection error: {e}")
        return pd.DataFrame()


@st.cache_data(ttl=30)
def load_alerts(limit: int = 50) -> pd.DataFrame:
    """Load high-threat alerts from MongoDB."""
    try:
        client = get_mongo_client()
        docs   = list(
            client[mongo_cfg.DB_NAME][mongo_cfg.COLLECTION_ALERTS]
            .find({}, {"_id": 0})
            .sort("created_at", -1)
            .limit(limit)
        )
        return pd.DataFrame(docs) if docs else pd.DataFrame()
    except Exception:
        return pd.DataFrame()


def score_to_severity(score: float) -> str:
    if score >= 0.85:
        return "CRITICAL"
    elif score >= 0.65:
        return "HIGH"
    elif score >= 0.40:
        return "MEDIUM"
    return "LOW"


def severity_badge(severity: str) -> str:
    cls = f"badge-{severity.lower()}"
    return f'<span class="alert-badge {cls}">{severity}</span>'


# ══════════════════════════════════════════════════════════════════════════════
#  Sidebar
# ══════════════════════════════════════════════════════════════════════════════

with st.sidebar:
    st.markdown("## 👁️ Eye of Horus")
    st.markdown("*Cyber Threat Intelligence*")
    st.divider()

    hours_back = st.slider("⏱ Time Window (hours)", 1, 168, 24)
    threshold  = st.slider(
        "🎚 Threat Threshold", 0.0, 1.0,
        float(threat_cfg.THRESHOLD), step=0.05
    )
    auto_refresh = st.checkbox("🔄 Auto-refresh (30s)", value=True)
    st.divider()

    st.markdown("**Sources**")
    source_filter = st.multiselect(
        "Filter by source",
        options=["reddit", "rss", "alienvault_otx", "nvd_cve"],
        default=["reddit", "rss", "alienvault_otx", "nvd_cve"],
    )
    st.divider()
    st.caption(f"Last refresh: {datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}")


# ══════════════════════════════════════════════════════════════════════════════
#  Main Dashboard
# ══════════════════════════════════════════════════════════════════════════════

st.markdown("# 👁️ Eye of Horus — Threat Intelligence Dashboard")
st.markdown(f"*Monitoring cyber threats in real-time · Last {hours_back}h*")
st.divider()

# ── Load data ─────────────────────────────────────────────────────────────────
df = load_threat_data(hours_back=hours_back)
df_alerts = load_alerts()

if not df.empty and source_filter:
    df = df[df["source"].isin(source_filter)]

# ── KPI Metrics Row ───────────────────────────────────────────────────────────
col1, col2, col3, col4, col5 = st.columns(5)

if not df.empty:
    total_records  = len(df)
    threat_records = df[df["threat_score"] >= threshold]
    n_threats      = len(threat_records)
    avg_score      = df["threat_score"].mean()
    max_score      = df["threat_score"].max()
    n_critical     = len(df[df["threat_score"] >= 0.85])
else:
    total_records = n_threats = avg_score = max_score = n_critical = 0

with col1:
    st.markdown(f"""<div class="metric-card">
        <div class="metric-value">{total_records:,}</div>
        <div class="metric-label">Total Records</div>
    </div>""", unsafe_allow_html=True)

with col2:
    st.markdown(f"""<div class="metric-card">
        <div class="metric-value critical">{n_threats:,}</div>
        <div class="metric-label">Threat Detections</div>
    </div>""", unsafe_allow_html=True)

with col3:
    st.markdown(f"""<div class="metric-card">
        <div class="metric-value critical">{n_critical:,}</div>
        <div class="metric-label">Critical Threats</div>
    </div>""", unsafe_allow_html=True)

with col4:
    st.markdown(f"""<div class="metric-card">
        <div class="metric-value">{avg_score:.3f}</div>
        <div class="metric-label">Avg Threat Score</div>
    </div>""", unsafe_allow_html=True)

with col5:
    st.markdown(f"""<div class="metric-card">
        <div class="metric-value high">{max_score:.3f}</div>
        <div class="metric-label">Max Score</div>
    </div>""", unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ── Row 2: Timeline + Source Distribution ─────────────────────────────────────
col_left, col_right = st.columns([3, 2])

with col_left:
    st.markdown("### 📈 Threat Score Timeline")
    if not df.empty and "processed_at" in df.columns:
        timeline = (
            df.set_index("processed_at")["threat_score"]
            .resample("15min")
            .agg(["mean", "max", "count"])
            .reset_index()
        )
        fig_timeline = go.Figure()
        fig_timeline.add_trace(go.Scatter(
            x=timeline["processed_at"], y=timeline["max"],
            name="Max Score", line=dict(color="#f85149", width=2),
            fill="tozeroy", fillcolor="rgba(248,81,73,0.1)",
        ))
        fig_timeline.add_trace(go.Scatter(
            x=timeline["processed_at"], y=timeline["mean"],
            name="Avg Score", line=dict(color="#58a6ff", width=1.5, dash="dash"),
        ))
        fig_timeline.add_hline(
            y=threshold, line_dash="dot",
            line_color="#d29922", annotation_text=f"Threshold ({threshold})",
        )
        fig_timeline.update_layout(
            paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
            xaxis=dict(color="#8b949e", gridcolor="#21262d"),
            yaxis=dict(color="#8b949e", gridcolor="#21262d", range=[0, 1]),
            legend=dict(bgcolor="#161b22", bordercolor="#30363d"),
            margin=dict(l=0, r=0, t=10, b=0), height=280,
        )
        st.plotly_chart(fig_timeline, use_container_width=True)
    else:
        st.info("No data yet. Start the pipeline to see live data.")

with col_right:
    st.markdown("### 🗂️ Records by Source")
    if not df.empty:
        source_counts = df.groupby("source")["threat_score"].agg(
            count="count", avg_score="mean"
        ).reset_index()
        fig_sources = px.bar(
            source_counts, x="source", y="count",
            color="avg_score", color_continuous_scale="RdYlGn_r",
            range_color=[0, 1],
        )
        fig_sources.update_layout(
            paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
            xaxis=dict(color="#8b949e", gridcolor="#21262d"),
            yaxis=dict(color="#8b949e", gridcolor="#21262d"),
            coloraxis_colorbar=dict(tickfont=dict(color="#8b949e")),
            margin=dict(l=0, r=0, t=10, b=0), height=280,
        )
        st.plotly_chart(fig_sources, use_container_width=True)
    else:
        st.info("Waiting for data...")

# ── Row 3: Threat Score Distribution + Top Threats Table ─────────────────────
col_dist, col_table = st.columns([2, 3])

with col_dist:
    st.markdown("### 📊 Score Distribution")
    if not df.empty:
        fig_hist = px.histogram(
            df, x="threat_score", nbins=40,
            color_discrete_sequence=["#58a6ff"],
        )
        fig_hist.add_vline(
            x=threshold, line_dash="dash",
            line_color="#d29922", annotation_text="Threshold",
        )
        fig_hist.update_layout(
            paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
            xaxis=dict(color="#8b949e", gridcolor="#21262d"),
            yaxis=dict(color="#8b949e", gridcolor="#21262d"),
            bargap=0.05, margin=dict(l=0, r=0, t=10, b=0), height=280,
        )
        st.plotly_chart(fig_hist, use_container_width=True)

with col_table:
    st.markdown("### 🚨 Top Threats")
    if not df.empty:
        top_threats = df[df["threat_score"] >= threshold].head(10).copy()
        if not top_threats.empty:
            top_threats["severity"] = top_threats["threat_score"].apply(score_to_severity)
            top_threats["badge"]    = top_threats["severity"].apply(severity_badge)
            top_threats["title_trunc"] = top_threats["title"].str[:70] + "..."

            display_df = top_threats[["badge", "source", "title_trunc", "threat_score"]].copy()
            display_df.columns = ["Severity", "Source", "Title", "Score"]

            st.write(
                display_df.to_html(escape=False, index=False),
                unsafe_allow_html=True
            )
        else:
            st.success(f"✅ No threats above threshold {threshold} in the last {hours_back}h")
    else:
        st.info("No data available.")

# ── Auto-refresh ──────────────────────────────────────────────────────────────
if auto_refresh:
    time.sleep(30)
    st.rerun()
