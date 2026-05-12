"""
Eye of Horus — SOC Threat Intelligence Dashboard
"""
import sys, time
from pathlib import Path
from datetime import datetime, timezone, timedelta
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pymongo import MongoClient
from streamlit_autorefresh import st_autorefresh

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import mongo as mongo_cfg, threat as threat_cfg, kafka as kafka_cfg

st.set_page_config(page_title="Eye of Horus — SOC", page_icon="👁️", layout="wide", initial_sidebar_state="expanded")

st.markdown("""<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=JetBrains+Mono:wght@400;700&display=swap');
html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
.stApp { background: linear-gradient(180deg, #0a0e17 0%, #0d1117 100%); color: #e6edf3; }
.block-container { padding-top: 1rem; }
div[data-testid="stTabs"] button { font-size: 1rem; font-weight: 600; }
div[data-testid="stTabs"] button[aria-selected="true"] { border-bottom: 3px solid #58a6ff; color: #58a6ff; }
.kpi-card { background: linear-gradient(135deg, rgba(22,27,34,0.9), rgba(33,38,45,0.9)); border: 1px solid #30363d; border-radius: 14px; padding: 18px 14px; text-align: center; backdrop-filter: blur(10px); transition: transform 0.2s, border-color 0.2s; }
.kpi-card:hover { transform: translateY(-2px); border-color: #58a6ff; }
.kpi-val { font-family: 'JetBrains Mono', monospace; font-size: 2.2rem; font-weight: 700; }
.kpi-label { font-size: 0.8rem; color: #8b949e; margin-top: 4px; letter-spacing: 0.5px; text-transform: uppercase; }
.clr-blue { color: #58a6ff; } .clr-red { color: #f85149; } .clr-amber { color: #d29922; } .clr-green { color: #3fb950; }
.alert-row { background: rgba(22,27,34,0.8); border: 1px solid #21262d; border-radius: 10px; padding: 12px 16px; margin-bottom: 8px; border-left: 4px solid #30363d; }
.alert-row.sev-critical { border-left-color: #f85149; } .alert-row.sev-high { border-left-color: #d29922; } .alert-row.sev-medium { border-left-color: #58a6ff; }
.badge { display: inline-block; padding: 2px 10px; border-radius: 20px; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.5px; }
.badge-critical { background: #3d1f1f; color: #f85149; border: 1px solid #f85149; }
.badge-high { background: #2d2008; color: #d29922; border: 1px solid #d29922; }
.badge-medium { background: #0d2137; color: #58a6ff; border: 1px solid #58a6ff; }
.badge-low { background: #0d2917; color: #3fb950; border: 1px solid #3fb950; }
.status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
.dot-green { background: #3fb950; box-shadow: 0 0 6px #3fb950; } .dot-red { background: #f85149; box-shadow: 0 0 6px #f85149; }
table { width: 100%; border-collapse: collapse; }
th { background: #161b22; color: #8b949e; padding: 10px 12px; text-align: left; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.5px; }
td { padding: 10px 12px; border-bottom: 1px solid #21262d; font-size: 0.85rem; }
tr:hover { background: rgba(88,166,255,0.05); }
</style>""", unsafe_allow_html=True)

# ── Data Loading ──
@st.cache_resource
def get_mongo():
    return MongoClient(mongo_cfg.URI, serverSelectionTimeoutMS=3000)

def _try_dt(val):
    if isinstance(val, datetime): return val
    if isinstance(val, str):
        try: return datetime.fromisoformat(val)
        except: pass
    return None

@st.cache_data(ttl=2)
def load_threats(hours_back: int = 24) -> pd.DataFrame:
    try:
        client = get_mongo()
        col = client[mongo_cfg.DB_NAME][mongo_cfg.COLLECTION_THREATS]
        since = datetime.utcnow() - timedelta(hours=hours_back)
        # Try datetime query first, fall back to string query, then no filter
        for q in [{"processed_at": {"$gte": since}}, {"processed_at": {"$gte": since.isoformat()}}, {}]:
            docs = list(col.find(q, {"_id": 0}).sort("threat_score", -1).limit(5000))
            if docs: break
        if not docs: return pd.DataFrame()
        df = pd.DataFrame(docs)
        if "processed_at" in df.columns:
            df["processed_at"] = df["processed_at"].apply(_try_dt)
            df["processed_at"] = pd.to_datetime(df["processed_at"], errors="coerce", utc=True)
        if "published_at" in df.columns:
            df["published_at"] = df["published_at"].apply(_try_dt)
            df["published_at"] = pd.to_datetime(df["published_at"], errors="coerce", utc=True)
        for c in ["threat_score","keyword_score","sentiment_score"]:
            if c in df.columns: df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)
        if "severity" not in df.columns and "threat_score" in df.columns:
            df["severity"] = df["threat_score"].apply(lambda s: "CRITICAL" if s>=0.85 else "HIGH" if s>=0.65 else "MEDIUM" if s>=0.4 else "LOW")
        return df
    except Exception as e:
        st.error(f"MongoDB error: {e}")
        return pd.DataFrame()

@st.cache_data(ttl=2)
def load_alerts(limit=100) -> pd.DataFrame:
    try:
        client = get_mongo()
        docs = list(client[mongo_cfg.DB_NAME][mongo_cfg.COLLECTION_ALERTS].find({}, {"_id": 0}).sort("created_at", -1).limit(limit))
        return pd.DataFrame(docs) if docs else pd.DataFrame()
    except: return pd.DataFrame()

@st.cache_data(ttl=2)
def load_stats() -> dict:
    try:
        client = get_mongo()
        db = client[mongo_cfg.DB_NAME]
        return {"raw": db[mongo_cfg.COLLECTION_RAW].count_documents({}), "threats": db[mongo_cfg.COLLECTION_THREATS].count_documents({}), "alerts": db[mongo_cfg.COLLECTION_ALERTS].count_documents({})}
    except: return {"raw": 0, "threats": 0, "alerts": 0}

def badge(sev):
    return f'<span class="badge badge-{sev.lower()}">{sev}</span>'

CHART_LAYOUT = dict(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#8b949e", size=11), margin=dict(l=10,r=10,t=30,b=10),
    xaxis=dict(gridcolor="#21262d", zerolinecolor="#21262d"),
    yaxis=dict(gridcolor="#21262d", zerolinecolor="#21262d"),
    legend=dict(bgcolor="rgba(22,27,34,0.8)", bordercolor="#30363d"))

# ── Sidebar ──
with st.sidebar:
    st.markdown("## 👁️ Eye of Horus")
    st.markdown("*Security Operations Center*")
    st.divider()
    minutes_back = st.slider("⏱ Time Window (Minutes)", 1, 1440, 60, format="%d min")
    hours_back = minutes_back / 60.0
    threshold = st.slider("🎚 Threat Threshold", 0.0, 1.0, float(threat_cfg.THRESHOLD), 0.05)
    source_filter = st.multiselect("📡 Sources", ["reddit","rss","alienvault_otx","nvd_cve", "mock_generator"], default=["reddit","rss","alienvault_otx","nvd_cve", "mock_generator"])
    auto_refresh = st.checkbox("🔄 Auto-refresh (2s)", value=True)
    st.divider()
    stats = load_stats()
    st.markdown("**Pipeline Status**")
    st.markdown(f'<span class="status-dot dot-green"></span> MongoDB connected', unsafe_allow_html=True)
    st.caption(f"📦 Raw posts: **{stats['raw']:,}**")
    st.caption(f"🎯 Scored: **{stats['threats']:,}**")
    st.caption(f"🚨 Alerts: **{stats['alerts']:,}**")
    st.divider()
    st.caption(f"Last refresh: {datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}")

# ── Load Data ──
df = load_threats(hours_back)
df_alerts = load_alerts()
if not df.empty and source_filter:
    df = df[df["source"].isin(source_filter)]

# ── Header ──
st.markdown("# 👁️ Eye of Horus — Threat Intelligence")
if not df.empty:
    n_threats = len(df[df["threat_score"] >= threshold])
    if n_threats > 0:
        st.markdown(f'<div style="background:rgba(248,81,73,0.1);border:1px solid #f85149;border-radius:8px;padding:8px 16px;color:#f85149;font-weight:600;">🚨 {n_threats} active threat{"s" if n_threats!=1 else ""} detected in the last {hours_back}h</div>', unsafe_allow_html=True)
st.markdown("")

# ── Tabs ──
tab_overview, tab_alerts, tab_analytics, tab_explorer, tab_system = st.tabs(["🏠 Overview", "🚨 Live Alerts", "📊 Analytics", "🔍 Explorer", "⚙️ System"])

# ════════════════════════════════════════════════════════════════════════
#  TAB 1: OVERVIEW
# ════════════════════════════════════════════════════════════════════════
with tab_overview:
    if df.empty:
        st.info("No data yet. Start the pipeline with `start_project.bat`.")
    else:
        total = len(df); threats = len(df[df["threat_score"]>=threshold]); crit = len(df[df["threat_score"]>=0.85])
        avg_s = df["threat_score"].mean(); max_s = df["threat_score"].max()
        c1,c2,c3,c4,c5 = st.columns(5)
        for col,val,lbl,clr in [(c1,f"{total:,}","Total Records","clr-blue"),(c2,f"{threats:,}","Threats","clr-red"),(c3,f"{crit:,}","Critical","clr-red"),(c4,f"{avg_s:.3f}","Avg Score","clr-amber"),(c5,f"{max_s:.3f}","Max Score","clr-amber")]:
            col.markdown(f'<div class="kpi-card"><div class="kpi-val {clr}">{val}</div><div class="kpi-label">{lbl}</div></div>', unsafe_allow_html=True)
        st.markdown("")
        cl, cr = st.columns([3,2])
        with cl:
            st.markdown("#### 📈 Threat Score Timeline")
            if "processed_at" in df.columns and df["processed_at"].notna().any():
                tdf = df.dropna(subset=["processed_at"]).set_index("processed_at")["threat_score"].resample("15min").agg(["mean","max","count"]).reset_index()
                fig = go.Figure()
                fig.add_trace(go.Scatter(x=tdf["processed_at"],y=tdf["max"],name="Max",line=dict(color="#f85149",width=2),fill="tozeroy",fillcolor="rgba(248,81,73,0.08)"))
                fig.add_trace(go.Scatter(x=tdf["processed_at"],y=tdf["mean"],name="Avg",line=dict(color="#58a6ff",width=1.5,dash="dash")))
                fig.add_hline(y=threshold,line_dash="dot",line_color="#d29922",annotation_text=f"Threshold ({threshold})")
                fig.update_layout(**CHART_LAYOUT, height=300, yaxis_range=[0,1])
                st.plotly_chart(fig, use_container_width=True)
            else: st.info("Waiting for timestamped data...")
        with cr:
            st.markdown("#### 🗂️ Records by Source")
            sc = df.groupby("source")["threat_score"].agg(count="count",avg_score="mean").reset_index()
            fig2 = px.bar(sc, x="source", y="count", color="avg_score", color_continuous_scale="RdYlGn_r", range_color=[0,1])
            fig2.update_layout(**CHART_LAYOUT, height=300, coloraxis_colorbar=dict(tickfont=dict(color="#8b949e")))
            st.plotly_chart(fig2, use_container_width=True)
        st.markdown("#### 🚨 Top 10 Threats")
        top = df[df["threat_score"]>=threshold].head(10).copy()
        if not top.empty:
            rows = ""
            for _,r in top.iterrows():
                sev = r.get("severity","MEDIUM")
                b = badge(sev)
                title = str(r.get("title",""))[:80]
                url = r.get("url","#")
                rows += f'<tr><td>{b}</td><td>{r.get("source","")}</td><td><a href="{url}" target="_blank" style="color:#58a6ff;text-decoration:none;">{title}</a></td><td style="font-family:JetBrains Mono;font-weight:700;">{r["threat_score"]:.3f}</td></tr>'
            st.markdown(f'<table><thead><tr><th>Severity</th><th>Source</th><th>Title</th><th>Score</th></tr></thead><tbody>{rows}</tbody></table>', unsafe_allow_html=True)
        else:
            st.success(f"✅ No threats above {threshold} in the last {hours_back}h")

# ════════════════════════════════════════════════════════════════════════
#  TAB 2: LIVE ALERTS
# ════════════════════════════════════════════════════════════════════════
with tab_alerts:
    st.markdown("#### 🚨 Live Alert Feed")
    # Use alerts collection, fall back to high-threat records
    alert_data = df_alerts if not df_alerts.empty else (df[df["threat_score"]>=threshold] if not df.empty else pd.DataFrame())
    if alert_data.empty:
        st.info("No alerts generated yet. The threat processor will create alerts when scores exceed the threshold.")
    else:
        for _, a in alert_data.head(30).iterrows():
            sev = str(a.get("severity", "MEDIUM"))
            sev_class = f"sev-{sev.lower()}"
            b = badge(sev)
            title = str(a.get("title","N/A"))[:90]
            src = a.get("source","")
            score = float(a.get("threat_score",0))
            url = a.get("url","#")
            ts = a.get("created_at", a.get("processed_at",""))
            if isinstance(ts, datetime): ts = ts.strftime("%Y-%m-%d %H:%M UTC")
            st.markdown(f'''<div class="alert-row {sev_class}">
                <div style="display:flex;justify-content:space-between;align-items:center;">
                    <div>{b} &nbsp; <strong><a href="{url}" target="_blank" style="color:#e6edf3;text-decoration:none;">{title}</a></strong></div>
                    <div style="font-family:JetBrains Mono;font-weight:700;font-size:1.1rem;color:#f85149;">{score:.3f}</div>
                </div>
                <div style="margin-top:6px;font-size:0.78rem;color:#8b949e;">📡 {src} &nbsp;·&nbsp; 🕐 {ts}</div>
            </div>''', unsafe_allow_html=True)

# ════════════════════════════════════════════════════════════════════════
#  TAB 3: ANALYTICS
# ════════════════════════════════════════════════════════════════════════
with tab_analytics:
    if df.empty:
        st.info("No data available for analytics.")
    else:
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("#### 📊 Score Distribution")
            fig_h = px.histogram(df, x="threat_score", nbins=40, color_discrete_sequence=["#58a6ff"])
            fig_h.add_vline(x=threshold, line_dash="dash", line_color="#d29922", annotation_text="Threshold")
            fig_h.update_layout(**CHART_LAYOUT, height=300, bargap=0.05)
            st.plotly_chart(fig_h, use_container_width=True)
        with c2:
            st.markdown("#### 🎯 Severity Breakdown")
            if "severity" in df.columns:
                sev_counts = df["severity"].value_counts().reset_index()
                sev_counts.columns = ["severity","count"]
                colors = {"CRITICAL":"#f85149","HIGH":"#d29922","MEDIUM":"#58a6ff","LOW":"#3fb950"}
                fig_d = px.pie(sev_counts, values="count", names="severity", color="severity", color_discrete_map=colors, hole=0.55)
                fig_d.update_layout(**CHART_LAYOUT, height=300, showlegend=True)
                fig_d.update_traces(textinfo="percent+label", textfont_size=11)
                st.plotly_chart(fig_d, use_container_width=True)
        c3, c4 = st.columns(2)
        with c3:
            st.markdown("#### 📡 Source × Avg Threat Score")
            if "source" in df.columns:
                src_stats = df.groupby("source").agg(count=("threat_score","count"), avg=("threat_score","mean"), max_s=("threat_score","max")).reset_index()
                fig_s = go.Figure()
                fig_s.add_trace(go.Bar(x=src_stats["source"], y=src_stats["avg"], name="Avg Score", marker_color="#58a6ff"))
                fig_s.add_trace(go.Bar(x=src_stats["source"], y=src_stats["max_s"], name="Max Score", marker_color="#f85149"))
                fig_s.update_layout(**CHART_LAYOUT, height=300, barmode="group")
                st.plotly_chart(fig_s, use_container_width=True)
        with c4:
            st.markdown("#### 📈 Keyword vs Sentiment Scores")
            if "keyword_score" in df.columns and "sentiment_score" in df.columns:
                fig_sc = px.scatter(df, x="keyword_score", y="sentiment_score", color="threat_score",
                    color_continuous_scale="RdYlGn_r", range_color=[0,1], size="threat_score",
                    size_max=12, hover_data=["source","title"])
                fig_sc.update_layout(**CHART_LAYOUT, height=300)
                st.plotly_chart(fig_sc, use_container_width=True)

# ════════════════════════════════════════════════════════════════════════
#  TAB 4: THREAT EXPLORER
# ════════════════════════════════════════════════════════════════════════
with tab_explorer:
    st.markdown("#### 🔍 Threat Explorer")
    if df.empty:
        st.info("No data available.")
    else:
        search = st.text_input("🔎 Search titles...", "", key="search_threats")
        min_score = st.slider("Minimum threat score", 0.0, 1.0, 0.0, 0.05, key="min_score_explorer")
        filtered = df[df["threat_score"] >= min_score]
        if search:
            filtered = filtered[filtered["title"].str.contains(search, case=False, na=False)]
        st.caption(f"Showing {len(filtered):,} records")
        if not filtered.empty:
            display_cols = [c for c in ["severity","source","title","threat_score","keyword_score","sentiment_score","published_at"] if c in filtered.columns]
            st.dataframe(filtered[display_cols].head(200), use_container_width=True, height=500)
            csv = filtered[display_cols].to_csv(index=False)
            st.download_button("📥 Export CSV", csv, "threats_export.csv", "text/csv")

# ════════════════════════════════════════════════════════════════════════
#  TAB 5: SYSTEM STATUS
# ════════════════════════════════════════════════════════════════════════
with tab_system:
    st.markdown("#### ⚙️ System Status")
    stats = load_stats()
    sc1, sc2, sc3 = st.columns(3)
    sc1.metric("📦 Raw Posts", f"{stats['raw']:,}")
    sc2.metric("🎯 Threat Scores", f"{stats['threats']:,}")
    sc3.metric("🚨 Alerts", f"{stats['alerts']:,}")
    st.divider()
    st.markdown("**Pipeline Architecture**")
    st.code("""
    ┌─────────────┐     ┌───────────┐     ┌──────────────┐     ┌────────────────┐
    │   Scrapers   │────▶│   Kafka   │────▶│   Consumer   │────▶│    MongoDB     │
    │ RSS/OTX/NVD  │     │ raw-osint │     │  raw_posts   │     │   raw_posts    │
    └─────────────┘     └─────┬─────┘     └──────────────┘     └────────────────┘
                              │
                              ▼
                     ┌────────────────┐     ┌────────────────┐
                     │   Threat       │────▶│    MongoDB     │
                     │   Processor    │     │ threat_scores  │
                     │  (NLP + Score) │     │    alerts      │
                     └────────────────┘     └───────┬────────┘
                                                    │
                                                    ▼
                                           ┌────────────────┐
                                           │   Streamlit    │
                                           │   Dashboard    │
                                           └────────────────┘
    """, language=None)
    st.divider()
    st.markdown("**Configuration**")
    st.json({"kafka_bootstrap": kafka_cfg.BOOTSTRAP_SERVERS, "kafka_topic_raw": kafka_cfg.TOPIC_RAW,
             "mongo_db": mongo_cfg.DB_NAME, "threshold": threat_cfg.THRESHOLD,
             "scoring_weights": {"alpha": threat_cfg.ALPHA, "beta": threat_cfg.BETA, "gamma": threat_cfg.GAMMA, "delta": threat_cfg.DELTA}})

# ── Auto-refresh ──
if auto_refresh:
    st_autorefresh(interval=2000, key="soc_dashboard_refresh")
