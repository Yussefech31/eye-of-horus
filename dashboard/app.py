"""
Eye of Horus — SOC Threat Intelligence Dashboard
Enterprise-grade multi-page Streamlit application.

Navigation:
    🏠 Command Center   — Overview KPIs, timeline, top threats
    🌍 Attack Map       — Global threat geolocation and density
    🔗 Correlation      — Threat clustering and IOC analysis
    📉 Anomalies        — Statistical threat volume anomaly detection
    🤖 AI Analyst       — Automated triage and mitigation
    🎮 Simulation       — Control synthetic threat scenarios
    🚨 Live Alerts      — Real-time alert feed with acknowledge actions
    📊 Analytics        — Advanced threat analytics and visualizations
    🔍 Explorer         — Searchable threat intelligence data grid
    📑 Reports          — PDF and CSV report generation
    ⚙️ System           — Pipeline health, architecture, and config
"""

import sys
from pathlib import Path
from datetime import datetime, timezone

import streamlit as st
from streamlit_autorefresh import st_autorefresh

# ── Project root on path ──────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import threat as threat_cfg

# ── Page Config (must be first Streamlit command) ─────────────────────────────
st.set_page_config(
    page_title="Eye of Horus — SOC",
    page_icon="👁️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Load CSS Design System ────────────────────────────────────────────────────
_css_path = Path(__file__).parent / "assets" / "theme.css"
if _css_path.exists():
    st.markdown(f"<style>{_css_path.read_text(encoding='utf-8')}</style>", unsafe_allow_html=True)

# ── Import dashboard modules ─────────────────────────────────────────────────
from dashboard.data_service import load_threats, load_alerts, load_stats
from dashboard.views import overview, alerts, analytics, explorer, system, attack_map, correlation, reports, simulation, anomalies, ai_analyst

# ═══════════════════════════════════════════════════════════════════════════════
#  Sidebar — Navigation & Global Controls
# ═══════════════════════════════════════════════════════════════════════════════

with st.sidebar:
    # ── Brand Header ──────────────────────────────────────────────────────
    st.markdown("## 👁️ EYE OF HORUS")
    st.markdown(
        '<span style="color:#8b949e;font-size:0.8rem;letter-spacing:1px;">'
        'SECURITY OPERATIONS CENTER</span>',
        unsafe_allow_html=True,
    )
    st.divider()

    # ── Navigation ────────────────────────────────────────────────────────
    nav_options = {
        "🏠 Command Center": "overview",
        "🌍 Attack Map": "attack_map",
        "🔗 Correlation": "correlation",
        "📉 Anomalies": "anomalies",
        "🤖 AI Analyst": "ai_analyst",
        "🎮 Simulation": "simulation",
        "🚨 Live Alerts": "alerts",
        "📊 Analytics": "analytics",
        "🔍 Explorer": "explorer",
        "📑 Reports": "reports",
        "⚙️ System": "system",
    }

    selected_label = st.radio(
        "Navigation",
        list(nav_options.keys()),
        index=0,
        key="nav_selection",
        label_visibility="collapsed",
    )
    selected_page = nav_options[selected_label]

    st.divider()

    # ── Global Filters ────────────────────────────────────────────────────
    st.markdown(
        '<span style="color:#8b949e;font-size:0.72rem;letter-spacing:1px;text-transform:uppercase;">'
        '⚡ Controls</span>',
        unsafe_allow_html=True,
    )

    minutes_back = st.slider(
        "⏱ Time Window", 1, 4320, 1440,
        format="%d min", key="global_time_window",
    )
    hours_back = minutes_back / 60.0

    threshold = st.slider(
        "🎚 Threat Threshold", 0.0, 1.0,
        float(threat_cfg.THRESHOLD), 0.05,
        key="global_threshold",
    )

    source_filter = st.multiselect(
        "📡 Sources",
        ["reddit", "rss", "alienvault_otx", "nvd_cve", "mock_generator"],
        default=["reddit", "rss", "alienvault_otx", "nvd_cve", "mock_generator"],
        key="global_sources",
    )

    auto_refresh = st.checkbox("🔄 Auto-refresh (2s)", value=True, key="global_autorefresh")

    st.divider()

    # ── Pipeline Status ───────────────────────────────────────────────────
    st.markdown(
        '<span style="color:#8b949e;font-size:0.72rem;letter-spacing:1px;text-transform:uppercase;">'
        '📊 Pipeline</span>',
        unsafe_allow_html=True,
    )

    stats = load_stats()
    st.markdown(
        f'<span class="status-dot dot-green"></span> MongoDB connected',
        unsafe_allow_html=True,
    )
    st.caption(f"📦 Raw: **{stats['raw']:,}** · 🎯 Scored: **{stats['threats']:,}** · 🚨 Alerts: **{stats['alerts']:,}**")

    st.divider()
    st.caption(f"🕐 {datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}")
    st.caption(
        '<span style="font-size:0.65rem;color:#484f58;">v2.0 — Enterprise Edition</span>',
        unsafe_allow_html=True,
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  Data Loading
# ═══════════════════════════════════════════════════════════════════════════════

df = load_threats(hours_back, sources=tuple(source_filter))
df_alerts = load_alerts()


# ═══════════════════════════════════════════════════════════════════════════════
#  Page Header
# ═══════════════════════════════════════════════════════════════════════════════

st.markdown(
    '<h1 style="font-family:\'Inter\',sans-serif;font-size:1.5rem;font-weight:700;'
    'color:#e6edf3;margin-bottom:2px;">'
    '<span style="background:linear-gradient(135deg,#39d4e0,#58a6ff);'
    '-webkit-background-clip:text;-webkit-text-fill-color:transparent;">👁️ Eye of Horus</span></h1>',
    unsafe_allow_html=True,
)
st.markdown(
    f'<p style="color:#484f58;font-size:0.78rem;margin-top:0;">'
    f'Threat Intelligence & Security Operations — {selected_label}</p>',
    unsafe_allow_html=True,
)
st.markdown("")


# ═══════════════════════════════════════════════════════════════════════════════
#  Page Router
# ═══════════════════════════════════════════════════════════════════════════════

if selected_page == "overview":
    overview.render(df, threshold, hours_back)

elif selected_page == "alerts":
    alerts.render(df, df_alerts, threshold)

elif selected_page == "analytics":
    analytics.render(df, threshold)

elif selected_page == "explorer":
    explorer.render(df)

elif selected_page == "attack_map":
    attack_map.render(df, threshold)

elif selected_page == "correlation":
    correlation.render(df, threshold)

elif selected_page == "reports":
    reports.render(df, threshold, f"last {int(minutes_back)} minutes" if minutes_back < 120 else f"last {hours_back:.1f} hours")

elif selected_page == "anomalies":
    anomalies.render(df, threshold)

elif selected_page == "ai_analyst":
    ai_analyst.render(df, threshold)

elif selected_page == "simulation":
    simulation.render()

elif selected_page == "system":
    system.render()


# ═══════════════════════════════════════════════════════════════════════════════
#  Auto-Refresh
# ═══════════════════════════════════════════════════════════════════════════════

if auto_refresh:
    st_autorefresh(interval=2000, key="soc_dashboard_refresh")
