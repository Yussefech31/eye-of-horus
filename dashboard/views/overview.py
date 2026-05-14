"""
Eye of Horus — Overview Page
Main SOC command center view with KPIs, timeline, source breakdown, and top threats.
"""

import streamlit as st
import pandas as pd

from dashboard.components import render_kpi_row, render_threat_table, render_section_header, render_banner_alert, render_empty_state
from dashboard.charts import threat_timeline_chart, source_bar_chart, threat_heatmap


def render(df: pd.DataFrame, threshold: float, hours_back: float):
    """Render the Overview page."""

    if df.empty:
        render_empty_state("No data yet — start the pipeline with start_project.bat", "📡")
        return

    # ── KPI Metrics ───────────────────────────────────────────────────────
    total = len(df)
    threats = len(df[df["threat_score"] >= threshold])
    critical = len(df[df["threat_score"] >= 0.85])
    avg_score = df["threat_score"].mean()
    max_score = df["threat_score"].max()

    # Threat banner
    if threats > 0:
        render_banner_alert(threats, hours_back)
        st.markdown("")

    render_kpi_row([
        {"value": f"{total:,}", "label": "Total Records", "icon": "📦", "color": "clr-blue"},
        {"value": f"{threats:,}", "label": "Active Threats", "icon": "🎯", "color": "clr-red"},
        {"value": f"{critical:,}", "label": "Critical", "icon": "💀", "color": "clr-red"},
        {"value": f"{avg_score:.3f}", "label": "Avg Score", "icon": "📊", "color": "clr-amber"},
        {"value": f"{max_score:.3f}", "label": "Max Score", "icon": "⚡", "color": "clr-purple"},
    ])

    st.markdown("")

    # ── Charts Row ────────────────────────────────────────────────────────
    col_left, col_right = st.columns([3, 2])

    with col_left:
        render_section_header("Threat Score Timeline", icon="📈")
        fig = threat_timeline_chart(df, threshold)
        st.plotly_chart(fig, width="stretch", key="overview_timeline")

    with col_right:
        render_section_header("Records by Source", icon="🗂️")
        fig2 = source_bar_chart(df)
        st.plotly_chart(fig2, width="stretch", key="overview_source")

    # ── Heatmap ───────────────────────────────────────────────────────────
    with st.expander("🔥 Threat Activity Heatmap", expanded=False):
        fig3 = threat_heatmap(df)
        st.plotly_chart(fig3, width="stretch", key="overview_heatmap")

    # ── Top Threats Table ─────────────────────────────────────────────────
    st.markdown("")
    render_section_header("Top Threats", icon="🚨", subtitle="highest scoring records")
    top = df[df["threat_score"] >= threshold].head(10)
    if not top.empty:
        render_threat_table(top, max_rows=10)
    else:
        st.success(f"✅ No threats above {threshold} in the last {hours_back:.0f}h")
