"""
Eye of Horus — Analytics Page
Advanced threat analytics with multiple chart types: histogram, donut,
scatter, grouped bars, and heatmap.
"""

import streamlit as st
import pandas as pd

from dashboard.components import render_section_header, render_empty_state
from dashboard.charts import (
    score_distribution_chart, severity_donut_chart,
    source_score_grouped_bar, keyword_sentiment_scatter,
    threat_heatmap,
)


def render(df: pd.DataFrame, threshold: float):
    """Render the Analytics page."""

    if df.empty:
        render_empty_state("No data available for analytics.", "📊")
        return

    # ── Row 1: Distribution + Severity ────────────────────────────────────
    c1, c2 = st.columns(2)

    with c1:
        render_section_header("Score Distribution", icon="📊")
        fig = score_distribution_chart(df, threshold)
        st.plotly_chart(fig, width="stretch", key="analytics_hist")

    with c2:
        render_section_header("Severity Breakdown", icon="🎯")
        fig2 = severity_donut_chart(df)
        st.plotly_chart(fig2, width="stretch", key="analytics_donut")

    # ── Row 2: Source Scores + NLP Scatter ────────────────────────────────
    c3, c4 = st.columns(2)

    with c3:
        render_section_header("Source × Threat Score", icon="📡")
        fig3 = source_score_grouped_bar(df)
        st.plotly_chart(fig3, width="stretch", key="analytics_source")

    with c4:
        render_section_header("Keyword vs Sentiment", icon="📈")
        fig4 = keyword_sentiment_scatter(df)
        st.plotly_chart(fig4, width="stretch", key="analytics_scatter")

    # ── Row 3: Heatmap ────────────────────────────────────────────────────
    render_section_header("Activity Heatmap", icon="🔥", subtitle="threats by hour and day")
    fig5 = threat_heatmap(df)
    st.plotly_chart(fig5, width="stretch", key="analytics_heatmap")

    # ── Row 4: Summary Statistics ─────────────────────────────────────────
    with st.expander("📋 Detailed Statistics", expanded=False):
        if "source" in df.columns:
            st.markdown("**Per-Source Statistics**")
            src_stats = df.groupby("source").agg(
                count=("threat_score", "count"),
                avg_score=("threat_score", "mean"),
                max_score=("threat_score", "max"),
                min_score=("threat_score", "min"),
                std_score=("threat_score", "std"),
            ).round(4).reset_index()
            st.dataframe(src_stats, width="stretch", hide_index=True)

        if "severity" in df.columns:
            st.markdown("**Severity Distribution**")
            sev_stats = df["severity"].value_counts().reset_index()
            sev_stats.columns = ["Severity", "Count"]
            sev_stats["Percentage"] = (sev_stats["Count"] / sev_stats["Count"].sum() * 100).round(1)
            st.dataframe(sev_stats, width="stretch", hide_index=True)
