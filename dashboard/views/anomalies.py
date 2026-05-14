"""
Eye of Horus — Anomaly Detection Dashboard
Visualizes statistical anomalies in threat volume.
"""

import sys
from pathlib import Path

import streamlit as st
import pandas as pd
import plotly.graph_objects as go

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from dashboard.components import render_section_header, render_kpi_row, badge_html
from services.anomaly_detector import detect_anomalies


def render(df: pd.DataFrame, threshold: float):
    """Render the Anomaly Detection page."""

    render_section_header("Volume Anomaly Detection", icon="📈", subtitle="statistical detection of sudden threat spikes")

    if df.empty:
        st.info("No data available for anomaly detection.")
        return

    # ── Controls ──────────────────────────────────────────────────────────
    col1, col2 = st.columns(2)
    with col1:
        window_mins = st.slider("Detection Window (mins)", 15, 120, 60, 15, help="Time window to compare against historical baseline")
    with col2:
        z_threshold = st.slider("Z-Score Sensitivity", 1.0, 5.0, 2.0, 0.5, help="Standard deviations above mean to trigger anomaly")

    # ── Detection ─────────────────────────────────────────────────────────
    with st.spinner("Analyzing statistical baselines..."):
        result = detect_anomalies(df, window_mins=window_mins, z_threshold=z_threshold)

    is_anomalous = result["is_anomalous"]
    
    st.markdown("")

    # ── Alert Banner ──────────────────────────────────────────────────────
    if is_anomalous:
        st.markdown(
            f'<div style="background:rgba(248,81,73,0.1); border:1px solid rgba(248,81,73,0.4); '
            f'padding:15px; border-radius:8px; margin-bottom:20px;">'
            f'<h4 style="color:#f85149; margin:0 0 5px 0;">🚨 ANOMALY DETECTED</h4>'
            f'<p style="color:#e6edf3; margin:0; font-size:0.9rem;">{result["reason"]}</p>'
            f'</div>', unsafe_allow_html=True
        )
    else:
        st.markdown(
            f'<div style="background:rgba(63,185,80,0.1); border:1px solid rgba(63,185,80,0.4); '
            f'padding:15px; border-radius:8px; margin-bottom:20px;">'
            f'<h4 style="color:#3fb950; margin:0 0 5px 0;">✅ THREAT VOLUME NORMAL</h4>'
            f'<p style="color:#e6edf3; margin:0; font-size:0.9rem;">{result["reason"]}</p>'
            f'</div>', unsafe_allow_html=True
        )

    # ── KPIs ──────────────────────────────────────────────────────────────
    render_kpi_row([
        {"value": f"{result.get('z_score', 0):.2f}", "label": "Z-Score", "icon": "⚡", "color": "clr-red" if is_anomalous else "clr-blue"},
        {"value": f"{result.get('recent_mean', 0):.1f}/5m", "label": "Recent Volume", "icon": "🔥", "color": "clr-amber"},
        {"value": f"{result.get('baseline_mean', 0):.1f}/5m", "label": "Baseline Mean", "icon": "📏", "color": "clr-cyan"},
    ])
    st.markdown("")

    # ── Volume Chart ──────────────────────────────────────────────────────
    render_section_header("Volume Timeline", icon="📊")
    
    # Re-create timeline for chart
    df_chart = df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df_chart["published_at"]):
        df_chart["published_at"] = pd.to_datetime(df_chart["published_at"], utc=True)
    df_chart.set_index("published_at", inplace=True)
    df_chart.sort_index(inplace=True)
    
    binned = df_chart.resample("5min").size()
    
    fig = go.Figure()
    
    # Baseline Mean line
    fig.add_trace(go.Scatter(
        x=[binned.index[0], binned.index[-1]],
        y=[result.get('baseline_mean', 0), result.get('baseline_mean', 0)],
        mode="lines",
        line=dict(color="rgba(57,212,224,0.5)", width=2, dash="dash"),
        name="Baseline Mean"
    ))
    
    # Anomaly Threshold line
    threshold_y = result.get('baseline_mean', 0) + (result.get('z_score', 0) if not is_anomalous else z_threshold) * (binned.std() if len(binned)>2 else 1)
    
    # Actual Volume
    fig.add_trace(go.Scatter(
        x=binned.index, y=binned.values,
        mode="lines+markers",
        line=dict(color="#f85149" if is_anomalous else "#58a6ff", width=2, shape="spline"),
        fill="tozeroy",
        fillcolor="rgba(248,81,73,0.1)" if is_anomalous else "rgba(88,166,255,0.1)",
        name="Volume / 5m"
    ))

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=0, r=0, t=20, b=0), height=350,
        xaxis=dict(showgrid=True, gridcolor="#21262d"),
        yaxis=dict(showgrid=True, gridcolor="#21262d"),
        legend=dict(bgcolor="rgba(13,17,23,0.8)", x=0.01, y=0.99),
    )
    st.plotly_chart(fig, width="stretch", key="anomaly_chart")

    # ── Severity Breakdown in Anomaly Window ──────────────────────────────
    if is_anomalous and "severities" in result and result["severities"]:
        render_section_header("Anomaly Contents", icon="🔍", subtitle=f"threats in the last {window_mins} mins")
        cols = st.columns(len(result["severities"]))
        for i, (sev, count) in enumerate(result["severities"].items()):
            with cols[i]:
                st.markdown(f"**{badge_html(sev)}**: {count}", unsafe_allow_html=True)
