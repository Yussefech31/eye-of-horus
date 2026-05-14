"""
Eye of Horus — Threat Correlation Dashboard
Interactive network graph visualization of related threats,
IOC correlation, and campaign clustering.
"""

import sys
from pathlib import Path
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from dashboard.components import render_section_header, render_empty_state, render_kpi_row, badge_html
from services.correlator import cluster_threats, extract_iocs


def render(df: pd.DataFrame, threshold: float):
    """Render the Threat Correlation page."""

    render_section_header("Threat Correlation", icon="🔗", subtitle="related threat clustering & IOC analysis")

    if df.empty or len(df) < 5:
        render_empty_state("Need at least 5 threat records for correlation analysis.", "🔗")
        return

    # ── Controls ──────────────────────────────────────────────────────────
    col_sim, col_limit = st.columns(2)
    with col_sim:
        sim_threshold = st.slider("Similarity Threshold", 0.1, 0.8, 0.25, 0.05, key="corr_threshold")
    with col_limit:
        max_records = st.slider("Max Records to Analyze", 20, 200, 100, 10, key="corr_limit")

    # ── Run Correlation ───────────────────────────────────────────────────
    work_df = df.head(max_records)

    with st.spinner("Analyzing threat correlations..."):
        result = cluster_threats(work_df, sim_threshold=sim_threshold)

    clusters = result["clusters"]
    edges = result["edges"]
    iocs = result["iocs"]
    corr_df = result["df"]

    # ── KPIs ──────────────────────────────────────────────────────────────
    total_edges = len(edges)
    total_clusters = len(clusters)
    ioc_count = sum(sum(len(v) for v in ioc_dict.values()) for ioc_dict in iocs.values())
    largest_cluster = max((len(c) for c in clusters), default=0)

    render_kpi_row([
        {"value": f"{total_clusters}", "label": "Threat Clusters", "icon": "🔗", "color": "clr-purple"},
        {"value": f"{total_edges}", "label": "Correlations", "icon": "🕸️", "color": "clr-blue"},
        {"value": f"{ioc_count}", "label": "IOCs Extracted", "icon": "🎯", "color": "clr-cyan"},
        {"value": f"{largest_cluster}", "label": "Largest Cluster", "icon": "📡", "color": "clr-amber"},
    ])

    st.markdown("")

    # ── Network Graph ─────────────────────────────────────────────────────
    if edges:
        render_section_header("Correlation Network", icon="🕸️")
        fig = _build_network_graph(corr_df, edges, clusters)
        st.plotly_chart(fig, width="stretch", key="corr_network")
    else:
        st.info("No correlations found at this threshold. Try lowering the similarity threshold.")

    # ── Cluster Details ───────────────────────────────────────────────────
    if clusters:
        render_section_header("Cluster Details", icon="📋")
        for i, cluster in enumerate(clusters[:10]):
            cluster_df = corr_df.iloc[cluster]
            avg_score = cluster_df["threat_score"].mean()
            sev = "CRITICAL" if avg_score >= 0.85 else "HIGH" if avg_score >= 0.65 else "MEDIUM" if avg_score >= 0.4 else "LOW"

            with st.expander(f"Cluster #{i+1} — {len(cluster)} threats — {badge_html(sev)} (avg: {avg_score:.3f})", expanded=(i == 0)):
                display_cols = [c for c in ["severity", "source", "title", "threat_score"] if c in cluster_df.columns]
                st.dataframe(cluster_df[display_cols], width="stretch", hide_index=True)

    # ── IOC Summary ───────────────────────────────────────────────────────
    if iocs:
        with st.expander("🎯 Extracted IOCs", expanded=False):
            all_iocs = {"ipv4": set(), "domain": set(), "cve": set(), "md5": set(), "sha256": set(), "email": set()}
            for ioc_dict in iocs.values():
                for ioc_type, values in ioc_dict.items():
                    if ioc_type in all_iocs:
                        all_iocs[ioc_type].update(values)

            for ioc_type, values in all_iocs.items():
                if values:
                    st.markdown(f"**{ioc_type.upper()}** ({len(values)})")
                    st.code("\n".join(sorted(values)[:20]))


def _build_network_graph(df: pd.DataFrame, edges: dict, clusters: list) -> go.Figure:
    """Build a Plotly network graph of correlated threats."""
    n = len(df)

    # Layout nodes in a circle with cluster grouping
    angles = np.linspace(0, 2 * np.pi, n, endpoint=False)
    x_nodes = np.cos(angles) * 10
    y_nodes = np.sin(angles) * 10

    # Assign colors by cluster
    node_colors = ["#484f58"] * n
    cluster_palette = ["#58a6ff", "#f85149", "#3fb950", "#d29922", "#bc8cff", "#39d4e0", "#f0883e"]
    for ci, cluster in enumerate(clusters):
        color = cluster_palette[ci % len(cluster_palette)]
        for idx in cluster:
            if idx < n:
                node_colors[idx] = color

    # Edge traces
    edge_x, edge_y = [], []
    for (i, j) in edges:
        if i < n and j < n:
            edge_x.extend([x_nodes[i], x_nodes[j], None])
            edge_y.extend([y_nodes[i], y_nodes[j], None])

    fig = go.Figure()

    # Edges
    fig.add_trace(go.Scatter(
        x=edge_x, y=edge_y, mode="lines",
        line=dict(width=0.5, color="rgba(88,166,255,0.2)"),
        hoverinfo="none", showlegend=False,
    ))

    # Nodes
    titles = df["title"].fillna("N/A").str[:40].tolist()
    scores = df["threat_score"].tolist()
    hover_texts = [f"<b>{titles[i]}</b><br>Score: {scores[i]:.3f}" for i in range(n)]

    fig.add_trace(go.Scatter(
        x=x_nodes, y=y_nodes, mode="markers",
        marker=dict(size=8, color=node_colors, opacity=0.9, line=dict(width=1, color="rgba(255,255,255,0.2)")),
        text=hover_texts, hoverinfo="text", showlegend=False,
    ))

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(visible=False), yaxis=dict(visible=False),
        margin=dict(l=0, r=0, t=0, b=0), height=450,
    )
    return fig
