"""
Eye of Horus — Chart Factory
Centralized Plotly chart creation with a unified dark/neon theme.
Every chart function returns a Plotly Figure ready for st.plotly_chart().
"""

import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
import numpy as np

# ═══════════════════════════════════════════════════════════════════════════════
#  Unified Dark Theme
# ═══════════════════════════════════════════════════════════════════════════════

DARK_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Inter, sans-serif", color="#8b949e", size=11),
    margin=dict(l=10, r=10, t=35, b=10),
    xaxis=dict(gridcolor="rgba(33,38,45,0.5)", zerolinecolor="#21262d", tickfont=dict(size=10)),
    yaxis=dict(gridcolor="rgba(33,38,45,0.5)", zerolinecolor="#21262d", tickfont=dict(size=10)),
    legend=dict(bgcolor="rgba(13,17,23,0.8)", bordercolor="#21262d", font=dict(size=10)),
    hoverlabel=dict(bgcolor="#161b22", bordercolor="#30363d", font=dict(family="Inter", size=12)),
)

SEVERITY_COLORS = {
    "CRITICAL": "#f85149",
    "HIGH": "#d29922",
    "MEDIUM": "#58a6ff",
    "LOW": "#3fb950",
}

NEON_PALETTE = ["#58a6ff", "#39d4e0", "#bc8cff", "#f0883e", "#3fb950", "#f85149", "#d29922"]


# ═══════════════════════════════════════════════════════════════════════════════
#  Timeline Charts
# ═══════════════════════════════════════════════════════════════════════════════

def threat_timeline_chart(df: pd.DataFrame, threshold: float = 0.65) -> go.Figure:
    """Area chart showing max/avg threat score over time with threshold line."""
    if "processed_at" not in df.columns or df["processed_at"].isna().all():
        return _empty_figure("Waiting for timestamped data...")

    tdf = (
        df.dropna(subset=["processed_at"])
        .set_index("processed_at")["threat_score"]
        .resample("15min")
        .agg(["mean", "max", "count"])
        .reset_index()
    )

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=tdf["processed_at"], y=tdf["max"], name="Max Score",
        line=dict(color="#f85149", width=2),
        fill="tozeroy", fillcolor="rgba(248,81,73,0.06)",
    ))
    fig.add_trace(go.Scatter(
        x=tdf["processed_at"], y=tdf["mean"], name="Avg Score",
        line=dict(color="#58a6ff", width=1.5, dash="dash"),
    ))
    fig.add_hline(
        y=threshold, line_dash="dot", line_color="#d29922",
        annotation_text=f"Threshold ({threshold})",
        annotation_font_color="#d29922", annotation_font_size=10,
    )
    fig.update_layout(**DARK_LAYOUT, height=300, yaxis_range=[0, 1])
    return fig


# ═══════════════════════════════════════════════════════════════════════════════
#  Distribution Charts
# ═══════════════════════════════════════════════════════════════════════════════

def score_distribution_chart(df: pd.DataFrame, threshold: float = 0.65) -> go.Figure:
    """Histogram of threat scores with threshold marker."""
    fig = px.histogram(
        df, x="threat_score", nbins=40,
        color_discrete_sequence=["#58a6ff"],
    )
    fig.add_vline(
        x=threshold, line_dash="dash", line_color="#d29922",
        annotation_text="Threshold", annotation_font_color="#d29922",
    )
    fig.update_layout(**DARK_LAYOUT, height=300, bargap=0.05)
    return fig


def severity_donut_chart(df: pd.DataFrame) -> go.Figure:
    """Donut chart of severity breakdown with neon colors."""
    if "severity" not in df.columns:
        return _empty_figure("No severity data")

    sev_counts = df["severity"].value_counts().reset_index()
    sev_counts.columns = ["severity", "count"]

    fig = px.pie(
        sev_counts, values="count", names="severity",
        color="severity", color_discrete_map=SEVERITY_COLORS,
        hole=0.6,
    )
    fig.update_layout(**DARK_LAYOUT, height=300, showlegend=True)
    fig.update_traces(
        textinfo="percent+label", textfont_size=11,
        marker=dict(line=dict(color="#0a0e17", width=2)),
    )
    return fig


# ═══════════════════════════════════════════════════════════════════════════════
#  Source Charts
# ═══════════════════════════════════════════════════════════════════════════════

def source_bar_chart(df: pd.DataFrame) -> go.Figure:
    """Bar chart of record count per source, colored by avg threat score."""
    sc = df.groupby("source")["threat_score"].agg(count="count", avg_score="mean").reset_index()
    fig = px.bar(
        sc, x="source", y="count",
        color="avg_score", color_continuous_scale="RdYlGn_r",
        range_color=[0, 1],
    )
    fig.update_layout(**DARK_LAYOUT, height=300, coloraxis_colorbar=dict(tickfont=dict(color="#8b949e")))
    return fig


def source_score_grouped_bar(df: pd.DataFrame) -> go.Figure:
    """Grouped bar chart: avg vs max threat score by source."""
    if "source" not in df.columns:
        return _empty_figure("No source data")

    src = df.groupby("source").agg(
        avg=("threat_score", "mean"), max_s=("threat_score", "max")
    ).reset_index()

    fig = go.Figure()
    fig.add_trace(go.Bar(x=src["source"], y=src["avg"], name="Avg Score", marker_color="#58a6ff"))
    fig.add_trace(go.Bar(x=src["source"], y=src["max_s"], name="Max Score", marker_color="#f85149"))
    fig.update_layout(**DARK_LAYOUT, height=300, barmode="group")
    return fig


# ═══════════════════════════════════════════════════════════════════════════════
#  Scatter & Correlation Charts
# ═══════════════════════════════════════════════════════════════════════════════

def keyword_sentiment_scatter(df: pd.DataFrame) -> go.Figure:
    """Scatter of keyword vs sentiment scores, sized by threat score."""
    if "keyword_score" not in df.columns or "sentiment_score" not in df.columns:
        return _empty_figure("No NLP score data")

    fig = px.scatter(
        df, x="keyword_score", y="sentiment_score",
        color="threat_score", color_continuous_scale="RdYlGn_r",
        range_color=[0, 1], size="threat_score", size_max=12,
        hover_data=["source", "title"],
    )
    fig.update_layout(**DARK_LAYOUT, height=300)
    return fig


# ═══════════════════════════════════════════════════════════════════════════════
#  Heatmap
# ═══════════════════════════════════════════════════════════════════════════════

def threat_heatmap(df: pd.DataFrame) -> go.Figure:
    """Heatmap of threat activity by hour and day of week."""
    if "processed_at" not in df.columns or df["processed_at"].isna().all():
        return _empty_figure("Waiting for timestamped data...")

    tdf = df.dropna(subset=["processed_at"]).copy()
    tdf["hour"] = tdf["processed_at"].dt.hour
    tdf["day"] = tdf["processed_at"].dt.day_name()

    day_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    pivot = tdf.groupby(["day", "hour"]).size().reset_index(name="count")
    matrix = pivot.pivot_table(index="day", columns="hour", values="count", fill_value=0)
    matrix = matrix.reindex(day_order, fill_value=0)

    fig = go.Figure(data=go.Heatmap(
        z=matrix.values, x=list(range(24)), y=day_order,
        colorscale=[[0, "#0d1117"], [0.3, "#0d2137"], [0.6, "#1a3a5c"], [1, "#58a6ff"]],
        hoverongaps=False,
    ))
    fig.update_layout(**DARK_LAYOUT, height=300, xaxis_title="Hour (UTC)", yaxis_title="")
    return fig


# ═══════════════════════════════════════════════════════════════════════════════
#  Utility
# ═══════════════════════════════════════════════════════════════════════════════

def _empty_figure(message: str = "No data available") -> go.Figure:
    """Return a styled empty figure with a centered message."""
    fig = go.Figure()
    fig.add_annotation(
        text=message, xref="paper", yref="paper",
        x=0.5, y=0.5, showarrow=False,
        font=dict(size=14, color="#484f58"),
    )
    fig.update_layout(**DARK_LAYOUT, height=300)
    fig.update_xaxes(visible=False)
    fig.update_yaxes(visible=False)
    return fig
