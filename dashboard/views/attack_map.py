"""
Eye of Horus — Global Attack Map
Interactive world map showing threat geolocation with severity-colored markers,
attack clustering, and heatmap overlay.
"""

import random
import hashlib
import streamlit as st
import pandas as pd
import plotly.graph_objects as go

from dashboard.components import render_section_header, render_empty_state, render_kpi_row


# ═══════════════════════════════════════════════════════════════════════════════
#  GeoIP Simulation — maps source/IP data to coordinates
# ═══════════════════════════════════════════════════════════════════════════════

LOCATION_COORDS = {
    "Russia": (55.75, 37.62),
    "China": (39.91, 116.39),
    "United States": (38.90, -77.04),
    "US": (38.90, -77.04),
    "USA": (38.90, -77.04),
    "Iran": (35.69, 51.39),
    "North Korea": (39.02, 125.75),
    "Brazil": (-15.79, -47.88),
    "India": (28.61, 77.21),
    "Nigeria": (9.06, 7.49),
    "Ukraine": (50.45, 30.52),
    "Germany": (52.52, 13.41),
    "Romania": (44.43, 26.10),
    "Turkey": (39.93, 32.85),
    "Vietnam": (21.03, 105.85),
    "Indonesia": (-6.21, 106.85),
    "France": (48.86, 2.35),
    "UK": (51.50, -0.12),
    "United Kingdom": (51.50, -0.12),
    "London": (51.50, -0.12),
    "Paris": (48.85, 2.35),
    "Moscow": (55.75, 37.62),
    "Beijing": (39.90, 116.40),
    "Washington": (38.90, -77.03),
    "New York": (40.71, -74.00),
    "Tokyo": (35.68, 139.69),
    "Israel": (31.04, 34.85),
    "Unknown": (0.0, 0.0)
}

def _lookup_geo(location_name: str, post_id: str) -> dict:
    """Map an NLP-extracted location name to geo coordinates."""
    if not location_name or pd.isna(location_name):
        location_name = "Unknown"
        
    matched_country = "Unknown"
    lat, lon = 0.0, 0.0
    
    for key, coords in LOCATION_COORDS.items():
        if key.lower() in str(location_name).lower():
            matched_country = key
            lat, lon = coords
            break
            
    # Add a tiny bit of deterministic jitter so points don't perfectly overlap
    h = int(hashlib.md5(str(post_id).encode()).hexdigest(), 16)
    lat_jitter = ((h >> 8) % 100 - 50) / 50.0
    lon_jitter = ((h >> 16) % 100 - 50) / 50.0

    return {
        "country": matched_country if matched_country != "Unknown" else location_name,
        "lat": lat + lat_jitter if matched_country != "Unknown" else lat,
        "lon": lon + lon_jitter if matched_country != "Unknown" else lon,
    }


def _enrich_with_geo(df: pd.DataFrame) -> pd.DataFrame:
    """Add lat/lon/country columns to threat DataFrame based on NLP extracted location."""
    if df.empty:
        return df

    if "extracted_location" not in df.columns:
        df["extracted_location"] = "Unknown"

    geo_data = df.apply(lambda row: _lookup_geo(row.get("extracted_location", "Unknown"), str(row["post_id"])), axis=1)
    
    df = df.copy()
    df["country"] = geo_data.apply(lambda g: g["country"])
    df["lat"] = geo_data.apply(lambda g: g["lat"])
    df["lon"] = geo_data.apply(lambda g: g["lon"])
    return df


# ═══════════════════════════════════════════════════════════════════════════════
#  Severity color mapping
# ═══════════════════════════════════════════════════════════════════════════════

SEV_COLORS = {
    "CRITICAL": "#f85149",
    "HIGH": "#d29922",
    "MEDIUM": "#58a6ff",
    "LOW": "#3fb950",
}

SEV_SIZES = {
    "CRITICAL": 14,
    "HIGH": 10,
    "MEDIUM": 7,
    "LOW": 5,
}


# ═══════════════════════════════════════════════════════════════════════════════
#  Render
# ═══════════════════════════════════════════════════════════════════════════════

def render(df: pd.DataFrame, threshold: float):
    """Render the Global Attack Map page."""

    render_section_header("Global Threat Map", icon="🌍", subtitle="real-time threat geolocation")

    if df.empty:
        render_empty_state("No threat data available for mapping.", "🌍")
        return

    # Filter to threats only
    threats = df[df["threat_score"] >= threshold].copy()
    if threats.empty:
        threats = df.head(200).copy()

    geo_df = _enrich_with_geo(threats)

    # ── KPIs ──────────────────────────────────────────────────────────────
    countries = geo_df["country"].nunique()
    top_country = geo_df["country"].value_counts().index[0] if not geo_df.empty else "N/A"
    crit_count = len(geo_df[geo_df.get("severity", pd.Series(dtype=str)).str.upper() == "CRITICAL"]) if "severity" in geo_df.columns else 0

    render_kpi_row([
        {"value": f"{len(geo_df):,}", "label": "Mapped Threats", "icon": "📍", "color": "clr-red"},
        {"value": f"{countries}", "label": "Countries", "icon": "🌐", "color": "clr-blue"},
        {"value": top_country, "label": "Top Origin", "icon": "🎯", "color": "clr-amber"},
        {"value": f"{crit_count}", "label": "Critical", "icon": "💀", "color": "clr-red"},
    ])

    st.markdown("")

    # ── Map Type Toggle ───────────────────────────────────────────────────
    map_type = st.radio(
        "Map View", ["Scatter Map", "Heatmap", "Bubble Map"],
        horizontal=True, key="attack_map_type",
    )

    # ── Build Map ─────────────────────────────────────────────────────────
    if map_type == "Heatmap":
        fig = _build_heatmap(geo_df)
    elif map_type == "Bubble Map":
        fig = _build_bubble_map(geo_df)
    else:
        fig = _build_scatter_map(geo_df)

    st.plotly_chart(fig, width="stretch", key="attack_map_chart")

    # ── Country Breakdown ─────────────────────────────────────────────────
    with st.expander("📊 Threat Origin Breakdown", expanded=False):
        country_stats = (
            geo_df.groupby("country")
            .agg(count=("threat_score", "count"), avg_score=("threat_score", "mean"), max_score=("threat_score", "max"))
            .round(3)
            .sort_values("count", ascending=False)
            .reset_index()
        )
        st.dataframe(country_stats, width="stretch", hide_index=True)


def _build_scatter_map(df: pd.DataFrame) -> go.Figure:
    """Scatter map with severity-colored threat markers."""
    fig = go.Figure()

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        sev_df = df[df.get("severity", pd.Series(dtype=str)) == sev] if "severity" in df.columns else pd.DataFrame()
        if sev_df.empty:
            continue
        fig.add_trace(go.Scattergeo(
            lat=sev_df["lat"], lon=sev_df["lon"],
            text=sev_df.apply(lambda r: f"<b>{r.get('title', 'N/A')[:50]}</b><br>Score: {r['threat_score']:.3f}<br>Source: {r.get('source', '')}<br>Country: {r['country']}", axis=1),
            hoverinfo="text",
            marker=dict(
                size=SEV_SIZES.get(sev, 6),
                color=SEV_COLORS.get(sev, "#58a6ff"),
                opacity=0.8,
                line=dict(width=0.5, color="rgba(255,255,255,0.3)"),
            ),
            name=sev,
        ))

    fig.update_layout(**_map_layout())
    return fig


def _build_heatmap(df: pd.DataFrame) -> go.Figure:
    """Density heatmap of threat origins."""
    fig = go.Figure(go.Densitymapbox(
        lat=df["lat"], lon=df["lon"],
        z=df["threat_score"],
        radius=20,
        colorscale=[[0, "rgba(88,166,255,0)"], [0.3, "#58a6ff"], [0.6, "#d29922"], [1, "#f85149"]],
        showscale=False,
        hoverinfo="skip",
    ))

    fig.update_layout(
        mapbox=dict(
            style="carto-darkmatter",
            center=dict(lat=25, lon=15),
            zoom=1.2,
        ),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=0, r=0, t=0, b=0),
        height=500,
    )
    return fig


def _build_bubble_map(df: pd.DataFrame) -> go.Figure:
    """Aggregated bubble map by country."""
    country_agg = df.groupby("country").agg(
        count=("threat_score", "count"),
        avg_score=("threat_score", "mean"),
        lat=("lat", "mean"),
        lon=("lon", "mean"),
    ).reset_index()

    fig = go.Figure(go.Scattergeo(
        lat=country_agg["lat"], lon=country_agg["lon"],
        text=country_agg.apply(lambda r: f"<b>{r['country']}</b><br>Threats: {r['count']}<br>Avg Score: {r['avg_score']:.3f}", axis=1),
        hoverinfo="text",
        marker=dict(
            size=country_agg["count"].clip(upper=50) * 1.5 + 5,
            color=country_agg["avg_score"],
            colorscale=[[0, "#3fb950"], [0.5, "#d29922"], [1, "#f85149"]],
            cmin=0, cmax=1,
            opacity=0.7,
            line=dict(width=1, color="rgba(255,255,255,0.4)"),
            showscale=True,
            colorbar=dict(title="Avg Score", tickfont=dict(color="#8b949e"), titlefont=dict(color="#8b949e")),
        ),
    ))

    fig.update_layout(**_map_layout())
    return fig


def _map_layout() -> dict:
    """Shared geo layout for dark theme maps."""
    return dict(
        geo=dict(
            bgcolor="rgba(0,0,0,0)",
            showframe=False,
            showcoastlines=True,
            coastlinecolor="rgba(88,166,255,0.2)",
            showland=True,
            landcolor="rgba(13,17,23,0.9)",
            showocean=True,
            oceancolor="rgba(5,8,16,0.95)",
            showcountries=True,
            countrycolor="rgba(33,38,45,0.6)",
            showlakes=False,
            projection_type="natural earth",
        ),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=0, r=0, t=0, b=0),
        height=500,
        legend=dict(
            bgcolor="rgba(13,17,23,0.8)",
            bordercolor="#21262d",
            font=dict(color="#8b949e", size=11),
            x=0.01, y=0.99,
        ),
    )
