"""
Eye of Horus — Global Attack Map
Interactive world map showing threat geolocation with severity-colored markers,
attack clustering, and animated attack arcs using PyDeck.
"""

import streamlit as st
import pandas as pd
import pydeck as pdk

from dashboard.components import render_section_header, render_empty_state, render_kpi_row

# ═══════════════════════════════════════════════════════════════════════════════
#  Severity color mapping
# ═══════════════════════════════════════════════════════════════════════════════

SEV_COLORS = {
    "CRITICAL": [248, 81, 73],   # #f85149
    "HIGH": [210, 153, 34],      # #d29922
    "MEDIUM": [88, 166, 255],    # #58a6ff
    "LOW": [63, 185, 80],        # #3fb950
}

# Attack-type color palette — each attack category gets a distinct neon color
ATTACK_TYPE_COLORS = {
    "ransomware":  [255, 45, 85],    # Hot pink
    "ddos":        [0, 199, 255],    # Electric cyan
    "apt":         [175, 82, 222],   # Purple
    "phishing":    [255, 159, 10],   # Orange
    "zero_day":    [255, 55, 55],    # Bright red
    "malware":     [50, 215, 75],    # Green
    "exploit":     [255, 214, 10],   # Yellow
    "data_breach": [100, 210, 255],  # Light blue
    "default":     [210, 153, 34],   # Amber fallback
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Render
# ═══════════════════════════════════════════════════════════════════════════════

def render(df: pd.DataFrame, threshold: float):
    """Render the Global Attack Map page."""

    render_section_header("Global Threat Map", icon="🌍", subtitle="real-time hybrid NLP + Mock threat geolocation")

    if df.empty:
        render_empty_state("No threat data available for mapping.", "🌍")
        return

    # Filter to threats only
    threats = df[df["threat_score"] >= threshold].copy()
    if threats.empty:
        threats = df.head(200).copy()

    geo_df, nlp_success, fallback_used = build_geo_df(threats)

    if geo_df.empty:
        render_empty_state("No valid geolocation data found in threats.", "🌍")
        return

    # ── KPIs ──────────────────────────────────────────────────────────────
    countries = geo_df["src_country"].nunique()
    top_origin = geo_df["src_country"].value_counts().index[0] if not geo_df.empty else "N/A"
    
    total = len(threats)
    nlp_pct = (nlp_success / total) * 100 if total > 0 else 0
    mock_pct = (fallback_used / total) * 100 if total > 0 else 0

    render_kpi_row([
        {"value": f"{total:,}", "label": "Mapped Threats", "icon": "📍", "color": "clr-red"},
        {"value": f"{nlp_pct:.1f}%", "label": "NLP Success Rate", "icon": "🧠", "color": "clr-blue"},
        {"value": f"{mock_pct:.1f}%", "label": "Fallback Usage", "icon": "🔄", "color": "clr-amber"},
        {"value": top_origin, "label": "Top Origin", "icon": "🎯", "color": "clr-red"},
    ])

    st.markdown("")

    # ── Map View ──────────────────────────────────────────────────────────
    _build_pydeck_map(geo_df)

    st.markdown("---")

    # ── Tables & Breakdown ─────────────────────────────────────────────────
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("#### 🚨 Live Threat Geolocation Feed")
        
        display_df = geo_df[["source_badge", "severity", "title", "src_country", "dst_country", "nlp_extracted"]].copy()
        display_df.rename(columns={
            "source_badge": "Type",
            "severity": "Severity",
            "title": "Title",
            "src_country": "Source",
            "dst_country": "Target",
            "nlp_extracted": "NLP Raw"
        }, inplace=True)
        st.dataframe(display_df, use_container_width=True, hide_index=True)
        
    with col2:
        st.markdown("#### 📊 Origin Breakdown")
        country_stats = (
            geo_df.groupby("src_country")
            .agg(attacks=("post_id", "count"))
            .sort_values("attacks", ascending=False)
            .reset_index()
        )
        st.dataframe(country_stats, use_container_width=True, hide_index=True)


# ═══════════════════════════════════════════════════════════════════════════════
#  Geo DataFrame builder (shared with simulation mini-dashboard)
# ═══════════════════════════════════════════════════════════════════════════════

def build_geo_df(threats: pd.DataFrame) -> tuple[pd.DataFrame, int, int]:
    """Unpack geo_data dicts into a flat DataFrame for PyDeck.
    Legacy records without geo_data get mock coordinates on-the-fly."""
    from services.geolocation.mock_attack_generator import generate_mock_geolocation

    geo_rows = []
    nlp_success = 0
    fallback_used = 0
    
    for _, row in threats.iterrows():
        g = row.get("geo_data", None)
        
        # Legacy records (processed before the geo upgrade) have no geo_data.
        # Generate mock coordinates on-the-fly so they still appear on the map.
        if not isinstance(g, dict) or "src_lat" not in g:
            post_id = str(row.get("post_id", "unknown"))
            g = generate_mock_geolocation(post_id)
            g["nlp_extracted"] = row.get("extracted_location", "Unknown")
            g["nlp_confidence"] = 0.0
            g["geo_fallback_used"] = True
            
        mock_used = g.get("geo_fallback_used", True)
        if mock_used:
            fallback_used += 1
        else:
            nlp_success += 1
            
        # Determine attack type from extra metadata or title keywords
        threat_type = "default"
        extra = row.get("extra", {})
        if isinstance(extra, dict):
            threat_type = extra.get("threat_type", "default")
        if threat_type == "default":
            # Try to infer from title
            title_lower = str(row.get("title", "")).lower()
            for atype in ATTACK_TYPE_COLORS:
                if atype.replace("_", " ") in title_lower or atype in title_lower:
                    threat_type = atype
                    break

        sev = row.get("severity", "LOW")
        color = ATTACK_TYPE_COLORS.get(threat_type, ATTACK_TYPE_COLORS["default"])
            
        geo_rows.append({
            "post_id": row.get("post_id"),
            "title": str(row.get("title", "Unknown"))[:60],
            "severity": sev,
            "threat_type": threat_type,
            "threat_score": round(float(row.get("threat_score", 0.0)), 3),
            "color_r": color[0],
            "color_g": color[1],
            "color_b": color[2],
            
            "src_lat": float(g.get("src_lat", 0.0)),
            "src_lon": float(g.get("src_lon", 0.0)),
            "src_country": g.get("src_country", "Unknown"),
            "src_isp": g.get("src_isp", "Unknown"),
            
            "dst_lat": float(g.get("dst_lat", 0.0)),
            "dst_lon": float(g.get("dst_lon", 0.0)),
            "dst_country": g.get("dst_country", "Unknown"),
            "dst_isp": g.get("dst_isp", "Unknown"),
            
            "is_mock": mock_used,
            "source_badge": "MOCK" if mock_used else "NLP",
            "nlp_extracted": g.get("nlp_extracted", "Unknown"),
        })

    return pd.DataFrame(geo_rows), nlp_success, fallback_used


# ═══════════════════════════════════════════════════════════════════════════════
#  PyDeck Map
# ═══════════════════════════════════════════════════════════════════════════════

def _build_pydeck_map(df: pd.DataFrame):
    """Builds an interactive PyDeck map with animated arcs and scatter nodes."""
    
    if df.empty:
        return

    tooltip = {
        "html": "<b>{title}</b><br/>"
                "<b>Severity:</b> {severity} ({threat_score})<br/>"
                "<b>Source:</b> {src_country} ({src_isp})<br/>"
                "<b>Target:</b> {dst_country} ({dst_isp})<br/>"
                "<b>Geo Type:</b> {source_badge}",
        "style": {
            "backgroundColor": "#161b22",
            "color": "#c9d1d9",
            "border": "1px solid #30363d",
            "borderRadius": "5px"
        }
    }

    # 1. Arc Layer: Attack flow lines from source to destination
    arc_layer = pdk.Layer(
        "ArcLayer",
        data=df,
        get_source_position=["src_lon", "src_lat"],
        get_target_position=["dst_lon", "dst_lat"],
        get_source_color=["color_r", "color_g", "color_b", 160],
        get_target_color=["color_r", "color_g", "color_b", 80],
        auto_highlight=True,
        width_scale=1,
        get_width=1,
        width_min_pixels=1,
        width_max_pixels=3,
        pickable=True,
    )

    # 2. Scatterplot: Source nodes
    scatter_src = pdk.Layer(
        "ScatterplotLayer",
        data=df,
        get_position=["src_lon", "src_lat"],
        get_fill_color=["color_r", "color_g", "color_b", 200],
        get_radius=60000,
        pickable=True,
        opacity=0.7,
        filled=True,
        radius_scale=2,
        radius_min_pixels=4,
        radius_max_pixels=12,
    )
    
    # 3. Scatterplot: Destination nodes (white glow)
    scatter_dst = pdk.Layer(
        "ScatterplotLayer",
        data=df,
        get_position=["dst_lon", "dst_lat"],
        get_fill_color=[255, 255, 255, 80],
        get_radius=40000,
        pickable=False,
        opacity=0.3,
        filled=True,
        radius_scale=2,
        radius_min_pixels=2,
        radius_max_pixels=8,
    )

    view_state = pdk.ViewState(
        latitude=20.0,
        longitude=10.0,
        zoom=1.3,
        pitch=0,
    )

    deck = pdk.Deck(
        layers=[arc_layer, scatter_src, scatter_dst],
        initial_view_state=view_state,
        tooltip=tooltip,
    )

    st.pydeck_chart(deck, use_container_width=True, height=500)
