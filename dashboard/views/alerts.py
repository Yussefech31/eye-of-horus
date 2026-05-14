"""
Eye of Horus — Live Alerts Page
Real-time alert feed with severity filtering and acknowledge actions.
"""

import streamlit as st
import pandas as pd

from dashboard.components import (
    render_alert_card, render_section_header, render_kpi_row,
    render_empty_state, badge_html,
)
from dashboard.data_service import acknowledge_alert


def render(df_threats: pd.DataFrame, df_alerts: pd.DataFrame, threshold: float):
    """Render the Live Alerts page."""

    # Use alerts collection, fall back to high-threat records
    alert_data = df_alerts if not df_alerts.empty else (
        df_threats[df_threats["threat_score"] >= threshold] if not df_threats.empty else pd.DataFrame()
    )

    if alert_data.empty:
        render_empty_state(
            "No alerts generated yet. The threat processor will create alerts when scores exceed the threshold.",
            "🔔"
        )
        return

    # ── Alert Summary KPIs ────────────────────────────────────────────────
    total_alerts = len(alert_data)
    crit = len(alert_data[alert_data.get("severity", pd.Series()).str.upper() == "CRITICAL"]) if "severity" in alert_data.columns else 0
    high = len(alert_data[alert_data.get("severity", pd.Series()).str.upper() == "HIGH"]) if "severity" in alert_data.columns else 0
    acked = len(alert_data[alert_data.get("acknowledged", pd.Series()) == True]) if "acknowledged" in alert_data.columns else 0

    render_kpi_row([
        {"value": f"{total_alerts}", "label": "Total Alerts", "icon": "🚨", "color": "clr-red"},
        {"value": f"{crit}", "label": "Critical", "icon": "💀", "color": "clr-red"},
        {"value": f"{high}", "label": "High", "icon": "⚠️", "color": "clr-amber"},
        {"value": f"{acked}", "label": "Acknowledged", "icon": "✅", "color": "clr-green"},
    ])

    st.markdown("")

    # ── Filters ───────────────────────────────────────────────────────────
    col_f1, col_f2 = st.columns([1, 1])
    with col_f1:
        sev_filter = st.multiselect(
            "Filter by Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            default=["CRITICAL", "HIGH", "MEDIUM", "LOW"], key="alert_sev_filter"
        )
    with col_f2:
        ack_filter = st.selectbox(
            "Status", ["All", "Unacknowledged", "Acknowledged"], key="alert_ack_filter"
        )

    # Apply filters
    filtered = alert_data.copy()
    if "severity" in filtered.columns:
        filtered = filtered[filtered["severity"].str.upper().isin(sev_filter)]
    if ack_filter == "Unacknowledged" and "acknowledged" in filtered.columns:
        filtered = filtered[filtered["acknowledged"] != True]
    elif ack_filter == "Acknowledged" and "acknowledged" in filtered.columns:
        filtered = filtered[filtered["acknowledged"] == True]

    st.caption(f"Showing {len(filtered)} alert{'s' if len(filtered) != 1 else ''}")

    # ── Alert Feed ────────────────────────────────────────────────────────
    render_section_header("Live Alert Feed", icon="🚨")

    for idx, (_, alert) in enumerate(filtered.head(50).iterrows()):
        col_alert, col_action = st.columns([10, 1])
        with col_alert:
            render_alert_card(alert.to_dict())
        with col_action:
            post_id = alert.get("post_id", "")
            if post_id and not alert.get("acknowledged", False):
                if st.button("✓", key=f"ack_{idx}_{post_id}", help="Acknowledge alert"):
                    if acknowledge_alert(post_id):
                        st.toast(f"Alert acknowledged: {post_id}", icon="✅")
                        st.rerun()
