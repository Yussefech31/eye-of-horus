"""
Eye of Horus — AI Threat Analyst Dashboard
Provides AI-generated explanations and mitigation strategies for alerts.
"""

import sys
from pathlib import Path

import streamlit as st
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from dashboard.components import render_section_header, render_empty_state, badge_html
from services.ai_service import AIAnalystService

@st.cache_resource
def get_ai_service():
    return AIAnalystService()


def render(df: pd.DataFrame, threshold: float):
    """Render the AI Analyst page."""

    render_section_header("AI Threat Analyst", icon="🤖", subtitle="automated triage and mitigation recommendations")

    if df.empty:
        render_empty_state("No threat data available for analysis.", "🤖")
        return

    # Filter to critical threats
    critical_df = df[df["threat_score"] >= threshold].sort_values("threat_score", ascending=False)
    
    if critical_df.empty:
        st.info("No threats currently exceed the threshold for AI analysis.")
        return

    ai_service = get_ai_service()

    # ── Select Threat ─────────────────────────────────────────────────────
    st.markdown("### 1. Select a Threat for Analysis")
    
    # Create selectbox options
    options = []
    for idx, row in critical_df.head(20).iterrows():
        title = str(row.get("title", "N/A"))[:80]
        options.append(f"[{row.get('threat_score', 0):.3f}] {title}")
        
    selected_idx = st.selectbox("Critical Alerts", range(len(options)), format_func=lambda i: options[i])
    selected_row = critical_df.iloc[selected_idx].to_dict()

    # ── Display Raw Alert ─────────────────────────────────────────────────
    st.markdown("---")
    col_raw, col_ai = st.columns([1, 1.5])

    with col_raw:
        st.markdown("### 📄 Raw Intelligence")
        st.markdown(f"**Source:** {selected_row.get('source', 'Unknown')}")
        st.markdown(f"**Score:** {selected_row.get('threat_score', 0):.3f}")
        st.markdown(f"**Title:** {selected_row.get('title', 'N/A')}")
        
        with st.expander("Full Content", expanded=True):
            st.write(selected_row.get("text", "No content available."))
            
        st.markdown(f"**Analyzed At:** {selected_row.get('processed_at', 'N/A')}")

    # ── Generate AI Analysis ──────────────────────────────────────────────
    with col_ai:
        st.markdown("### 🧠 AI Analyst Report")
        
        if st.button("Generate Analysis Report", type="primary", use_container_width=True):
            with st.spinner("AI is analyzing the threat signature..."):
                report = ai_service.analyze_alert(selected_row)
                st.markdown(
                    f'<div style="background:rgba(13,17,23,0.8); border:1px solid #30363d; '
                    f'padding:20px; border-radius:8px;">{report}</div>', 
                    unsafe_allow_html=True
                )
        else:
            st.info("Click the button above to generate a detailed MITRE ATT&CK breakdown and mitigation strategy.")
