"""
Eye of Horus — Threat Explorer Page
Searchable, filterable data grid with pagination and CSV export.
"""

import streamlit as st
import pandas as pd

from dashboard.components import render_section_header, render_empty_state


# Number of rows per page
PAGE_SIZE = 50


def render(df: pd.DataFrame):
    """Render the Threat Explorer page."""

    render_section_header("Threat Explorer", icon="🔍", subtitle="search and filter all intelligence records")

    if df.empty:
        render_empty_state("No data available.", "🔍")
        return

    # ── Filters ───────────────────────────────────────────────────────────
    col_search, col_score, col_source = st.columns([3, 1, 1])

    with col_search:
        search = st.text_input("🔎 Search titles...", "", key="explorer_search",
                               placeholder="e.g. ransomware, CVE-2024, phishing...")

    with col_score:
        min_score = st.slider("Min Score", 0.0, 1.0, 0.0, 0.05, key="explorer_min_score")

    with col_source:
        sources = sorted(df["source"].unique().tolist()) if "source" in df.columns else []
        source_sel = st.multiselect("Sources", sources, default=sources, key="explorer_sources")

    # ── Apply Filters ─────────────────────────────────────────────────────
    filtered = df.copy()

    if min_score > 0:
        filtered = filtered[filtered["threat_score"] >= min_score]

    if search:
        filtered = filtered[filtered["title"].str.contains(search, case=False, na=False)]

    if source_sel and "source" in filtered.columns:
        filtered = filtered[filtered["source"].isin(source_sel)]

    # ── Severity filter ───────────────────────────────────────────────────
    if "severity" in filtered.columns:
        sev_options = sorted(filtered["severity"].unique().tolist())
        sev_sel = st.multiselect("Severity", sev_options, default=sev_options, key="explorer_sev")
        filtered = filtered[filtered["severity"].isin(sev_sel)]

    st.caption(f"Showing **{len(filtered):,}** records")

    # ── Pagination ────────────────────────────────────────────────────────
    total_pages = max(1, (len(filtered) + PAGE_SIZE - 1) // PAGE_SIZE)

    if "explorer_page" not in st.session_state:
        st.session_state.explorer_page = 1

    col_prev, col_info, col_next = st.columns([1, 2, 1])
    with col_prev:
        if st.button("◀ Previous", key="explorer_prev", disabled=st.session_state.explorer_page <= 1):
            st.session_state.explorer_page -= 1
            st.rerun()
    with col_info:
        st.markdown(
            f"<div style='text-align:center;color:#8b949e;padding:8px;'>"
            f"Page {st.session_state.explorer_page} of {total_pages}</div>",
            unsafe_allow_html=True,
        )
    with col_next:
        if st.button("Next ▶", key="explorer_next", disabled=st.session_state.explorer_page >= total_pages):
            st.session_state.explorer_page += 1
            st.rerun()

    # ── Data Grid ─────────────────────────────────────────────────────────
    start_idx = (st.session_state.explorer_page - 1) * PAGE_SIZE
    end_idx = start_idx + PAGE_SIZE
    page_df = filtered.iloc[start_idx:end_idx]

    display_cols = [c for c in [
        "severity", "source", "title", "threat_score",
        "keyword_score", "sentiment_score", "published_at",
    ] if c in page_df.columns]

    if not page_df.empty:
        st.dataframe(
            page_df[display_cols],
            width="stretch",
            height=500,
            hide_index=True,
            column_config={
                "threat_score": st.column_config.ProgressColumn(
                    "Threat Score", min_value=0, max_value=1, format="%.3f"
                ),
                "keyword_score": st.column_config.ProgressColumn(
                    "Keyword", min_value=0, max_value=1, format="%.3f"
                ),
                "sentiment_score": st.column_config.ProgressColumn(
                    "Sentiment", min_value=0, max_value=1, format="%.3f"
                ),
            },
        )

    # ── Export ─────────────────────────────────────────────────────────────
    st.markdown("")
    col_csv, col_info2 = st.columns([1, 3])
    with col_csv:
        csv = filtered[display_cols].to_csv(index=False)
        st.download_button(
            "📥 Export CSV", csv, "eye_of_horus_threats.csv", "text/csv",
            key="explorer_csv",
        )
    with col_info2:
        st.caption(f"Export contains {len(filtered):,} records with {len(display_cols)} columns")
