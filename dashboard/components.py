"""
Eye of Horus — Reusable UI Components
Glassmorphism cards, badges, status indicators, and layout helpers.
All components render via st.markdown with unsafe_allow_html.
"""

import streamlit as st


# ═══════════════════════════════════════════════════════════════════════════════
#  KPI Cards
# ═══════════════════════════════════════════════════════════════════════════════

def render_kpi_card(value: str, label: str, icon: str = "", color: str = "clr-blue"):
    """Render a glassmorphism KPI card with icon, value, and label."""
    st.markdown(f'''
    <div class="kpi-card">
        <div class="kpi-icon">{icon}</div>
        <div class="kpi-val {color}">{value}</div>
        <div class="kpi-label">{label}</div>
    </div>
    ''', unsafe_allow_html=True)


def render_kpi_row(metrics: list[dict]):
    """
    Render a row of KPI cards.
    Each metric: {"value": str, "label": str, "icon": str, "color": str}
    """
    cols = st.columns(len(metrics))
    for col, m in zip(cols, metrics):
        with col:
            render_kpi_card(
                value=m["value"],
                label=m["label"],
                icon=m.get("icon", ""),
                color=m.get("color", "clr-blue"),
            )


# ═══════════════════════════════════════════════════════════════════════════════
#  Badges
# ═══════════════════════════════════════════════════════════════════════════════

def badge_html(severity: str) -> str:
    """Return HTML for a severity badge."""
    sev = severity.upper()
    return f'<span class="badge badge-{sev.lower()}">{sev}</span>'


# ═══════════════════════════════════════════════════════════════════════════════
#  Section Headers
# ═══════════════════════════════════════════════════════════════════════════════

def render_section_header(title: str, icon: str = "", subtitle: str = ""):
    """Render a styled section header with optional icon and subtitle."""
    sub_html = f'<span class="section-sub">— {subtitle}</span>' if subtitle else ""
    st.markdown(f'''
    <div class="section-header">
        <h3>{icon} {title} {sub_html}</h3>
    </div>
    ''', unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
#  Alert Cards
# ═══════════════════════════════════════════════════════════════════════════════

def render_alert_card(alert: dict):
    """Render a single alert card with severity color-coding."""
    from datetime import datetime

    sev = str(alert.get("severity", "MEDIUM")).upper()
    sev_class = f"sev-{sev.lower()}"
    b = badge_html(sev)
    title = str(alert.get("title", "N/A"))[:90]
    src = alert.get("source", "")
    score = float(alert.get("threat_score", 0))
    url = alert.get("url", "#")
    ts = alert.get("created_at", alert.get("processed_at", ""))
    if isinstance(ts, datetime):
        ts = ts.strftime("%Y-%m-%d %H:%M UTC")

    ack = alert.get("acknowledged", False)
    ack_icon = "✅" if ack else "🔴"

    st.markdown(f'''
    <div class="alert-row {sev_class}">
        <div style="display:flex;justify-content:space-between;align-items:center;">
            <div>{b} &nbsp; <strong><a href="{url}" target="_blank" style="color:#e6edf3;text-decoration:none;">{title}</a></strong></div>
            <div style="display:flex;align-items:center;gap:12px;">
                <span style="font-size:0.75rem;color:#8b949e;">{ack_icon}</span>
                <span style="font-family:'JetBrains Mono',monospace;font-weight:700;font-size:1.1rem;color:#f85149;">{score:.3f}</span>
            </div>
        </div>
        <div style="margin-top:6px;font-size:0.76rem;color:#8b949e;">📡 {src} &nbsp;·&nbsp; 🕐 {ts}</div>
    </div>
    ''', unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
#  Status Indicators
# ═══════════════════════════════════════════════════════════════════════════════

def render_status_indicator(service: str, is_online: bool, detail: str = ""):
    """Render a pulsing status dot with service name."""
    dot_class = "dot-green" if is_online else "dot-red"
    status_text = "Online" if is_online else "Offline"
    detail_html = f' <span style="color:#484f58;font-size:0.75rem;">({detail})</span>' if detail else ""
    st.markdown(
        f'<span class="status-dot {dot_class}"></span> '
        f'<strong>{service}</strong> — '
        f'<span style="color:{"#3fb950" if is_online else "#f85149"};">{status_text}</span>'
        f'{detail_html}',
        unsafe_allow_html=True,
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  Threat Table
# ═══════════════════════════════════════════════════════════════════════════════

def render_threat_table(df, max_rows: int = 10):
    """Render a styled HTML table for top threats."""
    if df.empty:
        render_empty_state("No threats detected", "🛡️")
        return

    rows_html = ""
    for _, r in df.head(max_rows).iterrows():
        sev = r.get("severity", "MEDIUM")
        b = badge_html(sev)
        title = str(r.get("title", ""))[:80]
        url = r.get("url", "#")
        source = r.get("source", "")
        score = float(r.get("threat_score", 0))

        score_color = "#f85149" if score >= 0.85 else "#d29922" if score >= 0.65 else "#58a6ff" if score >= 0.4 else "#3fb950"
        rows_html += f'''<tr>
            <td>{b}</td>
            <td style="color:#8b949e;">{source}</td>
            <td><a href="{url}" target="_blank" style="color:#58a6ff;text-decoration:none;">{title}</a></td>
            <td style="font-family:'JetBrains Mono',monospace;font-weight:700;color:{score_color};">{score:.3f}</td>
        </tr>'''

    st.markdown(f'''
    <table class="threat-table">
        <thead><tr><th>Severity</th><th>Source</th><th>Title</th><th>Score</th></tr></thead>
        <tbody>{rows_html}</tbody>
    </table>
    ''', unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
#  Empty & Loading States
# ═══════════════════════════════════════════════════════════════════════════════

def render_empty_state(message: str, icon: str = "📭"):
    """Render a beautiful empty state placeholder."""
    st.markdown(f'''
    <div class="empty-state">
        <div class="empty-icon">{icon}</div>
        <div class="empty-msg">{message}</div>
    </div>
    ''', unsafe_allow_html=True)


def render_banner_alert(count: int, hours: float):
    """Render a pulsing threat banner alert."""
    st.markdown(f'''
    <div class="banner-alert">
        <span>🚨</span>
        <span>{count} active threat{"s" if count != 1 else ""} detected in the last {hours:.0f}h</span>
    </div>
    ''', unsafe_allow_html=True)
