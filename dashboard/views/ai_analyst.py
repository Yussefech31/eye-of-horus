"""
Eye of Horus — AI Threat Analyst (Chatbot Interface)
"""

import sys
from pathlib import Path
import streamlit as st
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from dashboard.components import render_section_header, render_empty_state
from services.ai_service import AIAnalystService


@st.cache_resource
def get_ai_service():
    return AIAnalystService()


def _stream_groq(service: AIAnalystService, messages: list) -> str:
    try:
        from groq import Groq
        client = Groq(api_key=service.api_key)
        resp = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=messages,
            temperature=0.4,
            max_tokens=1024,
        )
        return resp.choices[0].message.content
    except Exception as e:
        return f"⚠️ **Groq API error:** {e}\n\n{service._generate_mock_analysis({})}"


def _build_system_prompt(alert: dict | None) -> str:
    base = (
        "You are an expert Level-3 SOC Analyst AI assistant for the Eye of Horus cybersecurity platform. "
        "You have deep expertise in threat intelligence, MITRE ATT&CK, incident response, malware analysis, "
        "CVE/CVSS scoring, and SOC operations. "
        "Always format your responses with clear markdown headings. Be concise, technical, and actionable."
    )
    if alert:
        base += (
            f"\n\nCurrent alert context loaded:\n"
            f"- Title: {alert.get('title', 'N/A')}\n"
            f"- Source: {alert.get('source', 'N/A')}\n"
            f"- Threat Score: {alert.get('threat_score', 0):.3f}\n"
            f"- Severity: {alert.get('severity', 'N/A')}\n"
            f"- Content: {str(alert.get('text', ''))[:800]}\n\n"
            "When the user asks about 'this alert', 'this threat', or 'this CVE', refer to the above context."
        )
    return base


def _handle_user_message(service: AIAnalystService, user_input: str, alert: dict | None):
    system_prompt = _build_system_prompt(alert)
    st.session_state.ai_chat_history.append({"role": "user", "content": user_input})

    api_messages = [{"role": "system", "content": system_prompt}]
    for msg in st.session_state.ai_chat_history:
        api_messages.append({"role": msg["role"], "content": msg["content"]})

    with st.spinner("🧠 Analyst thinking..."):
        reply = _stream_groq(service, api_messages) if service.api_key else service._generate_mock_analysis(alert or {})

    st.session_state.ai_chat_history.append({"role": "assistant", "content": reply})


def _trigger_auto_analysis(service: AIAnalystService, alert: dict):
    auto_prompt = (
        f"Please analyze this threat alert:\n\n"
        f"**Title:** {alert.get('title', 'N/A')}\n"
        f"**Severity:** {alert.get('severity', 'N/A')} | "
        f"**Score:** {alert.get('threat_score', 0):.3f} | "
        f"**Source:** {alert.get('source', 'N/A')}\n\n"
        "Provide: threat explanation, potential impact, and MITRE ATT&CK-aligned mitigation steps."
    )
    _handle_user_message(service, auto_prompt, alert)
    st.rerun()


def render(df: pd.DataFrame, threshold: float):
    render_section_header(
        "AI Threat Analyst", icon="🤖",
        subtitle="chat with your Level-3 SOC analyst powered by Llama 3.3 70B"
    )

    ai_service = get_ai_service()

    if "ai_chat_history" not in st.session_state:
        st.session_state.ai_chat_history = []

    # ── TOP CONTROL PANEL ─────────────────────────────────────────────────────
    with st.container():
        st.markdown(
            '<div style="background:rgba(22,27,34,0.9);border:1px solid #30363d;'
            'border-radius:10px;padding:16px 20px;margin-bottom:18px;">',
            unsafe_allow_html=True
        )

        ctrl_col1, ctrl_col2 = st.columns([2, 1])

        selected_alert = None
        with ctrl_col1:
            context_mode = st.radio(
                "Analyst Mode",
                ["🔍 Selected Alert", "🌐 General SOC Assistant"],
                horizontal=True,
                key="ai_context_mode",
                label_visibility="collapsed"
            )

            if context_mode == "🔍 Selected Alert" and not df.empty:
                threats = df[df["threat_score"] >= threshold].sort_values("threat_score", ascending=False)
                if not threats.empty:
                    options = [
                        f"[{r['threat_score']:.3f}]  {str(r.get('title', 'N/A'))[:70]}"
                        for _, r in threats.head(30).iterrows()
                    ]
                    idx = st.selectbox(
                        "Select alert to analyze:",
                        range(len(options)),
                        format_func=lambda i: options[i],
                        key="ai_alert_selector",
                        label_visibility="collapsed"
                    )
                    selected_alert = threats.iloc[idx].to_dict()
                else:
                    st.info("No alerts exceed the current threshold.")

        with ctrl_col2:
            st.markdown("<br>", unsafe_allow_html=True)
            btn_col1, btn_col2 = st.columns(2)
            with btn_col1:
                if selected_alert and st.button("🔎 Auto-Analyze", use_container_width=True, type="primary"):
                    _trigger_auto_analysis(ai_service, selected_alert)
            with btn_col2:
                if st.button("🗑️ Clear Chat", use_container_width=True):
                    st.session_state.ai_chat_history = []
                    st.rerun()

        # Alert context badge (shown inline below controls)
        if selected_alert:
            sev = selected_alert.get("severity", "N/A")
            sev_color = {"CRITICAL": "#f85149", "HIGH": "#d29922",
                         "MEDIUM": "#58a6ff", "LOW": "#3fb950"}.get(sev, "#8b949e")
            st.markdown(
                f'<div style="display:flex;align-items:center;gap:12px;margin-top:10px;'
                f'background:rgba(13,17,23,0.6);border:1px solid #21262d;border-radius:6px;padding:8px 12px;">'
                f'<span style="color:{sev_color};font-weight:bold;font-size:0.8rem;">'
                f'● {sev} — Score: {selected_alert.get("threat_score",0):.3f}</span>'
                f'<span style="color:#8b949e;font-size:0.8rem;">|</span>'
                f'<span style="color:#e6edf3;font-size:0.82rem;">{str(selected_alert.get("title","N/A"))[:80]}</span>'
                f'<span style="color:#8b949e;font-size:0.75rem;margin-left:auto;">src: {selected_alert.get("source","N/A")}</span>'
                f'</div>',
                unsafe_allow_html=True
            )

        st.markdown('</div>', unsafe_allow_html=True)

    # ── CHAT HISTORY ──────────────────────────────────────────────────────────
    if not st.session_state.ai_chat_history:
        st.markdown(
            '<div style="text-align:center;padding:50px 20px;color:#8b949e;">'
            '<div style="font-size:3.5rem;">🤖</div>'
            '<div style="font-size:1.15rem;margin-top:12px;color:#e6edf3;font-weight:600;">'
            'Eye of Horus AI Analyst</div>'
            '<div style="font-size:0.9rem;margin-top:6px;">Powered by Llama 3.3 70B via Groq</div>'
            '<div style="font-size:0.85rem;margin-top:16px;max-width:500px;margin-left:auto;'
            'margin-right:auto;line-height:1.6;">'
            'Select an alert above and click <b>🔎 Auto-Analyze</b>, '
            'or type any cybersecurity question below.</div>'
            '</div>',
            unsafe_allow_html=True
        )
    else:
        for msg in st.session_state.ai_chat_history:
            with st.chat_message(msg["role"], avatar="🤖" if msg["role"] == "assistant" else "👤"):
                st.markdown(msg["content"])

    # ── CHAT INPUT ────────────────────────────────────────────────────────────
    user_input = st.chat_input(
        "Ask the analyst anything... e.g. 'What MITRE tactics does this use?' or 'Explain CVE-2025-XXXX'"
    )
    if user_input:
        _handle_user_message(ai_service, user_input, selected_alert)
        st.rerun()
