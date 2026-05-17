"""
Eye of Horus — SOC Reporting
Generate PDF and CSV reports based on threat intelligence data.
"""

import sys
import base64
from io import BytesIO
from datetime import datetime
from pathlib import Path

import streamlit as st
import pandas as pd
from fpdf import FPDF

from dashboard.components import render_section_header, render_empty_state, render_kpi_row


# ═══════════════════════════════════════════════════════════════════════════════
#  PDF Generation
# ═══════════════════════════════════════════════════════════════════════════════

def sanitize_text(text: str) -> str:
    """Sanitize text for standard FPDF fonts (replace unsupported unicode chars)."""
    if not isinstance(text, str):
        text = str(text)
    replacements = {
        '—': '-', '–': '-', '“': '"', '”': '"', 
        '‘': "'", '’': "'", '…': '...', '•': '-'
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    # Replace any remaining unsupported characters with '?'
    return text.encode('latin-1', 'replace').decode('latin-1')


class SOCReportPDF(FPDF):
    def header(self):
        # Logo / Branding
        self.set_font('Arial', 'B', 15)
        self.set_text_color(14, 56, 122) # Dark blue brand color
        self.cell(0, 10, 'EYE OF HORUS', 0, 1, 'L')
        self.set_font('Arial', '', 10)
        self.set_text_color(100, 100, 100)
        self.cell(0, 10, 'Security Operations Center - Threat Intelligence Report', 0, 1, 'L')
        self.line(10, 30, 200, 30)
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(100, 100, 100)
        self.cell(0, 10, f'Page {self.page_no()} | Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}', 0, 0, 'C')


def generate_pdf_report(df: pd.DataFrame, author: str, time_window: str) -> bytes:
    """Generate a formatted PDF report."""
    pdf = SOCReportPDF()
    pdf.add_page()
    
    # ── Summary Section ──────────────────────────────────────────────────
    pdf.set_font('Arial', 'B', 12)
    pdf.set_text_color(30, 30, 30) # Text primary (dark)
    pdf.cell(0, 10, 'Executive Summary', 0, 1)
    
    pdf.set_font('Arial', '', 10)
    pdf.set_text_color(50, 50, 50)
    
    total = len(df)
    critical = len(df[df.get("severity", pd.Series(dtype=str)) == "CRITICAL"]) if "severity" in df.columns else 0
    high = len(df[df.get("severity", pd.Series(dtype=str)) == "HIGH"]) if "severity" in df.columns else 0
    
    summary_text = sanitize_text(
        f"This report covers the threat landscape over the past {time_window}. "
        f"A total of {total} threat intelligence records were analyzed. "
        f"Of these, {critical} were classified as CRITICAL and {high} as HIGH severity. "
        f"Report prepared by: {author}."
    )
    pdf.multi_cell(0, 6, summary_text)
    pdf.ln(5)

    # ── Top Threats ──────────────────────────────────────────────────────
    pdf.set_font('Arial', 'B', 12)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 10, 'Top 10 Critical Threats', 0, 1)
    
    top_threats = df.sort_values(by="threat_score", ascending=False).head(10)
    
    for i, row in top_threats.iterrows():
        title = sanitize_text(str(row.get("title", "N/A"))[:80] + ("..." if len(str(row.get("title", ""))) > 80 else ""))
        score = row.get("threat_score", 0)
        source = sanitize_text(str(row.get("source", "N/A")))
        
        pdf.set_font('Arial', 'B', 9)
        pdf.set_text_color(248, 81, 73) if score >= 0.85 else pdf.set_text_color(210, 153, 34)
        pdf.cell(15, 6, f"[{score:.3f}]", 0, 0)
        
        pdf.set_font('Arial', '', 9)
        pdf.set_text_color(120, 120, 120)
        pdf.cell(35, 6, f"({source})", 0, 0)
        
        pdf.set_text_color(50, 50, 50)
        pdf.cell(0, 6, title, 0, 1)

    pdf.ln(10)

    # ── Source Breakdown ─────────────────────────────────────────────────
    if "source" in df.columns:
        pdf.set_font('Arial', 'B', 12)
        pdf.set_text_color(30, 30, 30)
        pdf.cell(0, 10, 'Source Analysis', 0, 1)
        
        sources = df["source"].value_counts()
        pdf.set_font('Arial', '', 10)
        pdf.set_text_color(50, 50, 50)
        for src, count in sources.items():
            pdf.cell(50, 6, sanitize_text(str(src)), 0, 0)
            pdf.cell(0, 6, f"{count} records", 0, 1)

    # fpdf2 output() returns a bytearray, no need to encode
    return bytes(pdf.output())


# ═══════════════════════════════════════════════════════════════════════════════
#  Render
# ═══════════════════════════════════════════════════════════════════════════════

def render(df: pd.DataFrame, threshold: float, time_window: str):
    """Render the Reports page."""

    render_section_header("SOC Reports", icon="📑", subtitle="generate PDF and CSV threat intelligence reports")

    if df.empty:
        render_empty_state("No data available to generate reports.", "📑")
        return

    # ── Report Configuration ──────────────────────────────────────────────
    col_cfg1, col_cfg2 = st.columns(2)
    with col_cfg1:
        report_title = st.text_input("Report Title", "Daily SOC Threat Briefing", key="rep_title")
        author = st.text_input("Prepared By", "SOC Analyst", key="rep_author")
    with col_cfg2:
        include_charts = st.checkbox("Include Charts (Pro)", disabled=True, help="Requires premium PDF engine")
        only_threats = st.checkbox("Only Include Threats > Threshold", value=True)

    st.markdown("")

    report_df = df[df["threat_score"] >= threshold] if only_threats else df

    # ── Report Preview KPIs ───────────────────────────────────────────────
    render_kpi_row([
        {"value": f"{len(report_df)}", "label": "Included Records", "icon": "📄", "color": "clr-blue"},
        {"value": f"{report_df['threat_score'].mean():.3f}", "label": "Avg Score", "icon": "📊", "color": "clr-amber"},
    ])
    st.markdown("")

    # ── Generation Actions ────────────────────────────────────────────────
    col_pdf, col_csv = st.columns(2)

    with col_pdf:
        render_section_header("Executive PDF Report", icon="📕")
        st.caption("A formatted summary document suitable for management and daily briefings.")
        
        if st.button("Generate PDF Report", key="gen_pdf", use_container_width=True):
            with st.spinner("Generating PDF..."):
                try:
                    pdf_bytes = generate_pdf_report(report_df, author, time_window)
                    b64_pdf = base64.b64encode(pdf_bytes).decode('utf-8')
                    
                    # Create a download link using HTML to avoid Streamlit rerun issues
                    href = f'<a href="data:application/pdf;base64,{b64_pdf}" download="soc_report_{datetime.now().strftime("%Y%m%d")}.pdf" class="btn btn-primary" style="display:inline-block;padding:0.5rem 1rem;background-color:#58a6ff;color:#0d1117;border-radius:4px;text-decoration:none;font-weight:600;margin-top:10px;">⬇️ Click here to Download PDF</a>'
                    st.markdown(href, unsafe_allow_html=True)
                    st.success("PDF generated successfully!")
                except Exception as e:
                    st.error(f"Error generating PDF: {e}")

    with col_csv:
        render_section_header("Raw Data Export", icon="📗")
        st.caption("Full dataset export for external analysis in Excel, Splunk, or Jupyter.")
        
        csv_data = report_df.to_csv(index=False)
        st.download_button(
            "⬇️ Download CSV",
            data=csv_data,
            file_name=f"soc_data_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv",
            use_container_width=True,
        )

    # ── Report Preview ────────────────────────────────────────────────────
    st.markdown("---")
    render_section_header("Data Preview", icon="👀")
    
    display_cols = [c for c in ["severity", "source", "title", "threat_score"] if c in report_df.columns]
    st.dataframe(report_df[display_cols].head(20), width="stretch", hide_index=True)
