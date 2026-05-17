"""
Eye of Horus — Cyber Range Simulation Center
"""

import sys
import os
import time
from pathlib import Path
import pandas as pd
import streamlit as st
import threading
from pymongo import MongoClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from config.settings import mongo as mongo_cfg
from dashboard.components import render_section_header, render_kpi_row

# Add simulation engine to path so we can trigger the scenarios
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "simulation_engine"))
try:
    from simulation_engine.scenario_generators.scenarios import SCENARIO_MAP
    from simulation_engine.validators.pipeline_validator import PipelineValidator
    from simulation_engine.engine import SimulationEngine
except ImportError:
    SCENARIO_MAP = {}
    PipelineValidator = None
    SimulationEngine = None


def get_db_client():
    return MongoClient(mongo_cfg.URI, serverSelectionTimeoutMS=2000)

@st.cache_resource
def get_engine():
    if SimulationEngine:
        return SimulationEngine()
    return None

def inject_scenario_batch(scenario_name: str, intensity: int):
    """Pushes a batch of scenario events to Kafka (sim-raw-osint)"""
    from broker.producer import OsintProducer
    generator = SCENARIO_MAP.get(scenario_name)
    if not generator:
        return 0
    events = list(generator.generate(intensity))
    if not events:
        return 0
        
    try:
        from config.settings import kafka as kafka_cfg
        with OsintProducer() as producer:
            for event in events:
                # Transform to OSINT schema
                from datetime import datetime, timezone
                record = {
                    "post_id": event["id"],
                    "title": event["title"],
                    "text": event["description"],
                    "author": event["author"],
                    "url": event["url"],
                    "published_at": datetime.fromtimestamp(event["created_utc"], tz=timezone.utc).isoformat(),
                    "extra": {
                        "source_type": "simulation",
                        "threat_type": event["threat_type"],
                        "source_ip": event["source_ip"],
                        "cvss_score": event["cvss"],
                        "num_comments": event["comments"],
                        "upvote_ratio": 1.0,
                    }
                }
                producer.send(record, topic="sim-raw-osint", key="simulation")
        return len(events)
    except Exception as e:
        st.error(f"Kafka error: {e}")
        return 0

def fetch_sim_data():
    """Fetch data from sim collections for mini dashboards."""
    try:
        client = get_db_client()
        db = client[mongo_cfg.DB_NAME]
        alerts = list(db.sim_threat_scores.find().sort("processed_at", -1).limit(100))
        df = pd.DataFrame(alerts)
        return df
    except Exception:
        return pd.DataFrame()


def render():
    """Render the Cyber Range Control Center."""
    render_section_header("Cyber Range Simulation", icon="🎯", subtitle="isolated environment for full system testing")

    engine = get_engine()
    if not engine:
        st.error("Simulation Engine module not found.")
        return

    # Initialize session state for auto-refresh
    if "sim_auto_refresh" not in st.session_state:
        st.session_state.sim_auto_refresh = False

    # ── Controls ──────────────────────────────────────────────────────────
    st.markdown("### 🎛️ Command Center")
    with st.container():
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            scenario = st.selectbox("Attack Scenario", options=list(SCENARIO_MAP.keys()))
        with col2:
            intensity = st.slider("Attack Intensity", min_value=1, max_value=20, value=5)
        with col3:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("🚀 Inject Scenario Batch", use_container_width=True, type="primary"):
                if not engine.is_running:
                    st.warning("Start the Simulation Pipeline first!")
                else:
                    count = inject_scenario_batch(scenario, intensity)
                    st.toast(f"Injected {count} events into simulation pipeline!", icon="☠️")
        with col4:
            st.markdown("<br>", unsafe_allow_html=True)
            if engine.is_running:
                if st.button("🛑 Stop Pipeline", use_container_width=True):
                    engine.stop_pipeline()
                    st.session_state.sim_auto_refresh = False
                    st.rerun()
            else:
                if st.button("⚡ Start Isolated Pipeline", use_container_width=True):
                    engine.start_pipeline()
                    st.session_state.sim_auto_refresh = True
                    st.rerun()

    st.markdown("---")
    
    st.markdown("### 🌪️ Stress Testing")
    with st.expander("Advanced Pipeline Stress Test", expanded=False):
        st.warning("This will flood the pipeline with thousands of events per second.")
        st_col1, st_col2 = st.columns(2)
        with st_col1:
            stress_rate = st.number_input("Events / Sec", min_value=100, max_value=5000, value=500, step=100)
        with st_col2:
            stress_dur = st.number_input("Duration (Sec)", min_value=1, max_value=60, value=5, step=1)
            
        if st.button("🚨 Launch Stress Test", type="primary"):
            if not engine.is_running:
                st.error("Start the Simulation Pipeline first!")
            else:
                from simulation_engine.stress_testing.flooder import run_stress_test
                with st.spinner("Flooding pipeline..."):
                    run_stress_test(events_per_sec=stress_rate, duration_sec=stress_dur)
                st.success("Stress test complete. Check validators for pipeline health.")

    st.markdown("---")

    # ── Validators & Live Status ──────────────────────────────────────────
    st.markdown("### 🛡️ System Validation")
    
    if engine.is_running:
        st.markdown(
            '<div style="background:rgba(35, 134, 54, 0.1); border:1px solid rgba(35, 134, 54, 0.4); padding:10px; border-radius:5px; margin-bottom:15px;">'
            '<span style="color:#2ea043; font-weight:bold;">🟢 PIPELINE ACTIVE:</span> Isolated Consumer & Threat Processor running.'
            '</div>', unsafe_allow_html=True
        )
    else:
        st.markdown(
            '<div style="background:rgba(248,81,73,0.1); border:1px solid rgba(248,81,73,0.4); padding:10px; border-radius:5px; margin-bottom:15px;">'
            '<span style="color:#f85149; font-weight:bold;">🔴 PIPELINE OFFLINE:</span> Start pipeline to process simulation events.'
            '</div>', unsafe_allow_html=True
        )

    val_col1, val_col2, val_col3, val_col4 = st.columns(4)
    validator = PipelineValidator() if PipelineValidator else None
    metrics = validator.get_validation_metrics() if validator else {}

    with val_col1:
        color = "green" if metrics.get("raw_ingested", 0) > 0 else "gray"
        st.markdown(f"**Kafka -> Mongo**<br><span style='color:{color}; font-size:24px;'>●</span> {metrics.get('raw_ingested', 0)} events", unsafe_allow_html=True)
    with val_col2:
        color = "green" if metrics.get("threats_scored", 0) > 0 else "gray"
        st.markdown(f"**Threat Scoring**<br><span style='color:{color}; font-size:24px;'>●</span> {metrics.get('threats_scored', 0)} scored", unsafe_allow_html=True)
    with val_col3:
        # Anomaly detected
        color = "orange" if metrics.get("anomaly_detected") else "gray"
        st.markdown(f"**Anomaly Engine**<br><span style='color:{color}; font-size:24px;'>●</span> {'Triggered' if metrics.get('anomaly_detected') else 'Idle'}", unsafe_allow_html=True)
    with val_col4:
        # Scoring Accuracy
        acc = metrics.get("scoring_accuracy")
        color = "green" if acc is True else ("red" if acc is False else "gray")
        status = "Passed" if acc is True else ("Failed" if acc is False else "Waiting")
        st.markdown(f"**CVSS Severity Logic**<br><span style='color:{color}; font-size:24px;'>●</span> {status}", unsafe_allow_html=True)

    st.markdown("---")

    # ── Mini Dashboards ───────────────────────────────────────────────────
    st.markdown("### 📊 Live Simulation Dashboards")
    
    df = fetch_sim_data()
    
    dash_col1, dash_col2 = st.columns([1, 1])
    
    with dash_col1:
        st.markdown("#### 🌍 Attack Map (Simulated)")
        if not df.empty:
            from dashboard.views.attack_map import _build_pydeck_map, build_geo_df
            try:
                geo_df, _, _ = build_geo_df(df)
                if not geo_df.empty:
                    _build_pydeck_map(geo_df)
                else:
                    st.info("No geospatial data mapped yet.")
            except Exception as e:
                st.error(f"Map error: {e}")
        else:
            st.info("No geospatial events generated yet.")

    with dash_col2:
        st.markdown("#### 🚨 Alerts Feed (Simulated)")
        if not df.empty:
            st.dataframe(
                df[["post_id", "severity", "threat_score", "source", "title"]].head(20),
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("No alerts generated yet.")
            
    # Auto-refresh loop
    if st.session_state.sim_auto_refresh:
        time.sleep(2)
        st.rerun()

