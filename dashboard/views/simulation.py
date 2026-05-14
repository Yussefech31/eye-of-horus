"""
Eye of Horus — Simulation Mode
Control panel to inject synthetic threat data and run controlled attack scenarios
for testing and demonstration purposes.
"""

import sys
from pathlib import Path

import streamlit as st
from pymongo import MongoClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from config.settings import mongo as mongo_cfg
from dashboard.components import render_section_header, render_kpi_row
from scraper.mock_scraper import SCENARIOS


def get_sim_state():
    """Get the current simulation state from MongoDB."""
    try:
        client = MongoClient(mongo_cfg.URI, serverSelectionTimeoutMS=2000)
        db = client[mongo_cfg.DB_NAME]
        state = db.simulation_state.find_one()
        if not state:
            state = {"active": False, "scenario": "Random", "intensity": 5}
            db.simulation_state.insert_one(state)
        return state, db.simulation_state
    except Exception as e:
        st.error(f"Failed to connect to MongoDB: {e}")
        return {"active": False, "scenario": "Random", "intensity": 5}, None


def render():
    """Render the Simulation Control Panel."""

    render_section_header("Simulation & Demo Mode", icon="🎮", subtitle="control synthetic threat generation")

    state, collection = get_sim_state()
    is_active = state.get("active", False)
    
    # ── Status Banner ─────────────────────────────────────────────────────
    if is_active:
        st.markdown(
            '<div style="background:rgba(248,81,73,0.1); border:1px solid rgba(248,81,73,0.4); '
            'padding:15px; border-radius:8px; margin-bottom:20px;">'
            '<h4 style="color:#f85149; margin:0 0 5px 0;">🔴 SIMULATION ACTIVE</h4>'
            '<p style="color:#e6edf3; margin:0; font-size:0.9rem;">Synthetic threat data is currently being injected into the pipeline.</p>'
            '</div>', unsafe_allow_html=True
        )
    else:
        st.markdown(
            '<div style="background:rgba(88,166,255,0.1); border:1px solid rgba(88,166,255,0.4); '
            'padding:15px; border-radius:8px; margin-bottom:20px;">'
            '<h4 style="color:#58a6ff; margin:0 0 5px 0;">⏸️ SIMULATION PAUSED</h4>'
            '<p style="color:#e6edf3; margin:0; font-size:0.9rem;">Pipeline is running in pure OSINT mode (no synthetic data).</p>'
            '</div>', unsafe_allow_html=True
        )

    # ── Controls ──────────────────────────────────────────────────────────
    with st.form("sim_controls_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            scenario_options = ["Random"] + list(SCENARIOS.keys())
            current_scenario = state.get("scenario", "Random")
            if current_scenario not in scenario_options:
                current_scenario = "Random"
                
            selected_scenario = st.selectbox(
                "Attack Scenario", 
                options=scenario_options,
                index=scenario_options.index(current_scenario),
                help="Select the type of threat data to generate."
            )
            
            st.markdown(f"**Scenario Details:**")
            if selected_scenario == "Random":
                st.caption("Mixes all attack types randomly.")
            else:
                keywords = SCENARIOS[selected_scenario]["keywords"]
                st.caption(f"Keywords: {', '.join(keywords)}")

        with col2:
            intensity = st.slider(
                "Attack Intensity (Events/sec)", 
                min_value=1, max_value=10, 
                value=state.get("intensity", 5),
                help="Higher intensity generates more records and forces higher threat scores."
            )
            
            new_status = st.radio(
                "Engine Status",
                options=["Active", "Paused"],
                index=0 if is_active else 1,
                horizontal=True
            )

        submit = st.form_submit_button("Update Simulation Engine", type="primary")

        if submit and collection is not None:
            new_active = new_status == "Active"
            collection.update_one(
                {}, 
                {"$set": {"active": new_active, "scenario": selected_scenario, "intensity": intensity}},
                upsert=True
            )
            st.toast("Simulation engine updated successfully!", icon="✅")
            st.rerun()

    # ── Instruction ───────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("""
    ### How it Works
    1. **Scraper Orchestrator**: The backend `orchestrator.py` continuously runs the `MockScraper` in the background.
    2. **Database Sync**: The scraper reads the configuration you set here from MongoDB every 2 seconds.
    3. **Injection**: If Active, it injects realistic OSINT payloads matching the scenario directly into the Kafka `raw-osint` topic.
    4. **Processing**: The Threat Processor scores these synthetic events exactly like real OSINT, allowing you to demo the correlation engine, attack map, and live alerts in real-time.
    """)
