# app.py
import streamlit as st
import pandas as pd
from compliance_auditor import system_scan_data, iso_27001_controls
from triage import AlertTriage

# Page Configuration
st.set_page_config(
    page_title="SOC-1 SecOps & GRC Command Center",
    page_icon="🛡️",
    layout="wide"
)

# Header Section
st.title("🛡️ SOC-1: Automated SecOps & GRC Command Center")
st.markdown("Real-time infrastructure compliance monitoring, firewall log triage, and automated threat scoring.")

# Sidebar Controls
st.sidebar.header("Control Panel")
selected_view = st.sidebar.radio("Navigation", ["Overview Dashboard", "GRC Compliance Audit", "Live Alert Triage"])

if selected_view == "Overview Dashboard":
    st.subheader("System Health Metrics")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric(label="Active Firewall Status", value="Protected", delta="Online")
    with col2:
        st.metric(label="Compliance Health Score", value="50%", delta="-1 Control Flagged")
    with col3:
        st.metric(label="Pending Alerts", value="1 Critical", delta="Action Required", delta_color="inverse")
        
    st.markdown("---")
    st.info("💡 **Tip:** Use the sidebar to inspect detailed GRC control frameworks or simulate incoming threat triage logs.")

elif selected_view == "GRC Compliance Audit":
    st.subheader("ISO 27001 Compliance Auditor")
    st.markdown("Evaluating current system configurations against global security frameworks.")
    
    audit_data = []
    for control_id, control in iso_27001_controls.items():
        passed = control["check"](system_scan_data)
        audit_data.append({
            "Control ID": control_id,
            "Title": control["title"],
            "Status": "✅ COMPLIANT" if passed else "❌ NON-COMPLIANT",
            "Remediation Plan": control["remediation"] if not passed else "None required"
        })
        
    df_audit = pd.DataFrame(audit_data)
    st.dataframe(df_audit, use_container_width=True)

elif selected_view == "Live Alert Triage":
    st.subheader("Simulated Log Ingestion & Threat Triage")
    
    # Interactive input for custom log testing
    custom_payload = st.text_input(
        "Simulate Raw Log Payload:", 
        value="DENY src=45.33.32.156 dst=10.0.0.15 proto=TCP dpt=3389 (Brute-force pattern on admin port)"
    )
    source_system = st.selectbox("Source System", ["FortiGate", "Windows Security", "M365 Exchange"])
    
    if st.button("Run AI Triage Assessment"):
        alert = AlertTriage(source=source_system, event_type="Firewall Incursion", payload=custom_payload)
        score = alert.calculate_risk_score()
        priority = alert.evaluate_priority()
        
        col_a, col_b = st.columns(2)
        with col_a:
            st.metric(label="Calculated Risk Score", value=f"{score} / 100")
        with col_b:
            st.metric(label="Priority Assessment", value=priority)
            
        if score >= 75:
            st.error("⚠️ High-risk activity detected! Immediate automated firewall blocking recommended.")
        else:
            st.success("✅ Event logged successfully. Low immediate threat level.")