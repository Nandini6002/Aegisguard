import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import time, datetime, csv
from model import detect_insider_threats

# 1. PAGE SETUP & SOC THEME
st.set_page_config(page_title="AegisGuard COMMAND", layout="wide", page_icon="🛡️")

# Professional Dark-Mode CSS
st.markdown("""
    <style>
    .stApp { background-color: #0e1117; color: white; }
    .stMetric { background-color: #161b22; border: 1px solid #30363d; padding: 20px; border-radius: 15px; }
    .stTabs [data-baseweb="tab-list"] { gap: 10px; }
    .stTabs [data-baseweb="tab"] { height: 50px; background-color: #161b22; border-radius: 5px; color: white; }
    .stTabs [aria-selected="true"] { background-color: #1f6feb !important; }
    </style>
""", unsafe_allow_html=True)

# Session State for Incident History (The "Action Log")
if 'incident_log' not in st.session_state:
    st.session_state['incident_log'] = []

st.title("🛡️ AegisGuard: Live SOC Command Center")
st.markdown("*Advanced User & Entity Behavior Analytics (UEBA) Platform*")

# 2. SIDEBAR & SIMULATION CONTROLS
st.sidebar.image("https://img.icons8.com/clouds/200/000000/shield.png")
st.sidebar.header("🕹️ System Controls")
live_mode = st.sidebar.toggle("Enable Live Telemetry Feed", value=True)
refresh_rate = st.sidebar.slider("Sensor Refresh (Sec)", 2, 10, 3)

st.sidebar.divider()
if st.sidebar.button("💥 TRIGGER 3 AM ATTACK SIMULATION", type="primary"):
    attack_data = {
        "user_id": "STOLEN_CRED", "timestamp": f"{datetime.date.today()} 03:15:00",
        "department": "Finance", "role": "External", "login_count": 1,
        "file_access": 95, "avg_file_access_30d": 2, "usb_usage": 1, "emails_sent": 1,
        "email_subject": "DUMP_CONFIDENTIAL_PASSWORDS", "network_traffic_mb": 52.4
    }
    pd.DataFrame([attack_data]).to_csv("live_telemetry.csv", mode='a', header=False, index=False)
    st.sidebar.error("ALERT: Attack injected into telemetry.")

# 3. RENDER FUNCTION (The Core UI)
def render_soc_dashboard(df):
    if 'timestamp' not in df.columns or df.empty:
        st.warning("🔄 Syncing with EDR Agent...")
        return

    results = detect_insider_threats(df)
    latest = results.iloc[-1]
    
    # SYSTEM STATUS BADGE
    if latest['threat_level'] == "CRITICAL":
        st.error(f"🚨 SYSTEM BREACH: {latest['risk_factors']}")
    elif latest['threat_level'] == "MEDIUM":
        st.warning("⚠️ SECURITY WARNING: Suspicious activity detected.")
    else:
        st.success("✅ SYSTEM SECURE: All entities operating within baseline.")

    # KPI METRICS
    m1, m2, m3, m4 = st.columns(4)
    with m1: st.metric("🌐 Network Outbound", f"{latest['network_traffic_mb']} MB")
    with m2: st.metric("🚨 Risk Index", f"{int(latest['risk_score'])}/100")
    with m3: st.metric("👤 Entity ID", latest['user_id'])
    with m4: st.metric("📂 File IO Ops", latest['file_access'])

    # MASTER TABS (All Features Combined)
    t_feed, t_forensics, t_analytics, t_log = st.tabs([
        "📺 LIVE ALERT FEED", "🕵️ FORENSIC INSPECTOR", "📊 ORG-WIDE ANALYTICS", "📜 ACTION HISTORY"
    ])

    with t_feed:
        st.subheader("🔥 Real-Time Incident Response Queue")
        def color_threat(val):
            if val == 'CRITICAL': return 'background-color: #4a0000; color: #ff4b4b; font-weight: bold;'
            if val == 'MEDIUM': return 'background-color: #3d2b00; color: #ffa500;'
            return 'color: #00ff00;'

        view_cols = ['timestamp', 'user_id', 'risk_score', 'threat_level', 'risk_factors', 'email_subject']
        st.dataframe(results.sort_values('timestamp', ascending=False)[view_cols].head(20).style.map(color_threat, subset=['threat_level']), use_container_width=True)
        
        st.write("**Threat Trajectory (Last 50 Events)**")
        st.plotly_chart(px.line(results.tail(50), x='timestamp', y='risk_score', template="plotly_dark", color_discrete_sequence=['#00f2ff']), use_container_width=True)

    with t_forensics:
        st.subheader("🔍 Deep-Dive Forensic Audit")
        f_col1, f_col2 = st.columns([1, 2])
        with f_col1:
            st.info(f"**Entity:** {latest['user_id']}\n\n**Risk Factors:** {latest['risk_factors']}")
            
            # CONTENT INSPECTOR (NLP Code Block)
            st.markdown("**Content Inspector (NLP Pattern Match):**")
            st.code(f"Snippet: {latest['email_subject']}\nPatterns: {latest['patterns_found']}", language="bash")
            
            if st.button("🛑 REVOKE ACCESS & ISOLATE", type="primary"):
                entry = {"User": latest['user_id'], "Action": "Isolated", "Reason": latest['risk_factors'], "Time": datetime.datetime.now().strftime("%H:%M:%S")}
                st.session_state['incident_log'].append(entry)
                st.toast("Security Policy Applied!")

            # RISK GAUGE (Heat Meter)
            fig_gauge = go.Figure(go.Indicator(
                mode = "gauge+number", value = latest['risk_score'],
                gauge = {'axis': {'range': [0, 100]}, 'bar': {'color': "red" if latest['risk_score'] > 65 else "cyan"}},
                title = {'text': "Current Risk Index"}
            ))
            fig_gauge.update_layout(paper_bgcolor='rgba(0,0,0,0)', font={'color': "white"}, height=250)
            st.plotly_chart(fig_gauge, use_container_width=True)

        with f_col2:
            st.write("**Network Data Exfiltration Monitor**")
            st.plotly_chart(px.area(results.tail(40), x='timestamp', y='network_traffic_mb', color_discrete_sequence=['#ff00ff']), use_container_width=True)

    with t_analytics:
        st.subheader("📉 Organizational Threat Distribution")
        a1, a2 = st.columns(2)
        with a1:
            st.plotly_chart(px.pie(results, names='threat_level', hole=0.4, title="Risk Segmentation"), use_container_width=True)
        with a2:
            st.plotly_chart(px.histogram(results, x='department', y='risk_score', color='threat_level', title="Departmental Risk Exposure"), use_container_width=True)

    with t_log:
        st.subheader("📜 Automated Response History")
        if st.session_state['incident_log']:
            st.table(pd.DataFrame(st.session_state['incident_log']))
        else:
            st.info("No response actions recorded in this session.")

# 4. MASTER EXECUTION LOOP
if live_mode:
    placeholder = st.empty()
    while True:
        try:
            df = pd.read_csv("live_telemetry.csv", on_bad_lines='skip', engine='python')
            if not df.empty and 'timestamp' in df.columns:
                with placeholder.container():
                    render_soc_dashboard(df)
            time.sleep(refresh_rate)
        except:
            time.sleep(1)