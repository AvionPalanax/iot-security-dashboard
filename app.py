import streamlit as st
import pandas as pd
import numpy as np
import time
from utils.predictor import predict_anomalies
from pdf_generator import generate_pdf

st.set_page_config(layout="wide")
st.sidebar.title("IoT Security Dashboard Navigation")
page = st.sidebar.radio("Go to", ["Live Monitoring", "Offline Analysis"])

def apply_threat_response(df):
    df['policy_violations'] = ((df['vpn'] == 0).astype(int) +
                               (df['mfa'] == 0).astype(int) +
                               (df['firewall'] == 0).astype(int))
    df['threat_level'] = np.where(
        (df['anomaly_score'] > 0.9) & (df['policy_violations'] >= 2),
        'High', 'Normal'
    )
    df['auto_action'] = np.where(
        df['threat_level'] == 'High', 'Device Quarantined', 'None'
    )
    return df

if page == "Live Monitoring":
    st.title("📡 Live MQTT Monitoring")
    refresh_rate = st.sidebar.slider("Refresh interval (seconds)", 5, 60, 10)
    mqtt_placeholder = st.empty()

    try:
        while True:
            with mqtt_placeholder.container():
                live_data = pd.read_csv("logs/live_mqtt_log.csv")
                live_data["device_id"] = [f"Device_{i}" for i in range(len(live_data))]

                st.subheader("📊 Anomalies in Recent MQTT Packets")
                window_sizes = [10, 20, 50, 100]
                cols = st.columns(len(window_sizes))
                for i, w in enumerate(window_sizes):
                    recent = live_data.tail(w)
                    count = (recent["anomaly_score"] > 0.5).sum()
                    cols[i].metric(f"Last {w} Packets", f"{count}")

                if 'timestamp' not in live_data.columns:
                    live_data['timestamp'] = pd.date_range(end=pd.Timestamp.now(), periods=len(live_data), freq='s')

                live_data['timestamp'] = pd.to_datetime(live_data['timestamp'], errors='coerce')
                live_data = live_data.dropna(subset=['timestamp'])

                if not live_data.empty:
                    st.line_chart(live_data.tail(20).set_index('timestamp')['anomaly_score'])

                st.dataframe(live_data.tail(10), use_container_width=True)

                st.subheader("🚨 Policy Violations in MQTT")
                live_data['vpn'] = live_data.get('vpn', 1)
                live_data['mfa'] = live_data.get('mfa', 1)
                live_data['firewall'] = live_data.get('firewall', 1)

                last_20 = live_data.tail(20)
                total_violations = ((last_20['vpn'] == 0) | (last_20['mfa'] == 0) | (last_20['firewall'] == 0)).sum()
                col1, col2, col3, col4 = st.columns(4)
                col1.metric("Total Policy Violations (Last 20)", total_violations)
                col2.metric("VPN Violations (Last 20)", (last_20['vpn'] == 0).sum())
                col3.metric("MFA Violations (Last 20)", (last_20['mfa'] == 0).sum())
                col4.metric("Firewall Violations (Last 20)", (last_20['firewall'] == 0).sum())

                live_data = apply_threat_response(live_data)

                st.subheader("🧠 Threat Response Actions")
                st.dataframe(live_data[['device_id', 'anomaly_score', 'policy_violations', 'threat_level', 'auto_action']].tail(10))

            time.sleep(refresh_rate)

    except FileNotFoundError:
        st.warning("Live MQTT data not found.")

elif page == "Offline Analysis":
    st.title("📁 Offline Analysis from CSV")
    offline_file = st.file_uploader("Upload CSV", type="csv")

    if offline_file:
        df = pd.read_csv(offline_file)
        df["device_id"] = [f"Device_{i}" for i in range(len(df))]

        st.subheader("🔍 Anomaly Detection")
        preds = predict_anomalies(df, "models/lstm_anomaly_model.h5")
        df['anomaly_score'] = preds
        anomalies = df[df['anomaly_score'] > 0.5]
        st.dataframe(anomalies[['device_id', 'anomaly_score']])

        total_packets = len(df)
        total_anomalies = len(anomalies)
        col_a, col_b = st.columns(2)
        col_a.metric("Total Packets Received", total_packets)
        col_b.metric("Total Anomalies Detected", total_anomalies)

        if 'timestamp' not in df.columns:
            df['timestamp'] = pd.date_range(end=pd.Timestamp.now(), periods=len(df), freq='s')
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df = df.dropna(subset=['timestamp'])

        if not df.empty:
            st.line_chart(df.tail(100).set_index('timestamp')['anomaly_score'])

        st.subheader("🚨 Policy Violations")
        df['vpn'] = df.get('vpn', 1)
        df['mfa'] = df.get('mfa', 1)
        df['firewall'] = df.get('firewall', 1)

        violations = df[(df['vpn'] == 0) | (df['mfa'] == 0) | (df['firewall'] == 0)]
        st.dataframe(violations[['device_id', 'vpn', 'mfa', 'firewall']])

        df = apply_threat_response(df)
        st.subheader("🧠 Threat Response Actions")
        st.dataframe(df[['device_id', 'anomaly_score', 'policy_violations', 'threat_level', 'auto_action']])

        st.subheader("📄 Download Report")
        response_df = df[['timestamp', 'device_id', 'auto_action']]
        pdf_bytes = generate_pdf(anomalies, violations, response_df)
        st.download_button("Download PDF Report", data=pdf_bytes, file_name="iot_offline_report.pdf", mime="application/pdf")
