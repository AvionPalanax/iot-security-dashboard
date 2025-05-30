import paho.mqtt.client as mqtt
import json
import pandas as pd
import os
from utils.predictor import predict_anomalies  # Make sure this is implemented and working

# Configuration
BROKER = "broker.hivemq.com"
PORT = 1883
TOPIC = "iot/security/anomaly"
LOG_FILE = "logs/live_mqtt_log.csv"

# Ensure log folder exists
os.makedirs("logs", exist_ok=True)

# Create log file with headers if not present
if not os.path.exists(LOG_FILE) or os.path.getsize(LOG_FILE) == 0:
    pd.DataFrame(columns=["device_id", "anomaly_score", "mfa", "vpn", "firewall"]).to_csv(LOG_FILE, index=False)

# MQTT connection callback
def on_connect(client, userdata, flags, rc):
    print(f"[INFO] Connected to MQTT broker with result code {rc}")
    client.subscribe(TOPIC)
    print(f"[INFO] Subscribed to topic: {TOPIC}")

# MQTT message callback
def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
        print(f"[RECEIVED] Payload: {payload}")

        # Convert to DataFrame
        input_df = pd.DataFrame([payload])

        # Predict anomaly score
        result = predict_anomalies(input_df, model_path="models/lstm_anomaly_model.pkl")

        print(f"[PREDICTED] Anomaly score: {result[0]}")

        # Log entry
        log_entry = {
            "device_id": payload.get("device_id", "Unknown"),
            "anomaly_score": round(result[0], 3),
            "mfa": payload.get("mfa", ""),
            "vpn": payload.get("vpn", ""),
            "firewall": payload.get("firewall", "")
        }

        # Append to CSV log
        df_log = pd.DataFrame([log_entry])
        df_log.to_csv(LOG_FILE, mode='a', header=False, index=False)
        print(f"[LOGGED] {log_entry}")

    except Exception as e:
        print(f"[ERROR] Failed to process message: {e}")

def main():
    print("[INFO] Starting mqtt_subscriber.py script...")
    client = mqtt.Client()

    client.on_connect = on_connect
    client.on_message = on_message

    print("[INFO] Initializing MQTT client...")
    client.connect(BROKER, PORT, 60)

    print("[INFO] Connecting to broker...")
    client.loop_forever()

if __name__ == "__main__":
    main()
