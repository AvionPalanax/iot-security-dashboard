
import paho.mqtt.client as mqtt
import json
import random
import time

BROKER = "broker.hivemq.com"
PORT = 1883
TOPIC = "iot/security/anomaly"  # Updated to match subscriber

client = mqtt.Client()
client.connect(BROKER, PORT, 60)

def generate_packet(device_id):
    return {
        "device_id": device_id,
        "feature1": round(random.uniform(0.1, 1.0), 2),
        "feature2": round(random.uniform(0.1, 1.0), 2),
        "feature3": round(random.uniform(0.1, 1.0), 2),
        "feature4": round(random.uniform(0.1, 1.0), 2),
        "mfa": random.choice([0, 1]),
        "vpn": random.choice([0, 1]),
        "firewall": random.choice([0, 1])
    }

print("Starting MQTT publisher...")
try:
    while True:
        device_id = f"EdgeCam_{random.randint(1, 5)}"
        message = generate_packet(device_id)
        client.publish(TOPIC, json.dumps(message))
        print("Published:", message)
        time.sleep(2)
except KeyboardInterrupt:
    print("Publisher stopped.")
    client.disconnect()
