#!/usr/bin/env python3
"""
ML Threat Detection Engine
Role: Kafka Consumer that uses Isolation Forest ML model to detect anomalous login behavior.
Blocks malicious IPs automatically.

Architecture:
Kafka → Feature Engineering → ML Model → Block IP (PostgreSQL)
"""

import json
import time
import joblib
from datetime import datetime, timedelta
from collections import defaultdict

from kafka import KafkaConsumer
import psycopg2


# =============================
# Configuration
# =============================

KAFKA_BROKER = 'localhost:9092'
KAFKA_TOPIC = 'auth-events'
KAFKA_GROUP_ID = 'ml-threat-detection'

MODEL_PATH = "anomaly_model.pkl"

DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'security_db',
    'user': 'admin',
    'password': 'password'
}

BLOCK_DURATION_MINUTES = 30


# =============================
# ML Threat Detection Engine
# =============================

class MLThreatDetectionEngine:

    def __init__(self):

        # Load trained ML model
        print("Loading ML model...")


        self.model = joblib.load(MODEL_PATH)


        print("✅ ML model loaded")

        # Kafka Consumer
        self.consumer = KafkaConsumer(
            KAFKA_TOPIC,
            bootstrap_servers=KAFKA_BROKER,
            group_id=KAFKA_GROUP_ID,
            auto_offset_reset='latest',
            enable_auto_commit=True,
            value_deserializer=lambda m: json.loads(m.decode('utf-8'))
        )

        # PostgreSQL connection
        self.db_conn = None
        self.connect_to_db()

        # In-memory state for feature engineering
        self.ip_state = defaultdict(lambda: {
            "failures": 0,
            "attempts": 0,
            "users": set(),
            "last_timestamp": None
        })

        print("ML Threat Detection Engine started")
        print(f"Kafka Topic: {KAFKA_TOPIC}")
        print(f"Block duration: {BLOCK_DURATION_MINUTES} minutes")
        print("-" * 60)


    # =============================
    # Database Connection
    # =============================

    def connect_to_db(self):

        try:
            self.db_conn = psycopg2.connect(**DB_CONFIG)
            print("✅ Connected to PostgreSQL")

        except Exception as e:
            print("❌ DB connection failed:", e)
            raise


    # =============================
    # Feature Engineering
    # =============================

    def extract_features(self, event):

        ip = event.get("ip")
        username = event.get("username")
        status = event.get("status")
        timestamp = event.get("timestamp")

        if not ip:
            return None

        state = self.ip_state[ip]

        now = time.time()

        # delta_t calculation
        if state["last_timestamp"] is None:
            delta_t = 0
        else:
            delta_t = now - state["last_timestamp"]

        state["last_timestamp"] = now

        # Update attempts
        state["attempts"] += 1

        # Update failures
        if status == "FAILURE":
            state["failures"] += 1

        # Update unique users
        if username:
            state["users"].add(username)

        failures_per_ip = state["failures"]
        attempt_count_ip = state["attempts"]
        unique_users_per_ip = len(state["users"])

        failure_rate = failures_per_ip / attempt_count_ip

        hour = datetime.now().hour

        features = [
            failures_per_ip,
            attempt_count_ip,
            unique_users_per_ip,
            failure_rate,
            delta_t,
            hour
        ]

        return features


    # =============================
    # ML Prediction
    # =============================

    def analyze_event(self, event):

        ip = event.get("ip")
        status = event.get("status")

        print(f"Event: {status} from {ip}")

        features = self.extract_features(event)

        if features is None:
            return

        prediction = self.model.predict([features])[0]

        if prediction == -1:

            print(f"🚨 ML ANOMALY DETECTED from {ip}")
            print(f"   Features: {features}")

            self.block_ip(ip)

        else:
            print(f"Normal behavior from {ip}")


    # =============================
    # Block IP
    # =============================

    def block_ip(self, ip):

        try:

            cursor = self.db_conn.cursor()

            blocked_until = datetime.now() + timedelta(
                minutes=BLOCK_DURATION_MINUTES
            )

            cursor.execute("""
                           INSERT INTO blocked_ips (ip_address, blocked_until, reason)
                           VALUES (%s, %s, 'ML Anomaly Detected')
                               ON CONFLICT (ip_address)
                DO UPDATE SET
                               blocked_until = EXCLUDED.blocked_until,
                                                      blocked_at = CURRENT_TIMESTAMP,
                                                      reason = EXCLUDED.reason;
                           """, (ip, blocked_until))

            # Revoke all active sessions for this IP
            self.revoke_sessions_for_ip(cursor, ip)

            self.db_conn.commit()
            cursor.close()

            print(f"🚫 BLOCKED {ip} until {blocked_until}")

        except Exception as e:

            print("❌ Failed to block IP:", e)
            self.db_conn.rollback()


    def revoke_sessions_for_ip(self, cursor, ip):
        """
        Revoke all active sessions for a blocked IP.
        Deletes from both SPRING_SESSION and user_sessions tables.
        """
        try:
            # Find all session IDs for this IP
            cursor.execute(
                "SELECT session_id FROM user_sessions WHERE ip_address = %s", (ip,)
            )
            sessions = cursor.fetchall()

            if sessions:
                session_ids = [s[0] for s in sessions]
                print(f"   🔒 Revoking {len(session_ids)} session(s) for IP {ip}")

                # Delete from Spring Session table
                for sid in session_ids:
                    cursor.execute(
                        "DELETE FROM SPRING_SESSION WHERE SESSION_ID = %s", (sid,)
                    )

                # Delete from user_sessions tracking table
                cursor.execute(
                    "DELETE FROM user_sessions WHERE ip_address = %s", (ip,)
                )
                print(f"   ✅ Sessions revoked for IP {ip}")
            else:
                print(f"   ℹ️ No active sessions found for IP {ip}")
        except Exception as e:
            print(f"   ⚠️ Failed to revoke sessions for IP {ip}: {e}")


    # =============================
    # Main Loop
    # =============================

    def process_events(self):

        for message in self.consumer:

            try:

                event = message.value

                self.analyze_event(event)

            except Exception as e:

                print("Error processing event:", e)


    # =============================
    # Cleanup
    # =============================

    def cleanup(self):

        if self.consumer:
            self.consumer.close()

        if self.db_conn:
            self.db_conn.close()

        print("Shutdown complete")


# =============================
# Main
# =============================

def main():

    print("=" * 60)
    print("ML Threat Detection Engine Started")
    print("=" * 60)

    engine = MLThreatDetectionEngine()

    try:

        engine.process_events()

    except KeyboardInterrupt:

        print("Shutdown signal received")

    finally:

        engine.cleanup()


if __name__ == "__main__":
    main()
