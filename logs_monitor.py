#!/usr/bin/env python3
"""
The Logs monitor (Python Script)
Role: Kafka Consumer that analyzes login patterns and detects brute-force attacks.
Architecture: Part of "The Logs Monitor" - makes security decisions based on event streams.
"""
import json
import time
from datetime import datetime, timedelta
from collections import defaultdict
from kafka import KafkaConsumer
import psycopg2
from psycopg2.extras import RealDictCursor
import math
# Configuration
KAFKA_BROKER = 'localhost:9092'
KAFKA_TOPIC = 'auth-events'
KAFKA_GROUP_ID = 'threat-detection-tool'
DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'security_db',
    'user': 'admin',
    'password': 'password'
}
# Threat Detection Parameters
FAILURE_THRESHOLD = 5  # More than 5 failures
TIME_WINDOW_SECONDS = 60  # Within 60 seconds
BLOCK_DURATION_MINUTES = 15  # Block for 15 minutes
class ThreatDetectionEngine:
    """
    The Logs Monitor: Analyzes login patterns and blocks malicious IPs.
    Uses sliding window algorithm to detect brute-force attacks.
    """
    def __init__(self):
        # In-Memory Sliding Window: IP -> List of failure timestamps
        self.failed_attempts = defaultdict(list)
        # Track last successful login per username: { username: { ip, ts, lat, lon } }
        self.last_success_by_user = {}
        # Initialize Kafka Consumer
        self.consumer = KafkaConsumer(
            KAFKA_TOPIC,
            bootstrap_servers=KAFKA_BROKER,
            group_id=KAFKA_GROUP_ID,
            auto_offset_reset='latest',  # Start from latest messages
            enable_auto_commit=True,
            value_deserializer=lambda m: json.loads(m.decode('utf-8'))
        )
        # Database connection
        self.db_conn = None
        self.connect_to_db()
        print("Threat monitor initialized and listening...")
        print(f"   - Kafka Topic: {KAFKA_TOPIC}")
        print(f"   - Threshold: {FAILURE_THRESHOLD} failures in {TIME_WINDOW_SECONDS}s")
        print(f"   - Block Duration: {BLOCK_DURATION_MINUTES} minutes")
        print("-" * 60)
    def connect_to_db(self):
        """Establish PostgreSQL connection."""
        try:
            self.db_conn = psycopg2.connect(**DB_CONFIG)
            print("Connected to PostgreSQL")
        except Exception as e:
            print(f"Database connection failed: {e}")
            raise
    def process_events(self):
        """
        Main event processing loop.
        Listens to Kafka stream and analyzes patterns.
        """
        for message in self.consumer:
            try:
                event = message.value
                self.analyze_event(event)
            except Exception as e:
                print(f"Error processing event: {e}")
    def analyze_event(self, event):
        """
        Analyze a single login event using sliding window algorithm.
        Logic:
        1. Extract IP and status
        2. If FAILURE: Add to sliding window
        3. Clean old timestamps (outside 60s window)
        4. Check threshold (>5 failures)
        5. Block IP if threshold exceeded
        """
        ip = event.get('ip')
        status = event.get('status')
        timestamp = event.get('timestamp')
        username = event.get('username')
        # Optional geo fields if producers/enrichment provide them
        lat = event.get('lat')
        lon = event.get('lon')
        # Current wall time (seconds)
        now = time.time()
        print(f"📥 Event: {status} from {ip}")
        # Impossible-travel detection + Reset-on-success behavior
        if status == 'SUCCESS':
            # Impossible travel: if we have a previous successful login for the same username,
            # compute travel speed when geo is available; otherwise fall back to quick IP-switch check.
            if username:
                last = self.last_success_by_user.get(username)
                if last is not None:
                    dt = now - last.get('ts', now)
                    # If we have lat/lon for both events, compute haversine distance
                    if lat is not None and lon is not None and last.get('lat') is not None and last.get('lon') is not None:
                        def haversine_km(lat1, lon1, lat2, lon2):
                            # Haversine formula
                            R = 6371.0
                            phi1 = math.radians(lat1)
                            phi2 = math.radians(lat2)
                            dphi = math.radians(lat2 - lat1)
                            dlambda = math.radians(lon2 - lon1)
                            a = math.sin(dphi/2.0)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlambda/2.0)**2
                            c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
                            return R * c
                        distance_km = haversine_km(last['lat'], last['lon'], lat, lon)
                        hours = dt / 3600.0 if dt > 0 else 0.0
                        speed_kmh = float('inf') if hours == 0 else distance_km / hours
                        MAX_TRAVEL_SPEED_KMH = 500  # threshold; adjust per policy
                        if speed_kmh > MAX_TRAVEL_SPEED_KMH:
                            print(f"   IMPOSSIBLE TRAVEL detected for user '{username}': {distance_km:.1f} km in {dt:.1f}s (~{speed_kmh:.1f} km/h). Blocking IP {ip}.")
                            self.block_ip(ip)
                            # still update last-success and reset failure counters for IP
                    else:
                        # Fallback heuristic: different IPs within a short window -> suspicious
                        MIN_IP_SWITCH_SECONDS = 60  # if the same user logs in from two IPs within this window
                        if last.get('ip') and last.get('ip') != ip and dt < MIN_IP_SWITCH_SECONDS:
                            print(f"   QUICK IP SWITCH detected for user '{username}': {last.get('ip')} -> {ip} in {dt:.1f}s. Blocking IP {ip}.")
                            self.block_ip(ip)
            # Update last successful login for the user
            self.last_success_by_user[username] = {'ip': ip, 'ts': now, 'lat': lat, 'lon': lon}

            # Reset the sliding window for this IP (do not penalize a successful login)
            if ip in self.failed_attempts:
                del self.failed_attempts[ip]
                print(f"   {ip}: SUCCESS — reset failure counter")
            return

        # Only track failures from here onwards
        if status != 'FAILURE':
            return
        current_time = time.time()
        # Add current failure timestamp
        self.failed_attempts[ip].append(current_time)
        # SLIDING WINDOW CLEANUP: Remove timestamps older than TIME_WINDOW_SECONDS
        self.failed_attempts[ip] = [
            t for t in self.failed_attempts[ip] 
            if current_time - t < TIME_WINDOW_SECONDS
        ]
        failure_count = len(self.failed_attempts[ip])
        print(f"   {ip}: {failure_count} failures in last {TIME_WINDOW_SECONDS}s")
        # CHECK THRESHOLD
        if failure_count > FAILURE_THRESHOLD:
            print(f"  THREAT DETECTED! Blocking {ip}")
            self.block_ip(ip)
            # Clear memory for this IP to avoid re-blocking immediately
            del self.failed_attempts[ip]
    def block_ip(self, ip):
        """
        Block an IP by inserting/updating the database.
        Calculates blocked_until as NOW + BLOCK_DURATION_MINUTES.
        """
        try:
            cursor = self.db_conn.cursor()
            # Calculate expiry time
            blocked_until = datetime.now() + timedelta(minutes=BLOCK_DURATION_MINUTES)
            # Insert or update the block record
            cursor.execute("""
                INSERT INTO blocked_ips (ip_address, blocked_until, reason)
                VALUES (%s, %s, 'Brute Force Detected')
                ON CONFLICT (ip_address) 
                DO UPDATE SET 
                    blocked_until = EXCLUDED.blocked_until,
                    blocked_at = CURRENT_TIMESTAMP,
                    reason = EXCLUDED.reason;
            """, (ip, blocked_until))
            self.db_conn.commit()
            cursor.close()
            print(f"   BLOCKED {ip} until {blocked_until.strftime('%Y-%m-%d %H:%M:%S')}")
        except Exception as e:
            print(f"   Failed to block IP {ip}: {e}")
            self.db_conn.rollback()
    def cleanup(self):
        """Close connections gracefully."""
        if self.consumer:
            self.consumer.close()
        if self.db_conn:
            self.db_conn.close()
        print("\nLogs monitor shutdown complete")
def main():

    print("=" * 60)
    print("Logs monitor (analyzer)- Real-Time Threat Detection")
    print("=" * 60)
    engine = ThreatDetectionEngine()
    try:
        engine.process_events()
    except KeyboardInterrupt:
        print("\n  Shutdown signal received...")
    finally:
        engine.cleanup()
if __name__ == "__main__":
    main()
