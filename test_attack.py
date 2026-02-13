#!/usr/bin/env python3
"""
Test Script: Simulates a brute-force attack
This script sends multiple failed login attempts to test the threat detection system.
"""
import requests
import time
import random
API_URL = "http://localhost:8080/api/auth/login"
def simulate_attack(ip_address, num_attempts=10, delay=0.5):
    """
    Simulate brute-force attack from a specific IP.
    Args:
        ip_address: The IP to simulate (sent in X-Forwarded-For header)
        num_attempts: Number of login attempts
        delay: Delay between requests in seconds
    """
    print(f"🔥 Simulating attack from IP: {ip_address}")
    print(f"   Attempts: {num_attempts}, Delay: {delay}s")
    print("-" * 60)
    for i in range(1, num_attempts + 1):
        headers = {
            "X-Forwarded-For": ip_address,
            "Content-Type": "application/json"
        }
        payload = {
            "username": f"user{random.randint(1, 100)}",
            "password": "wrong_password"
        }
        try:
            response = requests.post(API_URL, json=payload, headers=headers)
            status = "✅" if response.status_code == 200 else "❌"
            print(f"{status} Attempt {i}: Status {response.status_code} - {response.json().get('message', 'N/A')}")
            # If blocked, stop
            if response.status_code == 403:
                print(f"\n🚫 IP {ip_address} has been BLOCKED!")
                break
        except Exception as e:
            print(f"❌ Request failed: {e}")
        time.sleep(delay)
    print("\n" + "=" * 60)
def test_normal_user():
    """Test with correct credentials."""
    print("\n✅ Testing legitimate user...")
    headers = {
        "X-Forwarded-For": "192.168.1.100",
        "Content-Type": "application/json"
    }
    payload = {
        "username": "admin",
        "password": "admin123"
    }
    response = requests.post(API_URL, json=payload, headers=headers)
    print(f"Response: {response.status_code} - {response.json()}")
if __name__ == "__main__":
    print("=" * 60)
    print("🧪 THREAT DETECTION SYSTEM - TEST SUITE")
    print("=" * 60)
    # Test 1: Simulate attack from attacker IP
    print("\n📍 TEST 1: Brute Force Attack Simulation")
    simulate_attack(ip_address="10.0.0.50", num_attempts=8, delay=0.5)
    # Wait a bit
    time.sleep(2)
    # Test 2: Verify block persists
    print("\n📍 TEST 2: Verify IP Block")
    simulate_attack(ip_address="10.0.0.50", num_attempts=1, delay=0)
    # Test 3: Different IP (legitimate user)
    test_normal_user()
    print("\n✅ Test suite completed!")
