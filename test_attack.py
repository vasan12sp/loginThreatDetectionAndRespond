#!/usr/bin/env python3
"""
Test Script: Simulates brute-force attacks and tests session-based authentication.
Tests the full threat detection pipeline including session revocation.
"""
import requests
import time
import random

API_BASE = "http://localhost:8080/api/auth"
LOGIN_URL = f"{API_BASE}/login"
LOGOUT_URL = f"{API_BASE}/logout"
SESSION_URL = f"{API_BASE}/session-info"
HEALTH_URL = f"{API_BASE}/health"
REGISTER_URL = f"{API_BASE}/register"


def simulate_attack(ip_address, num_attempts=10, delay=0.5):
    """
    Simulate brute-force attack from a specific IP.
    Sends multiple failed login attempts to trigger threat detection.
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
            response = requests.post(LOGIN_URL, json=payload, headers=headers)
            status = "✅" if response.status_code == 200 else "❌"
            print(f"{status} Attempt {i}: Status {response.status_code} - {response.json().get('message', 'N/A')}")

            if response.status_code == 403:
                print(f"\n🚫 IP {ip_address} has been BLOCKED!")
                break
        except Exception as e:
            print(f"❌ Request failed: {e}")

        time.sleep(delay)

    print("\n" + "=" * 60)


def test_login_and_session():
    """Test login with valid credentials and verify session."""
    print("\n✅ Testing legitimate user login with session...")
    headers = {
        "X-Forwarded-For": "192.168.1.100",
        "Content-Type": "application/json"
    }
    payload = {
        "username": "admin",
        "password": "admin123"
    }

    # Use a session to preserve cookies
    session = requests.Session()

    # Login
    response = session.post(LOGIN_URL, json=payload, headers=headers)
    print(f"Login Response: {response.status_code} - {response.json()}")

    if response.status_code == 200:
        session_id = response.json().get("sessionId")
        print(f"   Session ID: {session_id}")

        # Verify session by hitting a protected endpoint
        session_info = session.get(SESSION_URL, headers=headers)
        print(f"Session Info: {session_info.status_code} - {session_info.json()}")

        # Logout
        logout_resp = session.post(LOGOUT_URL, headers=headers)
        print(f"Logout Response: {logout_resp.status_code} - {logout_resp.json()}")

        # Verify session is gone
        session_info_after = session.get(SESSION_URL, headers=headers)
        print(f"Session After Logout: {session_info_after.status_code}")

    return session


def test_session_revocation_on_block(attacker_ip="10.0.0.99"):
    """
    Test that an active session gets revoked when the IP is blocked.
    1. Login from attacker IP
    2. Simulate brute-force from same IP (triggers block)
    3. Verify that the session is now invalid
    """
    print("\n🔒 Testing session revocation on IP block...")
    headers = {
        "X-Forwarded-For": attacker_ip,
        "Content-Type": "application/json"
    }

    session = requests.Session()

    # Step 1: Login successfully first
    payload = {"username": "admin", "password": "admin123"}
    login_resp = session.post(LOGIN_URL, json=payload, headers=headers)
    print(f"Login from {attacker_ip}: {login_resp.status_code} - {login_resp.json().get('message')}")

    if login_resp.status_code != 200:
        print("   ⚠️ Could not login. Skipping revocation test.")
        return

    # Step 2: Verify session works
    session_info = session.get(SESSION_URL, headers=headers)
    print(f"Session active: {session_info.status_code} - authenticated={session_info.json().get('authenticated')}")

    # Step 3: Simulate attack from same IP (this should trigger a block after threshold)
    print(f"\n   Now simulating brute-force from same IP to trigger block...")
    for i in range(1, 10):
        attack_headers = {
            "X-Forwarded-For": attacker_ip,
            "Content-Type": "application/json"
        }
        attack_payload = {"username": f"victim{i}", "password": "wrong"}
        resp = requests.post(LOGIN_URL, json=attack_payload, headers=attack_headers)
        print(f"   Attack attempt {i}: {resp.status_code} - {resp.json().get('message')}")
        if resp.status_code == 403:
            print(f"   🚫 IP blocked!")
            break
        time.sleep(0.3)

    # Step 4: Wait a moment for monitors to process and block
    print("\n   Waiting for threat monitors to process events...")
    time.sleep(5)

    # Step 5: Try to use the original session (should be revoked)
    session_check = session.get(SESSION_URL, headers=headers)
    print(f"Session after block: {session_check.status_code}")
    if session_check.status_code == 403:
        print("   ✅ Session was successfully revoked after IP block!")
    else:
        print("   ⚠️ Session may still be active (monitor may not have blocked yet)")


def test_health():
    """Test health endpoint."""
    print("\n🏥 Health Check...")
    response = requests.get(HEALTH_URL)
    print(f"Health: {response.status_code} - {response.json()}")


if __name__ == "__main__":
    print("=" * 60)
    print("🧪 THREAT DETECTION SYSTEM - TEST SUITE")
    print("   Session-Based Authentication + Threat Detection")
    print("=" * 60)

    # Test 0: Health check
    test_health()

    # Test 1: Login and session management
    print("\n📍 TEST 1: Session-Based Login & Logout")
    test_login_and_session()

    time.sleep(1)

    # Test 2: Brute force attack simulation
    print("\n📍 TEST 2: Brute Force Attack Simulation")
    simulate_attack(ip_address="10.0.0.50", num_attempts=8, delay=0.5)

    time.sleep(2)

    # Test 3: Verify block persists
    print("\n📍 TEST 3: Verify IP Block")
    simulate_attack(ip_address="10.0.0.50", num_attempts=1, delay=0)

    # Test 4: Session revocation on block
    print("\n📍 TEST 4: Session Revocation on IP Block")
    test_session_revocation_on_block(attacker_ip="10.0.0.77")

    print("\n✅ Test suite completed!")
