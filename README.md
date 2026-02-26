# 🛡️ Real-Time Threat Detection and Response System

> A production-grade, event-driven authentication security system with session-based authentication, real-time ML anomaly detection, automatic session revocation, and automated IP blocking using Kafka, Spring Boot, Spring Security, Python, and PostgreSQL.

![Java](https://img.shields.io/badge/Java-17-orange?style=flat-square&logo=openjdk)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-4.0.2-brightgreen?style=flat-square&logo=springboot)
![Spring Security](https://img.shields.io/badge/Spring%20Security-Session%20Based-brightgreen?style=flat-square&logo=springsecurity)
![Python](https://img.shields.io/badge/Python-3-blue?style=flat-square&logo=python)
![Kafka](https://img.shields.io/badge/Apache%20Kafka-Streaming-black?style=flat-square&logo=apachekafka)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Database-blue?style=flat-square&logo=postgresql)
![Machine Learning](https://img.shields.io/badge/ML-Isolation%20Forest-yellow?style=flat-square&logo=scikitlearn)
![Architecture](https://img.shields.io/badge/Architecture-Event%20Driven-purple?style=flat-square)
![Status](https://img.shields.io/badge/Status-Production%20Ready-success?style=flat-square)

---

## 📖 Overview

This project implements a real-time authentication threat detection and response system capable of identifying and blocking malicious login attempts using both:

- **Deterministic rule-based detection**
- **Machine learning anomaly detection**

The system uses an **event-driven architecture** powered by Apache Kafka, enabling scalable, asynchronous, and fault-tolerant security monitoring.

Authentication is handled via **Spring Security with session-based authentication**, where sessions are persisted in PostgreSQL using **Spring Session JDBC**. When a threat is detected, the system not only blocks the IP but also **immediately revokes all active sessions** associated with that IP — from both the Python detection engines (proactive) and the Java filter layer (reactive).

It automatically detects attacks such as:

- 🔐 Brute force attacks
- 🤖 Bot attacks
- 📋 Credential stuffing
- 🧠 Behavioral anomalies
- 🎭 Account takeover attempts

and enforces automated mitigation by blocking malicious IP addresses and **revoking their sessions immediately** after detection.

---

## ✨ Key Features

- 🔑 **Session-based authentication** with Spring Security + Spring Session JDBC
- 🔄 **Automatic session revocation** when an IP is blocked by threat detection
- 🛑 **Two-layer revocation** — proactive (Python DB delete) + reactive (Java filter)
- 🚨 Real-time brute force attack detection
- 🧠 Machine learning anomaly detection using Isolation Forest
- 🚫 Automatic malicious IP blocking
- 📡 Event-driven architecture using Apache Kafka
- 📊 Behavioral feature engineering for security analytics
- ⚡ Fully asynchronous detection pipeline
- 📈 Horizontally scalable detection engines
- 🔒 BCrypt password hashing for secure credential storage
- 🗄️ Database-backed sessions for cross-service session revocation
- 🏗️ Production-grade distributed system design

---

## 🏗️ System Architecture

```
                        ┌──────────────────────┐
                        │       Client         │
                        │   (SESSIONID cookie) │
                        └──────────┬───────────┘
                                   │
                                   ▼
                    ┌────────────────────────────┐
                    │  Spring Boot Auth Service  │
                    │                            │
                    │ • BlockedIpSessionFilter   │
                    │ • Spring Security Auth     │
                    │ • Session Management       │
                    │ • Kafka Event Producer     │
                    │ • IP Block Enforcement     │
                    └──────────┬─────────────────┘
                               │
                               ▼
                      ┌───────────────────┐
                      │   Kafka Topic     │
                      │  "auth-events"    │
                      └─────────┬─────────┘
                                │
              ┌─────────────────┴─────────────────┐
              │                                   │
              ▼                                   ▼
   ┌───────────────────────────┐     ┌────────────────────────────┐
   │ Rule-Based Detection      │     │ ML Anomaly Detection       │
   │ Engine (Python)           │     │ Engine (Python)            │
   │                           │     │                            │
   │ • Sliding Window          │     │ • Feature Engineering      │
   │ • Impossible Travel       │     │ • Isolation Forest Model   │
   │ • Rapid IP Switching      │     │ • Behavioral Analysis      │
   └──────────────┬────────────┘     └──────────────┬─────────────┘
                  │                                 │
                  └──────────────┬──────────────────┘
                                 ▼
                      ┌────────────────────────┐
                      │      PostgreSQL        │
                      │                        │
                      │ • blocked_ips          │
                      │ • users                │
                      │ • user_sessions        │
                      │ • SPRING_SESSION       │
                      └──────────┬─────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │  Auth Service enforces  │
                    │  Block + Revokes Session│
                    │  (HTTP 403)             │
                    └─────────────────────────┘
```

---

## ⚙️ Architecture Explanation

### Authentication Service (Spring Boot)

**Responsibilities:**

- Processes login requests via REST API
- Authenticates users with **Spring Security** (BCrypt password verification)
- Creates and manages **HTTP sessions** (stored in PostgreSQL via Spring Session JDBC)
- Tracks sessions in `user_sessions` table (links session → IP address)
- Publishes authentication events to Kafka
- Checks `blocked_ips` database on every request via `BlockedIpSessionFilter`
- Enforces IP blocking (HTTP 403) and **invalidates sessions mid-request**

**Acts as:** Event Producer · Authentication Layer · Session Manager · Enforcement Layer

---

### Apache Kafka (Event Streaming Layer)

**Provides:**

- Real-time event streaming
- Asynchronous processing
- Fault tolerance
- Horizontal scalability

**Topic used:**

```
auth-events
```

---

### Rule-Based Detection Engine (Python)

Detects known attack patterns using deterministic logic:

- 🔨 Brute force attacks (sliding window)
- 🌍 Impossible travel detection (haversine distance)
- 🔀 Rapid IP switching detection

**On threat detection:** Blocks IP → **Revokes all sessions for that IP from the database**

---

### Machine Learning Detection Engine (Python)

**Model used:** `Isolation Forest`

**Detects:**

- Unknown attack patterns
- Behavioral anomalies
- Credential stuffing
- Bot-driven authentication attempts
- Account takeover behavior

**On threat detection:** Blocks IP → **Revokes all sessions for that IP from the database**

---

### PostgreSQL Database

**Stores:**

| Table | Purpose |
|-------|---------|
| `blocked_ips` | Blocked IPs with TTL (time-to-live) |
| `users` | User credentials (BCrypt hashed passwords) |
| `user_sessions` | Session-to-IP mapping (bridge for revocation) |
| `SPRING_SESSION` | Actual HTTP session data (Spring Session JDBC) |
| `SPRING_SESSION_ATTRIBUTES` | Serialized session attributes |

**Acts as:** Central mitigation store · Session store · Shared enforcement database

---

## 🔄 Event Flow

```
Login Attempt
     │
     ▼
Auth Service receives request
     │
     ├── 1. BlockedIpSessionFilter checks blocked_ips table
     │      └── If blocked → Invalidate session → Clear SecurityContext → Return 403
     │
     ├── 2. Spring Security authenticates (BCrypt against users table)
     │      └── On success → Create HTTP session → Store in SPRING_SESSION
     │                      → Register in user_sessions (session_id ↔ ip_address)
     │
     ├── 3. Publishes LoginEvent → Kafka ("auth-events" topic)
     │
     ▼
Detection Engines consume event
     │
     ├── Rule-Based Engine: Sliding window, impossible travel, IP switching
     └── ML Engine: Isolation Forest prediction
            │
            ▼
     Threat Detected → block_ip():
            │
            ├── INSERT INTO blocked_ips
            ├── SELECT session_id FROM user_sessions WHERE ip_address = blocked_ip
            ├── DELETE FROM SPRING_SESSION WHERE SESSION_ID = <each session>  ← Session killed
            └── DELETE FROM user_sessions WHERE ip_address = blocked_ip
            │
            ▼
     Next request from blocked IP:
            │
            └── BlockedIpSessionFilter catches it → 403
```

---

## 🔒 Session Revocation Architecture

The system implements **two-layer session revocation** to ensure no blocked IP retains an active session:

### Layer 1: Proactive Revocation (Python → Database)

When a Python detection engine blocks an IP, it **directly deletes the session from PostgreSQL** in the same transaction:

```python
# Inside block_ip() — both logs_monitor.py and ml_anomaly_detection.py
def revoke_sessions_for_ip(self, cursor, ip):
    cursor.execute("SELECT session_id FROM user_sessions WHERE ip_address = %s", (ip,))
    sessions = cursor.fetchall()
    for sid in [s[0] for s in sessions]:
        cursor.execute("DELETE FROM SPRING_SESSION WHERE SESSION_ID = %s", (sid,))
    cursor.execute("DELETE FROM user_sessions WHERE ip_address = %s", (ip,))
```

✅ **Immediate** — session is gone from the DB before the next request arrives.

### Layer 2: Reactive Enforcement (Java Filter → Every Request)

The `BlockedIpSessionFilter` runs **before** Spring Security's authentication filter on every request:

```java
// BlockedIpSessionFilter.java
if (blockedIpRepository.isIpBlocked(ip)) {
    session.invalidate();                         // Kill in-memory session
    sessionRevocationService.removeSession(sid);  // Clean user_sessions
    SecurityContextHolder.clearContext();          // Wipe auth context
    return 403;                                   // Block the request
}
```

✅ **Safety net** — catches edge cases where Python-side revocation didn't cover a session.

### Why Two Layers?

| Layer | When it runs | What it does |
|-------|-------------|--------------|
| **Python (proactive)** | At the moment of IP block | Deletes session rows from DB |
| **Java filter (reactive)** | On every incoming HTTP request | Invalidates session + returns 403 |

Python can't reach into JVM memory. Java doesn't know about a block until a request comes in. **Both are needed** for bulletproof revocation.

---

### The Bridge: `user_sessions` Table

Spring's `SPRING_SESSION` table has **no `ip_address` column**. So when Python needs to revoke sessions for a blocked IP, it needs a way to find which sessions belong to that IP.

The `user_sessions` table serves as this **IP-to-session lookup index**:

```
Java (on login):  INSERT INTO user_sessions (session_id, username, ip_address)
Python (on block): SELECT session_id FROM user_sessions WHERE ip_address = ?
                   → DELETE FROM SPRING_SESSION WHERE SESSION_ID = ?
                   → DELETE FROM user_sessions WHERE ip_address = ?
```

---

## 🧠 Machine Learning Architecture

```
Historical Login Logs
         │
         ▼
Feature Engineering
         │
         ▼
Isolation Forest Training
         │
         ▼
anomaly_model.pkl
         │
         ▼
Real-Time Kafka Events
         │
         ▼
Feature Engineering
         │
         ▼
Isolation Forest Prediction
         │
         ▼
Anomaly → Block IP + Revoke Sessions
```

---

### 📊 Engineered Features

| Feature | Purpose |
|---------|---------|
| `failures_per_ip` | Detect brute force |
| `attempt_count_ip` | Identify excessive requests |
| `unique_users_per_ip` | Detect credential stuffing |
| `failure_rate` | Behavioral anomaly |
| `delta_t` | Request frequency |
| `hour_of_day` | Temporal anomaly |

### Behavioral Feature Engineering

**Normal user:**

```
failures_per_ip = 1
failure_rate = 0.1
```

**Attacker:**

```
failures_per_ip = 50
failure_rate = 1.0
unique_users_per_ip = 20
```

ML model detects attacker as anomaly.

---

## 🚨 Detection Methods

### Rule-Based Detection

- **Sliding window brute force detection** — `> 5 failed attempts in 60 seconds`
- **Impossible travel detection** — Haversine distance / speed check between logins
- **Rapid IP switching detection** — Same user, different IPs within short window

### Machine Learning Detection

**Model:** `Isolation Forest`

**Detects:**

- Unknown attack patterns
- Behavioral anomalies
- Credential stuffing attacks
- Bot-driven authentication attempts
- Account takeover behavior

---

## 🗄️ Database Schema

```sql
-- Blocked IPs with TTL
CREATE TABLE blocked_ips (
    ip_address VARCHAR(50) PRIMARY KEY,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    blocked_until TIMESTAMP NOT NULL,
    reason VARCHAR(255)
);

-- Users with BCrypt hashed passwords
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,       -- BCrypt hashed
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Session tracking (bridge: session_id ↔ ip_address for revocation)
CREATE TABLE user_sessions (
    session_id VARCHAR(255) PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    ip_address VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Spring Session JDBC tables (actual session storage)
-- SPRING_SESSION          — session metadata
-- SPRING_SESSION_ATTRIBUTES — serialized session data (SecurityContext, etc.)
```

---

## 🧱 Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Spring Boot 4.0.2 |
| Language | Java 17 |
| Authentication | Spring Security (Session-Based) |
| Session Store | Spring Session JDBC (PostgreSQL) |
| Detection Engines | Python 3 |
| Machine Learning | scikit-learn (Isolation Forest) |
| Streaming Platform | Apache Kafka |
| Database | PostgreSQL |
| Password Hashing | BCrypt |
| Event Format | JSON via Kafka |

---

## 📡 Kafka Event Format

```json
{
  "ip": "192.168.1.10",
  "username": "admin",
  "status": "FAILURE",
  "timestamp": "2026-01-01T10:00:00Z"
}
```

---

## 🚀 Installation and Setup

### Prerequisites

- Java 17+
- Python 3
- Apache Kafka
- PostgreSQL
- Maven

---

### Start Infrastructure (Docker Compose)

```bash
docker-compose up -d
```

This starts **Kafka**, **Zookeeper**, and **PostgreSQL** with the schema auto-initialized from `init.sql`.

---

### Setup Database (Manual)

```sql
CREATE DATABASE security_db;
```

```bash
psql -U admin -d security_db -f init.sql
```

---

### Run Authentication Service

```bash
mvn spring-boot:run
```

---

### Run Rule-Based Detection Engine

```bash
python logs_monitor.py
```

---

### Run ML Detection Engine

```bash
python ml_anomaly_detection.py
```

---

## 📡 API Endpoints

| Method | Endpoint | Auth Required | Description |
|--------|----------|---------------|-------------|
| `POST` | `/api/auth/login` | ❌ | Authenticate and create session |
| `POST` | `/api/auth/logout` | ✅ | Invalidate session and logout |
| `POST` | `/api/auth/register` | ❌ | Register a new user |
| `GET` | `/api/auth/health` | ❌ | Health check |
| `GET` | `/api/auth/session-info` | ✅ | Get current session and user info |

---

## 🧪 Example Usage

### Register a new user

```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"securepass123"}'
```

### Login (creates session)

```bash
curl -c cookies.txt -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

### Check session

```bash
curl -b cookies.txt http://localhost:8080/api/auth/session-info
```

### Logout

```bash
curl -b cookies.txt -X POST http://localhost:8080/api/auth/logout
```

---

## 🧪 Attack Simulation

```bash
# Send multiple failed login attempts to trigger brute force detection
for i in {1..8}; do
  curl -X POST http://localhost:8080/api/auth/login \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 10.0.0.50" \
    -d '{"username":"admin","password":"wrong"}'
  sleep 0.5
done
```

**Result:**

```
✅ IP 10.0.0.50 automatically blocked after threshold exceeded
✅ All active sessions from IP 10.0.0.50 are revoked from database
✅ Future requests from IP 10.0.0.50 return HTTP 403
```

Or run the full test suite:

```bash
python test_attack.py
```

---

## 📈 Scalability Architecture

```
Kafka
 ├── Detection Engine Instance 1
 ├── Detection Engine Instance 2
 ├── Detection Engine Instance 3
 └── Detection Engine Instance N
```

Kafka enables **horizontal scaling** of detection engines. Each instance joins the consumer group and processes a partition of events independently.

---

## 📌 Real-World Applications

- 🏦 Banking authentication systems
- 🔐 Identity providers
- 🏢 Enterprise security platforms
- ☁️ Cloud authentication systems
- 🛡️ Security Operations Centers (SOC)
- 🚫 Zero Trust security systems

---

## 🔮 Future Enhancements

- 📊 Real-time dashboard visualization
- ☸️ Kubernetes deployment
- ⚡ Redis caching layer for blocked IPs
- 🔄 Online model retraining pipeline
- 🧠 Advanced behavioral modeling
- 🔗 Integration with SIEM systems
- 🌐 GeoIP enrichment for login events

---

## 👨‍💻 Author

**Vasan S P**

GitHub: [https://github.com/vasan12sp](https://github.com/vasan12sp)

---

## 📄 License

MIT License
