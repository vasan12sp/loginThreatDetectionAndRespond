
# Real-Time Threat Detection and Response System

> Production-grade authentication security system with real-time ML anomaly detection, rule-based threat detection, and automated mitigation using Kafka, Spring Boot, Python, and PostgreSQL.

---

## System Overview

This project implements a real-time authentication security pipeline that detects and blocks malicious login attempts using both deterministic detection logic and machine learning–based behavioral anomaly detection.

The system uses an event-driven architecture powered by Apache Kafka to ensure scalability, low latency, and fault tolerance.

---

## Key Features

* Real-time brute force attack detection
* Machine learning anomaly detection using Isolation Forest
* Automatic malicious IP blocking
* Event-driven architecture using Apache Kafka
* Behavioral feature engineering for security analytics
* Fully asynchronous detection pipeline
* Horizontally scalable architecture
* Production-style threat detection and response

---

## Architecture Diagram

```
                        ┌──────────────────────┐
                        │        Client        │
                        └──────────┬───────────┘
                                   │
                                   ▼
                    ┌────────────────────────────┐
                    │ Spring Boot Auth Service   │
                    │                            │
                    │ • Authentication           │
                    │ • Enforcement              │
                    │ • Kafka Producer           │
                    └──────────┬──────────────── ┘
                               │
                               ▼
                      ┌───────────────────┐
                      │   Kafka Topic     │
                      │   "auth-events"   │
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
   └──────────────┬────────── ─┘     └──────────────┬─────────────┘
                  │                                 │
                  └──────────────┬──────────────── ─┘
                                 ▼
                      ┌────────────────────────┐
                      │     PostgreSQL         │
                      │     blocked_ips        │
                      └──────────┬───────────  ┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │  Auth Service enforces  │
                    │  Block (HTTP 403)       │
                    └─────────────────────────┘
```

---

## Event Flow Diagram

```
Login Attempt
     │
     ▼
Auth Service receives request
     │
     ├── Checks blocked_ips table
     │
     └── Publishes event → Kafka
                         │
                         ▼
                Detection Engines consume event
                         │
           ┌─────────────┴─────────────┐
           ▼                           ▼
    Rule-Based Detection        ML Detection
           │                           │
           └─────────────┬─────────────┘
                         ▼
                 Block malicious IP
                         │
                         ▼
                Auth Service enforces block
```

---

## Machine Learning Architecture

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
                Anomaly → Block IP
```

---

## Technology Stack

### Backend

* Java 17
* Spring Boot
* Spring Kafka

### Machine Learning

* Python 3
* scikit-learn
* Isolation Forest
* joblib

### Data Streaming

* Apache Kafka

### Database

* PostgreSQL

### Python Libraries

* kafka-python
* psycopg2
* scikit-learn
* joblib

---

## Detection Methods Implemented

### Rule-Based Detection

Sliding Window Brute Force Detection

```
Threshold: > 5 failed attempts within 60 seconds
```

Impossible Travel Detection

```
Detects geographically impossible login locations
```

Rapid IP Switching Detection

```
Detects proxy hopping and bot behavior
```

---

### Machine Learning Detection

Model Used:

```
Isolation Forest
```

Features Engineered:

```
failures_per_ip
attempt_count_ip
unique_users_per_ip
failure_rate
delta_t
hour_of_day
```

Detects:

* Unknown attacks
* Bot attacks
* Credential stuffing
* Account takeover behavior
* Behavioral anomalies

---

## Behavioral Feature Engineering

Example:

Normal user:

```
failures_per_ip = 1
failure_rate = 0.1
```

Attacker:

```
failures_per_ip = 50
failure_rate = 1.0
unique_users_per_ip = 20
```

ML model detects attacker as anomaly.

---

## Database Schema

```
CREATE TABLE blocked_ips (
    ip_address TEXT PRIMARY KEY,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    blocked_until TIMESTAMP NOT NULL,
    reason TEXT
);
```

---

## Event Format

```
{
  "ip": "192.168.1.10",
  "username": "admin",
  "status": "FAILURE",
  "timestamp": "2026-01-01T10:00:00Z"
}
```

---



## How to Run

### Start Kafka

```
localhost:9092
```

---

### Setup PostgreSQL

```
CREATE DATABASE security_db;
```

```
CREATE TABLE blocked_ips (
 ip_address TEXT PRIMARY KEY,
 blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
 blocked_until TIMESTAMP NOT NULL,
 reason TEXT
);
```

---

### Run Auth Service

```
mvn spring-boot:run
```

---

### Run Rule-Based Engine

```
python threat_monitor.py
```

---

### Run ML Detection Engine

```
python ml_threat_detection_engine.py
```

---

## Example Attack Simulation

```
curl -X POST http://localhost:8080/api/auth/login \
-H "Content-Type: application/json" \
-d '{"username":"admin","password":"wrong"}'
```

Result:

```
IP automatically blocked
Future requests return HTTP 403
```

---

## Scalability Model

```
Kafka
 ├── Detection Engine Instance 1
 ├── Detection Engine Instance 2
 ├── Detection Engine Instance 3
 └── Detection Engine Instance N
```

Horizontal scaling supported.

---

## Real-World Applications

* Identity Providers
* Banking Authentication Systems
* Enterprise Security Systems
* Cloud Authentication Platforms
* SOC Threat Detection Systems



