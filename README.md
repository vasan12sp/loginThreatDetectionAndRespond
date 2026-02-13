
# Real-Time Threat Detection and Response System

A production-style, event-driven authentication security system that detects and automatically mitigates brute-force attacks and suspicious login behavior in real time using Spring Boot, Kafka, Python, and PostgreSQL.

This project demonstrates modern security engineering practices including asynchronous event streaming, sliding-window threat detection, and automated response enforcement.

---

# Key Highlights

* Detects brute-force attacks in real time using sliding window analysis
* Automatically blocks malicious IPs without human intervention
* Event-driven architecture using Apache Kafka
* Low-latency authentication with asynchronous threat analysis
* Fully decoupled detection and enforcement pipeline
* Horizontally scalable security monitoring design

---

# Architecture Overview

```
Client
   │
   ▼
Spring Boot Auth Service
(Authentication + Enforcement)
   │
   ├── Checks blocked IPs (PostgreSQL)
   │
   └── Publishes login events
        │
        ▼
     Kafka Topic
     "auth-events"
        │
        ▼
Threat Detection Engine (Python)
   │
   ├── Sliding window brute-force detection
   ├── Impossible travel detection
   ├── Rapid IP switching detection
   │
   ▼
PostgreSQL blocked_ips table
   │
   ▼
Auth Service enforces block (403 response)
```

---

# System Components

## 1. Authentication Service (Spring Boot)

Responsibilities:

* Processes login requests
* Extracts client IP address
* Enforces blocked IP restrictions
* Publishes login events asynchronously to Kafka
* Returns authentication response with minimal latency

Endpoint:

```
POST /api/auth/login
```

Health check:

```
GET /api/auth/health
```

Example response:

```json
{
  "success": false,
  "message": "Access Denied: Temporarily Blocked",
  "ip": "192.168.1.10",
  "timestamp": 1700000000000
}
```

---

## 2. Event Streaming Layer (Apache Kafka)

Purpose:

Decouples authentication from threat detection.

Benefits:

* Non-blocking authentication flow
* High throughput event ingestion
* Fault tolerant and scalable

Event format:

```json
{
  "ip": "192.168.1.10",
  "status": "FAILURE",
  "timestamp": "2026-01-01T10:00:00Z",
  "username": "admin"
}
```

Topic:

```
auth-events
```

---

## 3. Threat Detection Engine (Python)

Consumes Kafka events and analyzes login patterns in real time.

Detection techniques implemented:

### Brute Force Detection

Detects excessive failed login attempts using sliding window algorithm.

Logic:

* Tracks failed attempts per IP
* Threshold: >5 failures within 60 seconds
* Automatically blocks IP

Time complexity:

```
O(n) per IP within time window
```

Memory efficient sliding window implementation.

---

### Impossible Travel Detection

Detects logins from geographically impossible locations within short time.

Uses:

* Haversine distance calculation
* Travel speed threshold validation

Detects:

* Credential compromise
* Account hijacking

---

### Rapid IP Switching Detection

Detects suspicious IP changes for same user within short duration.

Detects:

* Proxy hopping
* Bot activity
* Session abuse

---

## 4. Automated Threat Response

When a threat is detected:

* IP is inserted into PostgreSQL blocked_ips table
* Block duration automatically enforced
* Future login attempts rejected immediately

Database schema:

```sql
CREATE TABLE blocked_ips (
    ip_address TEXT PRIMARY KEY,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    blocked_until TIMESTAMP NOT NULL,
    reason TEXT
);
```

---

# Technology Stack

Backend:

* Java 17
* Spring Boot
* Spring Kafka

Threat Detection:

* Python 3
* kafka-python
* psycopg2

Data Layer:

* PostgreSQL

Event Streaming:

* Apache Kafka

Serialization:

* Jackson

---

# Key Engineering Concepts Demonstrated

Event-Driven Architecture
Asynchronous Processing
Distributed Systems Design
Security Threat Detection
Sliding Window Algorithms
Automated Threat Response
Microservice Decoupling
Kafka Event Streaming
Real-Time Data Processing

---

# Performance Characteristics

Authentication latency:

```
5–20 ms
```

Threat detection latency:

```
< 500 ms
```

System scalability:

```
Supports horizontal scaling via Kafka partitioning
```

Authentication service remains fast even under attack due to async design.

---

# Security Design Pattern

This system follows industry standard Threat Detection and Response (TDR) architecture:

Detection Layer:

* Event analysis
* Behavior monitoring

Response Layer:

* Automated mitigation
* Real-time enforcement

This architecture is used in:

* Banking systems
* Identity providers
* Cloud authentication platforms
* Enterprise security systems

---

# How to Run

## Start Kafka

Ensure Kafka is running on:

```
localhost:9092
```

---

## Setup PostgreSQL

Create database:

```sql
CREATE DATABASE security_db;
```

Create table:

```sql
CREATE TABLE blocked_ips (
    ip_address TEXT PRIMARY KEY,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    blocked_until TIMESTAMP NOT NULL,
    reason TEXT
);
```

---

## Run Spring Boot Auth Service

```bash
mvn spring-boot:run
```

Runs on:

```
http://localhost:8080
```

---

## Run Threat Detection Engine

Install dependencies:

```bash
pip install kafka-python psycopg2-binary
```

Run:

```bash
python threat_monitor.py
```

---

# Example Attack Simulation

Send multiple failed login attempts:

```bash
curl -X POST http://localhost:8080/api/auth/login \
-H "Content-Type: application/json" \
-d '{"username":"admin","password":"wrong"}'
```

Result:

* Threat detection engine detects brute force
* IP automatically blocked
* Future requests receive HTTP 403

---

# Scalability Design

This system supports horizontal scaling:

* Kafka partitions allow multiple detection consumers
* Authentication service remains stateless
* Detection engine can scale independently
* Database acts as enforcement source of truth

---

# Real-World Applications

* Authentication systems
* Enterprise identity providers
* API security platforms
* Banking login protection
* SOC threat monitoring systems



