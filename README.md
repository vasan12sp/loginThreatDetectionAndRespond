
# 🛡️ GateKeeper: Real-Time Threat Detection and Response

![Java](https://img.shields.io/badge/Java-17-orange)
![Spring Boot](https://img.shields.io/badge/Spring_Boot-3.0-green)
![Python](https://img.shields.io/badge/Python-3.9-blue)
![Apache Kafka](https://img.shields.io/badge/Apache_Kafka-Event_Streaming-black)
![Docker](https://img.shields.io/badge/Docker-Containerization-blue)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Database-blue)

> **A polyglot, event-driven security system that detects and blocks brute-force attacks in real-time without impacting user login latency.**

---

## 📖 Overview

**GateKeeper** allows web applications to offload heavy security analysis to a background process. Instead of blocking the user while performing complex threat detection (which increases latency), the API pushes login events to a high-throughput **Kafka** stream. A separate **Python Threat Monitor** analyzes these events in real-time and updates a shared **PostgreSQL** firewall table to block malicious actors instantly.

### 🚀 Key Features
* **Zero-Latency Security:** Decouples authentication logic from threat analysis using **Asynchronous Event Processing**.
* **Polyglot Microservices:** Combines the performance of **Java/Spring Boot** (API) with the analytical power of **Python** (Detection Engine).
* **Real-Time Enforcement:** Updates the blocklist instantly; the API enforces the block on the very next request.
* **Temporary Blocking (TTL):** Implements "Cooling-off" periods (e.g., 15 mins) using database timestamps, automatically lifting bans without manual intervention.
* **Fault Tolerance:** If the analysis engine crashes, user logins continue uninterrupted. Events are queued in Kafka for later processing.

---


### Data Flow

1. **The Gate (Java Producer):** Receives the login request. Checks the DB for an active block. If clear, it processes the login and **asynchronously** sends a `LOGIN_EVENT` to Kafka.
2. **The Pipe (Kafka):** Buffers the high-velocity log stream, handling spikes in traffic without crashing the database.
3. **The Detection Engine (Python Consumer):** Reads the stream. Uses a **Sliding Window Algorithm** to track failed logins per IP (e.g., >5 failures in 60s).
4. **The Lock (PostgreSQL):** Stores blocked IPs with an expiration time (`blocked_until`).

---

## 🛠️ Tech Stack

| Component | Technology | Description |
| --- | --- | --- |
| **API / Producer** | **Java 17 (Spring Boot)** | Handles HTTP requests, enforces blocks, produces Kafka events. |
| **Message Broker** | **Apache Kafka** | Decouples the API from the analysis engine. |
| **Analysis / Consumer** | **Python 3.9** | Runs the detection logic (Brute Force / Anomaly Detection). |
| **Database** | **PostgreSQL 14** | Shared source of truth for Blocked IPs. |
| **Infrastructure** | **Docker & Docker Compose** | Orchestrates the Kafka, Zookeeper, and DB containers. |

---

## ⚡ Getting Started

### Prerequisites

* Docker Desktop (Running)
* Java 17+ (JDK)
* Python 3.9+
* Maven

### 1. Start Infrastructure

Spin up Kafka, Zookeeper, and PostgreSQL containers.

```bash
docker-compose up -d

```

### 2. Start the API (The Guard)

```bash
./mvnw spring-boot:run

```

* The API will start on `http://localhost:8080`.

### 3. Start the Brain (The Detector)

Set up the Python environment and start the consumer.

```bash
cd brain
python3 -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows
pip install -r requirements.txt
python3 security_brain.py

```

---

## 🧪 How to Test (Attack Simulation)

1. **Legitimate Login:**
```bash
curl -X POST http://localhost:8080/api/login -d '{"ip": "192.168.1.5", "username": "user"}'

```


* *Result:* `200 OK` (Logged in).


2. **Brute Force Attack:**
   Run the included simulation script or fire requests rapidly:
```bash
# Send 6 failed login attempts rapidly
for i in {1..6}; do curl -X POST http://localhost:8080/api/login ... ; done

```


3. **Verify Block:**
   Check the Python console. You will see:
> `🚫 BLOCKING IP: 192.168.1.5 until 2026-02-12 10:15:00`


Try logging in again.
* *Result:* `403 Forbidden` (Access Denied: Temporarily Blocked).



---

## ⚙️ Configuration & Rules

You can tune the detection sensitivity in `security_brain.py`:

```python
# Sliding Window Configuration
FAILURE_THRESHOLD = 5       # Max failed attempts
WINDOW_SECONDS = 60         # Time window to count failures
BLOCK_DURATION_MIN = 15     # How long to block the IP (TTL)

```

---

## 📂 Project Structure

```bash
├── docker-compose.yml        # Infrastructure setup
├── init.sql                  # Database schema (creates blocked_ips table)
├── src/                      # Java Spring Boot Source Code
│   ├── controller/AuthController.java
│   ├── service/KafkaProducer.java
│   └── ...
├── brain/                    # Python Security Engine
│   ├── security_brain.py     # Main consumer script
│   └── requirements.txt      # Python dependencies
└── README.md

```

---

## 🔮 Future Improvements

*  **Discord Alerts:** Add a webhook to notify admins when an IP is blocked.
*  **Machine Learning:** Replace the static threshold with an Isolation Forest model for anomaly detection.


