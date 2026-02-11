-- Database Schema for Real-Time Threat Detection Pipeline
-- This table tracks blocked IPs with TTL (Time-To-Live) support

CREATE TABLE blocked_ips (
    ip_address VARCHAR(50) PRIMARY KEY,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    blocked_until TIMESTAMP NOT NULL,  -- The expiration time
    reason VARCHAR(255)
);

-- Index for faster lookups during login
CREATE INDEX idx_blocked_until ON blocked_ips(blocked_until);

-- Sample query to check if an IP is currently blocked:
-- SELECT COUNT(*) FROM blocked_ips WHERE ip_address = ? AND blocked_until > NOW();
