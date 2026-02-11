package com.vasan12sp.loginthreatdetection.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Model representing a login event that gets sent to Kafka.
 * This is the message format for "The Broker" (Kafka).
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginEvent {

    private String ip;
    private String status;  // "SUCCESS" or "FAILURE"
    private Instant timestamp;
    private String username;  // Optional, for additional context

    public LoginEvent(String ip, String status, Instant timestamp) {
        this.ip = ip;
        this.status = status;
        this.timestamp = timestamp;
    }
}
