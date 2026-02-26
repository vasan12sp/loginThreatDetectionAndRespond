package com.vasan12sp.loginthreatdetection.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;


@Entity
@Table(name = "user_sessions")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserSession {

    @Id
    @Column(name = "session_id", length = 255)
    private String sessionId;

    @Column(name = "username", nullable = false, length = 100)
    private String username;

    @Column(name = "ip_address", nullable = false, length = 50)
    private String ipAddress;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    public UserSession(String sessionId, String username, String ipAddress) {
        this.sessionId = sessionId;
        this.username = username;
        this.ipAddress = ipAddress;
        this.createdAt = LocalDateTime.now();
    }
}
