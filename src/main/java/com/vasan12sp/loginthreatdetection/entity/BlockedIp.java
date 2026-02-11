package com.vasan12sp.loginthreatdetection.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;


@Entity
@Table(name = "blocked_ips")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class BlockedIp {

    @Id
    @Column(name = "ip_address", length = 50)
    private String ipAddress;

    @Column(name = "blocked_at")
    private LocalDateTime blockedAt;

    @Column(name = "blocked_until", nullable = false)
    private LocalDateTime blockedUntil;

    @Column(name = "reason")
    private String reason;

    public BlockedIp(String ipAddress, LocalDateTime blockedUntil, String reason) {
        this.ipAddress = ipAddress;
        this.blockedAt = LocalDateTime.now();
        this.blockedUntil = blockedUntil;
        this.reason = reason;
    }
}
