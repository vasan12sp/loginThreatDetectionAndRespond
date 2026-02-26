package com.vasan12sp.loginthreatdetection.service;

import com.vasan12sp.loginthreatdetection.entity.UserSession;
import com.vasan12sp.loginthreatdetection.repository.UserSessionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;


/**
 * Service responsible for managing and revoking user sessions.
 * Works alongside the Python threat monitors to invalidate sessions
 * when an IP is blocked.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SessionRevocationService {

    private final UserSessionRepository userSessionRepository;
    private final JdbcTemplate jdbcTemplate;

    /**
     * Register a new session when a user successfully logs in.
     */
    public void registerSession(String sessionId, String username, String ipAddress) {
        UserSession session = new UserSession(sessionId, username, ipAddress);
        userSessionRepository.save(session);
        log.info("Session registered: {} for user: {} from IP: {}", sessionId, username, ipAddress);
    }

    /**
     * Remove a session record (on logout or invalidation).
     */
    public void removeSession(String sessionId) {
        userSessionRepository.deleteById(sessionId);
        log.info("Session removed: {}", sessionId);
    }

    /**
     * Revoke ALL sessions associated with a given IP address.
     * This is called when an IP is blocked by the threat detection system.
     * It deletes from both user_sessions and SPRING_SESSION tables.
     */
    @Transactional
    public void revokeSessionsByIp(String ipAddress) {
        List<UserSession> sessions = userSessionRepository.findByIpAddress(ipAddress);

        if (sessions.isEmpty()) {
            log.info("No active sessions found for IP: {}", ipAddress);
            return;
        }

        for (UserSession session : sessions) {
            // Delete from Spring Session JDBC table
            jdbcTemplate.update(
                "DELETE FROM SPRING_SESSION WHERE SESSION_ID = ?",
                session.getSessionId()
            );
            log.info("Revoked Spring Session: {} for user: {} from IP: {}",
                    session.getSessionId(), session.getUsername(), ipAddress);
        }

        // Delete from user_sessions tracking table
        userSessionRepository.deleteByIpAddress(ipAddress);
        log.info("All sessions revoked for IP: {} (count: {})", ipAddress, sessions.size());
    }

    /**
     * Revoke all sessions for a specific username.
     */
    @Transactional
    public void revokeSessionsByUsername(String username) {
        List<UserSession> sessions = userSessionRepository.findByUsername(username);

        for (UserSession session : sessions) {
            jdbcTemplate.update(
                "DELETE FROM SPRING_SESSION WHERE SESSION_ID = ?",
                session.getSessionId()
            );
        }

        userSessionRepository.deleteByUsername(username);
        log.info("All sessions revoked for user: {} (count: {})", username, sessions.size());
    }
}
