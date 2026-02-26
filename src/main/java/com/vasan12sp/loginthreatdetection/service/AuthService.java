package com.vasan12sp.loginthreatdetection.service;

import com.vasan12sp.loginthreatdetection.model.LoginEvent;
import com.vasan12sp.loginthreatdetection.model.LoginRequest;
import com.vasan12sp.loginthreatdetection.repository.BlockedIpRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.time.Instant;


@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final BlockedIpRepository blockedIpRepository;
    private final KafkaProducerService kafkaProducerService;
    private final AuthenticationManager authenticationManager;
    private final SessionRevocationService sessionRevocationService;


    public LoginResponse processLogin(LoginRequest request, String userIp, HttpServletRequest httpRequest) {
        log.info("Processing login for user: {} from IP: {}", request.getUsername(), userIp);

        // STEP 1: Check Block Status (Enforcement)
        if (blockedIpRepository.isIpBlocked(userIp)) {
            log.warn("Login attempt from blocked IP: {}", userIp);
            // Emit FAILURE event for blocked IPs too
            LoginEvent event = new LoginEvent(userIp, "FAILURE", Instant.now(), request.getUsername());
            kafkaProducerService.sendLoginEvent(event);
            return new LoginResponse(false, "Access Denied: Your IP is temporarily blocked", 403, null);
        }

        // STEP 2: Authenticate using Spring Security
        try {
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    request.getUsername(),
                    request.getPassword()
                )
            );

            // STEP 3: Create session and set security context
            SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
            securityContext.setAuthentication(authentication);
            SecurityContextHolder.setContext(securityContext);

            HttpSession session = httpRequest.getSession(true);
            session.setAttribute("SPRING_SECURITY_CONTEXT", securityContext);

            String sessionId = session.getId();
            log.info("Session created: {} for user: {}", sessionId, request.getUsername());

            // STEP 4: Register session for IP-based revocation tracking
            sessionRevocationService.registerSession(sessionId, request.getUsername(), userIp);

            // STEP 5: Emit SUCCESS event to Kafka
            LoginEvent event = new LoginEvent(userIp, "SUCCESS", Instant.now(), request.getUsername());
            kafkaProducerService.sendLoginEvent(event);

            return new LoginResponse(true, "Login successful", 200, sessionId);

        } catch (BadCredentialsException e) {
            log.warn("Authentication failed for user: {} from IP: {}", request.getUsername(), userIp);

            // Emit FAILURE event to Kafka (triggers threat detection)
            LoginEvent event = new LoginEvent(userIp, "FAILURE", Instant.now(), request.getUsername());
            kafkaProducerService.sendLoginEvent(event);

            return new LoginResponse(false, "Invalid credentials", 401, null);
        }
    }


    public void processLogout(HttpServletRequest httpRequest) {
        HttpSession session = httpRequest.getSession(false);
        if (session != null) {
            String sessionId = session.getId();
            session.invalidate();
            sessionRevocationService.removeSession(sessionId);
            log.info("User logged out, session invalidated: {}", sessionId);
        }
        SecurityContextHolder.clearContext();
    }


    public static class LoginResponse {
        private final boolean success;
        private final String message;
        private final int statusCode;
        private final String sessionId;

        public LoginResponse(boolean success, String message, int statusCode, String sessionId) {
            this.success = success;
            this.message = message;
            this.statusCode = statusCode;
            this.sessionId = sessionId;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getMessage() {
            return message;
        }

        public int getStatusCode() {
            return statusCode;
        }

        public String getSessionId() {
            return sessionId;
        }
    }
}
