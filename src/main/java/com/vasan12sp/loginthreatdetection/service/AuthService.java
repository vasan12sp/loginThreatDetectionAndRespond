package com.vasan12sp.loginthreatdetection.service;

import com.vasan12sp.loginthreatdetection.model.LoginEvent;
import com.vasan12sp.loginthreatdetection.model.LoginRequest;
import com.vasan12sp.loginthreatdetection.repository.BlockedIpRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Random;


@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final BlockedIpRepository blockedIpRepository;
    private final KafkaProducerService kafkaProducerService;
    private final Random random = new Random();


    public LoginResponse processLogin(LoginRequest request, String userIp) {
        log.info("Processing login for user: {} from IP: {}", request.getUsername(), userIp);

        // STEP 1: Check Block Status (Enforcement)
        if (blockedIpRepository.isIpBlocked(userIp)) {
            log.warn("Login attempt from blocked IP: {}", userIp);
            return new LoginResponse(false, "Access Denied: Temporarily Blocked", 403);
        }

        // STEP 2: Process Authentication (Mock)
        boolean isSuccess = authenticateUser(request);
        String status = isSuccess ? "SUCCESS" : "FAILURE";

        // STEP 3: Emit Event (Async Logging) - Fire and Forget
        LoginEvent event = new LoginEvent(userIp, status, Instant.now(), request.getUsername());
        kafkaProducerService.sendLoginEvent(event);

        // STEP 4: Return Response Immediately (Low Latency)
        if (isSuccess) {
            return new LoginResponse(true, "Login successful", 200);
        } else {
            return new LoginResponse(false, "Invalid credentials", 401);
        }
    }


    private boolean authenticateUser(LoginRequest request) {
        // For demo: 30% success rate to trigger failures
        // In production: verify credentials against user store
        if ("admin".equals(request.getUsername()) && "admin123".equals(request.getPassword())) {
            return true;
        }
        return random.nextDouble() < 0.3;
    }


    public static class LoginResponse {
        private final boolean success;
        private final String message;
        private final int statusCode;

        public LoginResponse(boolean success, String message, int statusCode) {
            this.success = success;
            this.message = message;
            this.statusCode = statusCode;
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
    }
}
