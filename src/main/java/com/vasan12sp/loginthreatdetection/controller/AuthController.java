package com.vasan12sp.loginthreatdetection.controller;

import com.vasan12sp.loginthreatdetection.model.LoginRequest;
import com.vasan12sp.loginthreatdetection.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;


@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;


    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(
            @RequestBody LoginRequest loginRequest,
            HttpServletRequest request) {

        // Extract IP address
        String userIp = extractIpAddress(request);
        log.info("Login request from IP: {}", userIp);

        // Process login through service
        AuthService.LoginResponse response = authService.processLogin(loginRequest, userIp);

        // Build response
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("success", response.isSuccess());
        responseBody.put("message", response.getMessage());
        responseBody.put("ip", userIp);
        responseBody.put("timestamp", System.currentTimeMillis());

        return ResponseEntity.status(response.getStatusCode()).body(responseBody);
    }


    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        Map<String, String> response = new HashMap<>();
        response.put("status", "UP");
        response.put("service", "Login Threat Detection API");
        return ResponseEntity.ok(response);
    }

    /**
     * Extract IP address from request.
     * Handles proxy headers (X-Forwarded-For, X-Real-IP).
     */
    private String extractIpAddress(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("X-Real-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        // If multiple IPs (proxy chain), take the first one
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }
        return ip != null ? ip : "unknown";
    }
}
