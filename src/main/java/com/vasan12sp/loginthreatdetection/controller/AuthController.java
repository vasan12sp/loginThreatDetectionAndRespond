package com.vasan12sp.loginthreatdetection.controller;

import com.vasan12sp.loginthreatdetection.entity.User;
import com.vasan12sp.loginthreatdetection.model.LoginRequest;
import com.vasan12sp.loginthreatdetection.repository.UserRepository;
import com.vasan12sp.loginthreatdetection.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;


@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;


    /**
     * Login endpoint - authenticates user and creates a session.
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(
            @RequestBody LoginRequest loginRequest,
            HttpServletRequest request) {

        String userIp = extractIpAddress(request);
        log.info("Login request from IP: {}", userIp);

        AuthService.LoginResponse response = authService.processLogin(loginRequest, userIp, request);

        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("success", response.isSuccess());
        responseBody.put("message", response.getMessage());
        responseBody.put("ip", userIp);
        responseBody.put("timestamp", System.currentTimeMillis());

        if (response.getSessionId() != null) {
            responseBody.put("sessionId", response.getSessionId());
        }

        return ResponseEntity.status(response.getStatusCode()).body(responseBody);
    }


    /**
     * Logout endpoint - invalidates session and clears security context.
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(HttpServletRequest request) {
        String userIp = extractIpAddress(request);
        log.info("Logout request from IP: {}", userIp);

        authService.processLogout(request);

        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("success", true);
        responseBody.put("message", "Logged out successfully");
        responseBody.put("timestamp", System.currentTimeMillis());

        return ResponseEntity.ok(responseBody);
    }


    /**
     * Register endpoint - creates a new user account.
     */
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody LoginRequest registerRequest) {
        Map<String, Object> responseBody = new HashMap<>();

        if (userRepository.existsByUsername(registerRequest.getUsername())) {
            responseBody.put("success", false);
            responseBody.put("message", "Username already exists");
            return ResponseEntity.badRequest().body(responseBody);
        }

        User newUser = new User(
                registerRequest.getUsername(),
                passwordEncoder.encode(registerRequest.getPassword())
        );
        userRepository.save(newUser);

        log.info("New user registered: {}", registerRequest.getUsername());

        responseBody.put("success", true);
        responseBody.put("message", "User registered successfully");
        responseBody.put("timestamp", System.currentTimeMillis());

        return ResponseEntity.ok(responseBody);
    }


    /**
     * Session info endpoint - returns current session and user info.
     * Requires authentication.
     */
    @GetMapping("/session-info")
    public ResponseEntity<Map<String, Object>> sessionInfo(HttpServletRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        HttpSession session = request.getSession(false);

        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("authenticated", auth != null && auth.isAuthenticated());
        responseBody.put("username", auth != null ? auth.getName() : null);
        responseBody.put("sessionId", session != null ? session.getId() : null);
        responseBody.put("ip", extractIpAddress(request));
        responseBody.put("timestamp", System.currentTimeMillis());

        return ResponseEntity.ok(responseBody);
    }


    /**
     * Health check endpoint - public.
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        Map<String, String> response = new HashMap<>();
        response.put("status", "UP");
        response.put("service", "Login Threat Detection API");
        response.put("authentication", "Session-Based (Spring Security + Spring Session JDBC)");
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
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }
        return ip != null ? ip : "unknown";
    }
}
