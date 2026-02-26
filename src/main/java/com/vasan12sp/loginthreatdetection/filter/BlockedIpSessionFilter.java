package com.vasan12sp.loginthreatdetection.filter;

import com.vasan12sp.loginthreatdetection.repository.BlockedIpRepository;
import com.vasan12sp.loginthreatdetection.service.SessionRevocationService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


/**
 * Filter that checks if the requesting IP is blocked on every request.
 * If blocked, invalidates the current session and returns 403.
 * This ensures mid-session revocation when an IP gets blocked
 * by the ML model or rule-based logs monitor.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class BlockedIpSessionFilter extends OncePerRequestFilter {

    private final BlockedIpRepository blockedIpRepository;
    private final SessionRevocationService sessionRevocationService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String ip = extractIpAddress(request);

        if (blockedIpRepository.isIpBlocked(ip)) {
            log.warn("Blocked IP detected in session filter: {}", ip);

            // Invalidate current session if exists
            HttpSession session = request.getSession(false);
            if (session != null) {
                String sessionId = session.getId();
                session.invalidate();
                sessionRevocationService.removeSession(sessionId);
                log.info("Session invalidated for blocked IP: {}", ip);
            }

            // Clear security context
            SecurityContextHolder.clearContext();

            // Return 403 JSON response
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.getWriter().write(
                "{\"success\":false,\"message\":\"Access Denied: Your IP has been blocked due to suspicious activity\",\"statusCode\":403}"
            );
            return;
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Extract IP address from request, handling proxy headers.
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
