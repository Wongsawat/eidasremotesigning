package com.wpanther.eidasremotesigning.service;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.wpanther.eidasremotesigning.dto.DigestSigningRequest;
import com.wpanther.eidasremotesigning.entity.SigningLog;
import com.wpanther.eidasremotesigning.exception.SigningException;
import com.wpanther.eidasremotesigning.repository.SigningLogRepository;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Service for handling signing operation logs
 * Creates an audit trail for all signing operations
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SigningLogService {

    private final SigningLogRepository signingLogRepository;
    
    /**
     * Logs a successful signing operation
     */
    @Transactional
    public void logSuccessfulSigning(DigestSigningRequest request, String signatureAlgorithm) {
        SigningLog signingLog = createBaseLog(request);
        signingLog.setStatus("SUCCESS");
        signingLog.setSignatureAlgorithm(signatureAlgorithm);
        
        signingLogRepository.saveAndFlush(signingLog);
        log.info("Logged successful signing operation with ID: {}", signingLog.getId());
    }
    
    /**
     * Logs a failed signing operation
     */
    @Transactional
    public void logFailedSigning(DigestSigningRequest request, String errorMessage) {
        SigningLog signingLog = createBaseLog(request);
        signingLog.setStatus("FAILED");
        signingLog.setErrorMessage(errorMessage);
        
        signingLogRepository.saveAndFlush(signingLog);
        log.warn("Logged failed signing operation with ID: {}", signingLog.getId());
    }
    
    /**
     * Creates a base log entry with common fields
     */
    private SigningLog createBaseLog(DigestSigningRequest request) {
        String clientId = getCurrentClientId();
        String requestIp = getClientIpAddress();
        
        return SigningLog.builder()
                .id(UUID.randomUUID().toString())
                .clientId(clientId)
                .certificateId(request.getCertificateId())
                .requestIp(requestIp)
                .digestAlgorithm(request.getDigestAlgorithm())
                .signatureType(request.getSignatureType().toString())
                .digestValue(request.getDigestValue())
                .createdAt(Instant.now())
                .build();
    }
    
    /**
     * Get signing logs for the current client
     */
    @Transactional(readOnly = true)
    public List<SigningLog> getClientLogs() {
        String clientId = getCurrentClientId();
        return signingLogRepository.findByClientId(clientId);
    }
    
    /**
     * Get signing logs for a specific certificate
     */
    @Transactional(readOnly = true)
    public List<SigningLog> getCertificateLogs(String certificateId) {
        // Ensure the client can only access their own certificate logs
        String clientId = getCurrentClientId();
        List<SigningLog> logs = signingLogRepository.findByCertificateId(certificateId);
        
        // Filter out logs from other clients
        return logs.stream()
                .filter(log -> log.getClientId().equals(clientId))
                .toList();
    }
    
    /**
     * Get signing logs for a date range
     */
    @Transactional(readOnly = true)
    public List<SigningLog> getLogsByDateRange(Instant start, Instant end) {
        String clientId = getCurrentClientId();
        return signingLogRepository.findByClientIdAndCreatedAtBetween(clientId, start, end);
    }
    
    /**
     * Get the current client ID from the security context
     */
    private String getCurrentClientId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        // Add debugging to see what authentication type is available
        log.debug("Authentication type: {}", authentication != null ? authentication.getClass().getName() : "null");
        
        if (authentication instanceof JwtAuthenticationToken) {
            JwtAuthenticationToken jwtAuth = (JwtAuthenticationToken) authentication;
            return jwtAuth.getName();
        }
        
        // For client credential flow, check if client ID is available in security context
        if (authentication != null && authentication.getPrincipal() != null) {
            return authentication.getName();
        }
        
        throw new SigningException("Unable to determine client ID from security context");
    }
    
    /**
     * Gets the client IP address from the current request
     */
    private String getClientIpAddress() {
        try {
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attributes != null) {
                HttpServletRequest request = attributes.getRequest();
                
                // Get the client IP address (handling proxies)
                String xForwardedFor = request.getHeader("X-Forwarded-For");
                if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
                    // Get the first IP in the chain
                    return xForwardedFor.split(",")[0].trim();
                }
                
                return request.getRemoteAddr();
            }
        } catch (Exception e) {
            log.warn("Failed to determine client IP", e);
        }
        
        return "unknown";
    }
}