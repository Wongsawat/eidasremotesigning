package com.wpanther.eidasremotesigning.service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

import com.wpanther.eidasremotesigning.dto.SigningMetricsResponse;
import com.wpanther.eidasremotesigning.entity.SigningLog;
import com.wpanther.eidasremotesigning.repository.SigningLogRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Service for calculating metrics from signing logs
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class MetricsService {

    private final SigningLogRepository signingLogRepository;
    
    /**
     * Calculates metrics for the authenticated client
     */
    public SigningMetricsResponse calculateClientMetrics(String clientId) {
        log.debug("Calculating metrics for client: {}", clientId);
        
        // Get all logs for the client
        List<SigningLog> clientLogs = signingLogRepository.findByClientId(clientId);
        
        // Current time for time-based metrics
        Instant now = Instant.now();
        Instant oneDayAgo = now.minus(24, ChronoUnit.HOURS);
        Instant sevenDaysAgo = now.minus(7, ChronoUnit.DAYS);
        Instant thirtyDaysAgo = now.minus(30, ChronoUnit.DAYS);
        
        // Calculate metrics
        long successfulOps = countByStatus(clientLogs, "SUCCESS");
        long failedOps = countByStatus(clientLogs, "FAILED");
        
        Map<String, Long> bySignatureType = countBySignatureType(clientLogs);
        Map<String, Long> byDigestAlgorithm = countByDigestAlgorithm(clientLogs);
        
        long last24Hours = countInTimeRange(clientLogs, oneDayAgo, now);
        long last7Days = countInTimeRange(clientLogs, sevenDaysAgo, now);
        long last30Days = countInTimeRange(clientLogs, thirtyDaysAgo, now);
        
        // Build and return the response
        return SigningMetricsResponse.builder()
                .successfulOperations(successfulOps)
                .failedOperations(failedOps)
                .operationsBySignatureType(bySignatureType)
                .operationsByDigestAlgorithm(byDigestAlgorithm)
                .operationsLast24Hours(last24Hours)
                .operationsLast7Days(last7Days)
                .operationsLast30Days(last30Days)
                .timestamp(now)
                .build();
    }
    
    /**
     * Counts logs with a specific status
     */
    private long countByStatus(List<SigningLog> logs, String status) {
        return logs.stream()
                .filter(log -> status.equals(log.getStatus()))
                .count();
    }
    
    /**
     * Counts logs by signature type
     */
    private Map<String, Long> countBySignatureType(List<SigningLog> logs) {
        return logs.stream()
                .filter(log -> "SUCCESS".equals(log.getStatus()))
                .collect(Collectors.groupingBy(
                        SigningLog::getSignatureType,
                        Collectors.counting()
                ));
    }
    
    /**
     * Counts logs by digest algorithm
     */
    private Map<String, Long> countByDigestAlgorithm(List<SigningLog> logs) {
        return logs.stream()
                .filter(log -> "SUCCESS".equals(log.getStatus()))
                .collect(Collectors.groupingBy(
                        SigningLog::getDigestAlgorithm,
                        Collectors.counting()
                ));
    }
    
    /**
     * Counts logs in a time range
     */
    private long countInTimeRange(List<SigningLog> logs, Instant start, Instant end) {
        return logs.stream()
                .filter(log -> "SUCCESS".equals(log.getStatus()))
                .filter(log -> !log.getCreatedAt().isBefore(start) && !log.getCreatedAt().isAfter(end))
                .count();
    }
    
    /**
     * Gets overall system metrics for admin purposes
     * This would be used in a separate admin controller with appropriate authorization
     */
    public Map<String, Object> getSystemMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        
        // Overall counts
        metrics.put("totalOperations", signingLogRepository.count());
        metrics.put("successfulOperations", signingLogRepository.countByStatus("SUCCESS"));
        metrics.put("failedOperations", signingLogRepository.countByStatus("FAILED"));
        
        // Operations by signature type
        List<Object[]> bySignatureType = signingLogRepository.countBySignatureType();
        Map<String, Long> signatureTypeMap = new HashMap<>();
        
        for (Object[] result : bySignatureType) {
            signatureTypeMap.put((String) result[0], (Long) result[1]);
        }
        
        metrics.put("bySignatureType", signatureTypeMap);
        
        return metrics;
    }
}