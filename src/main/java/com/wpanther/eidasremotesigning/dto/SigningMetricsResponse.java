package com.wpanther.eidasremotesigning.dto;

import java.time.Instant;
import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO containing metrics about signing operations
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SigningMetricsResponse {
    
    // Total successful operations
    private long successfulOperations;
    
    // Total failed operations
    private long failedOperations;
    
    // Operations by signature type
    private Map<String, Long> operationsBySignatureType;
    
    // Operations by digest algorithm
    private Map<String, Long> operationsByDigestAlgorithm;
    
    // Time-based metrics
    private long operationsLast24Hours;
    private long operationsLast7Days;
    private long operationsLast30Days;
    
    // Timestamp when metrics were calculated
    private Instant timestamp;
}