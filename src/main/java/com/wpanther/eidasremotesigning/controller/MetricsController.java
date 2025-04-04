package com.wpanther.eidasremotesigning.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.wpanther.eidasremotesigning.dto.SigningMetricsResponse;
import com.wpanther.eidasremotesigning.service.MetricsService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Controller for retrieving metrics about signing operations
 */
@RestController
@RequestMapping("/api/v1/metrics")
@RequiredArgsConstructor
@Slf4j
public class MetricsController {

    private final MetricsService metricsService;
    
    /**
     * Get metrics for the authenticated client
     */
    @GetMapping
    public ResponseEntity<SigningMetricsResponse> getClientMetrics() {
        String clientId = getCurrentClientId();
        log.debug("Fetching metrics for client: {}", clientId);
        
        SigningMetricsResponse metrics = metricsService.calculateClientMetrics(clientId);
        return ResponseEntity.ok(metrics);
    }
    
    /**
     * Gets the current client ID from the security context
     */
    private String getCurrentClientId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication != null && authentication.getPrincipal() != null) {
            return authentication.getName();
        }
        
        return "unknown";
    }
}