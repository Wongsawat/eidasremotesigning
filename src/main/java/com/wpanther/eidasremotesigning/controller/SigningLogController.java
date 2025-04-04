package com.wpanther.eidasremotesigning.controller;

import java.time.Instant;
import java.util.List;

import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.wpanther.eidasremotesigning.entity.SigningLog;
import com.wpanther.eidasremotesigning.service.SigningLogService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Controller for accessing signing operation logs
 * Provides endpoints for audit and compliance purposes
 */
@RestController
@RequestMapping("/api/v1/logs")
@RequiredArgsConstructor
@Slf4j
public class SigningLogController {

    private final SigningLogService signingLogService;
    
    /**
     * Get all signing logs for the authenticated client
     */
    @GetMapping
    public ResponseEntity<List<SigningLog>> getClientLogs() {
        log.debug("Fetching all signing logs for authenticated client");
        List<SigningLog> logs = signingLogService.getClientLogs();
        return ResponseEntity.ok(logs);
    }
    
    /**
     * Get logs for a specific certificate
     */
    @GetMapping("/certificate/{certificateId}")
    public ResponseEntity<List<SigningLog>> getCertificateLogs(
            @PathVariable String certificateId) {
        log.debug("Fetching signing logs for certificate: {}", certificateId);
        List<SigningLog> logs = signingLogService.getCertificateLogs(certificateId);
        return ResponseEntity.ok(logs);
    }
    
    /**
     * Get logs for a specific date range
     */
    @GetMapping("/daterange")
    public ResponseEntity<List<SigningLog>> getLogsByDateRange(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant startDate,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant endDate) {
        log.debug("Fetching signing logs from {} to {}", startDate, endDate);
        List<SigningLog> logs = signingLogService.getLogsByDateRange(startDate, endDate);
        return ResponseEntity.ok(logs);
    }
}