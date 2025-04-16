package com.wpanther.eidasremotesigning.controller;

import com.wpanther.eidasremotesigning.dto.csc.*;
import com.wpanther.eidasremotesigning.service.CSCAuthorizationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Controller implementing the Cloud Signature Consortium API v2.0 authorization endpoints
 * Handles credential authorization operations as defined in CSC API 2.0
 */
@RestController
@RequestMapping("/csc/v2/credentials")
@RequiredArgsConstructor
@Slf4j
public class CSCAuthorizationController {

    private final CSCAuthorizationService cscAuthorizationService;

    /**
     * Authorize credential for signing
     * This endpoint initiates the credential authorization process
     */
    @PostMapping("/authorize")
    public ResponseEntity<CSCAuthorizeResponse> authorizeCredential(
            @Valid @RequestBody CSCAuthorizeRequest request) {
        log.debug("CSC API: Credential authorization request from client: {}", request.getClientId());
        
        CSCAuthorizeResponse response = cscAuthorizationService.authorizeCredential(request);
        return ResponseEntity.ok(response);
    }
    
    /**
     * Extend credential authorization time
     * Extends the validity period of an existing authorization
     */
    @PostMapping("/extendTransaction")
    public ResponseEntity<CSCExtendTransactionResponse> extendTransaction(
            @Valid @RequestBody CSCExtendTransactionRequest request) {
        log.debug("CSC API: Transaction extension request from client: {}", request.getClientId());
        
        CSCExtendTransactionResponse response = cscAuthorizationService.extendTransaction(request);
        return ResponseEntity.ok(response);
    }
    
    /**
     * Check credential authorization status
     * Returns the current status of a credential authorization process
     */
    @PostMapping("/authorizeStatus")
    public ResponseEntity<CSCAuthorizeStatusResponse> getAuthorizeStatus(
            @Valid @RequestBody CSCAuthorizeStatusRequest request) {
        log.debug("CSC API: Authorization status request from client: {}", request.getClientId());
        
        CSCAuthorizeStatusResponse response = cscAuthorizationService.getAuthorizeStatus(request);
        return ResponseEntity.ok(response);
    }
}