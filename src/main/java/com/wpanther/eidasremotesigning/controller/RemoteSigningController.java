package com.wpanther.eidasremotesigning.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.wpanther.eidasremotesigning.dto.DigestSigningRequest;
import com.wpanther.eidasremotesigning.dto.DigestSigningResponse;
import com.wpanther.eidasremotesigning.service.RemoteSigningService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * REST controller for remote signing operations
 * All endpoints require OAuth2 authentication
 */
@RestController
@RequestMapping("/api/v1/signing")
@RequiredArgsConstructor
@Slf4j
public class RemoteSigningController {

    private final RemoteSigningService remoteSigningService;
    
    /**
     * Endpoint for signing document digests for XAdES and PAdES signatures
     */
    @PostMapping("/digest")
    public ResponseEntity<DigestSigningResponse> signDigest(
            @Valid @RequestBody DigestSigningRequest request) {
        log.debug("Received digest signing request for certificate ID: {}", request.getCertificateId());
        DigestSigningResponse response = remoteSigningService.signDigest(request);
        return ResponseEntity.ok(response);
    }
}