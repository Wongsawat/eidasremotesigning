package com.wpanther.eidasremotesigning.controller;

import org.springframework.http.HttpStatus;
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
 * REST controller for legacy remote signing operations
 * @deprecated This API is maintained for backward compatibility.
 *             New implementations should use the CSC API v2.0 endpoints.
 */
@RestController
@RequestMapping("/api/v1/signing")
@RequiredArgsConstructor
@Slf4j
@Deprecated(since = "2.0.0", forRemoval = false)
public class RemoteSigningController {

    private final RemoteSigningService remoteSigningService;
    
    /**
     * Endpoint for signing document digests for XAdES and PAdES signatures
     * @deprecated Use /csc/v2/signatures/signHash endpoint instead
     */
    @PostMapping("/digest")
    @Deprecated(since = "2.0.0", forRemoval = false)
    public ResponseEntity<DigestSigningResponse> signDigest(
            @Valid @RequestBody DigestSigningRequest request) {
        log.debug("Received legacy digest signing request for certificate ID: {}", request.getCertificateId());
        DigestSigningResponse response = remoteSigningService.signDigest(request);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }
}