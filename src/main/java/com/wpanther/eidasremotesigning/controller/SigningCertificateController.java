package com.wpanther.eidasremotesigning.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.wpanther.eidasremotesigning.dto.CertificateCreateRequest;
import com.wpanther.eidasremotesigning.dto.CertificateDetailResponse;
import com.wpanther.eidasremotesigning.dto.CertificateListResponse;
import com.wpanther.eidasremotesigning.dto.CertificateUpdateRequest;
import com.wpanther.eidasremotesigning.service.SigningCertificateService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

/**
 * REST controller for certificate management operations
 * All endpoints require authentication
 */

@RestController
@RequestMapping("/certificates")
@RequiredArgsConstructor
public class SigningCertificateController {

    private final SigningCertificateService signingCertificateService;

    @PostMapping
    public ResponseEntity<CertificateDetailResponse> createCertificate(
            @Valid @RequestBody CertificateCreateRequest request) {
        CertificateDetailResponse response = signingCertificateService.createCertificate(request);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    @GetMapping
    public ResponseEntity<CertificateListResponse> listCertificates() {
        CertificateListResponse response = signingCertificateService.listCertificates();
        return ResponseEntity.ok(response);
    }

    @GetMapping("/{certificateId}")
    public ResponseEntity<CertificateDetailResponse> getCertificate(
            @PathVariable String certificateId) {
        CertificateDetailResponse response = signingCertificateService.getCertificate(certificateId);
        return ResponseEntity.ok(response);
    }

    @PutMapping("/{certificateId}")
    public ResponseEntity<CertificateDetailResponse> updateCertificate(
            @PathVariable String certificateId,
            @Valid @RequestBody CertificateUpdateRequest request) {
        CertificateDetailResponse response = signingCertificateService.updateCertificate(certificateId, request);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/{certificateId}")
    public ResponseEntity<Void> deleteCertificate(
            @PathVariable String certificateId) {
        signingCertificateService.deleteCertificate(certificateId);
        return ResponseEntity.noContent().build();
    }
}