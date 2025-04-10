package com.wpanther.eidasremotesigning.controller;

import java.util.List;

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

import com.wpanther.eidasremotesigning.dto.CertificateDetailResponse;
import com.wpanther.eidasremotesigning.dto.CertificateListResponse;
import com.wpanther.eidasremotesigning.dto.CertificateUpdateRequest;
import com.wpanther.eidasremotesigning.dto.Pkcs11CertificateAssociateRequest;
import com.wpanther.eidasremotesigning.dto.Pkcs11CertificateInfo;
import com.wpanther.eidasremotesigning.service.SigningCertificateService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * REST controller for certificate management operations
 * All endpoints require authentication
 */
@RestController
@RequestMapping("/certificates")
@RequiredArgsConstructor
@Slf4j
public class SigningCertificateController {

    private final SigningCertificateService signingCertificateService;

    /**
     * List available certificates in PKCS#11 token
     */
    @GetMapping("/pkcs11")
    public ResponseEntity<List<Pkcs11CertificateInfo>> listPkcs11Certificates() {
        log.debug("Listing certificates in PKCS#11 token");
        List<Pkcs11CertificateInfo> certificates = signingCertificateService.listPkcs11Certificates();
        return ResponseEntity.ok(certificates);
    }
    
    /**
     * Associate an existing PKCS#11 certificate with the client
     */
    @PostMapping("/pkcs11/associate")
    public ResponseEntity<CertificateDetailResponse> associatePkcs11Certificate(
            @Valid @RequestBody Pkcs11CertificateAssociateRequest request) {
        log.debug("Associating PKCS#11 certificate with alias: {}", request.getCertificateAlias());
        CertificateDetailResponse response = signingCertificateService.associatePkcs11Certificate(request);
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
