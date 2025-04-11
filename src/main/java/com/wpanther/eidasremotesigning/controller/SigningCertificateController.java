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
import com.wpanther.eidasremotesigning.dto.csc.CSCBaseRequest;
import com.wpanther.eidasremotesigning.exception.CertificateException;
import com.wpanther.eidasremotesigning.service.SigningCertificateService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * REST controller for certificate management operations
 * @deprecated Legacy API. Use CSCApiController for new integrations.
 */
@RestController
@RequestMapping("/certificates")
@RequiredArgsConstructor
@Slf4j
@Deprecated
public class SigningCertificateController {

    private final SigningCertificateService signingCertificateService;


    
    /**
     * Associate an existing PKCS#11 certificate with the client
     * @deprecated Use CSC API instead
     */
    @PostMapping("/pkcs11/associate")
    @Deprecated
    public ResponseEntity<CertificateDetailResponse> associatePkcs11Certificate(
            @Valid @RequestBody Pkcs11CertificateAssociateRequest request,
            @RequestBody(required = false) CSCBaseRequest credentials) {
        log.debug("Associating PKCS#11 certificate with alias: {}", request.getCertificateAlias());
        
        String pin = null;
        if (credentials != null && credentials.getCredentials() != null && 
            credentials.getCredentials().getPin() != null) {
            pin = credentials.getCredentials().getPin().getValue();
        }
        
        if (pin == null || pin.isEmpty()) {
            throw new CertificateException("PIN is required to access PKCS#11 token");
        }
        
        CertificateDetailResponse response = signingCertificateService.associatePkcs11Certificate(request, pin);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

}