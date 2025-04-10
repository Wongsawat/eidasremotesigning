package com.wpanther.eidasremotesigning.controller;

import com.wpanther.eidasremotesigning.dto.csc.*;
import com.wpanther.eidasremotesigning.service.CSCApiService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Controller implementing the Cloud Signature Consortium API v2.0
 * See https://cloudsignatureconsortium.org/resources/csc-api-v2-0/
 */
@RestController
@RequestMapping("/csc/v2")
@RequiredArgsConstructor
@Slf4j
public class CSCApiController {

    private final CSCApiService cscApiService;

    /**
     * Get information about this CSC service
     */
    @GetMapping("/info")
    public ResponseEntity<CSCInfoResponse> getInfo() {
        log.debug("CSC API: Request for service information");
        
        // Build response with service capabilities according to CSC API v2.0
        CSCInfoResponse response = CSCInfoResponse.builder()
                .name("eIDAS Remote Signing Service")
                .region("EU")
                .lang(List.of("en"))
                .description("eIDAS compliant remote signing service supporting PKCS#11 hardware tokens")
                .methods(List.of("credentials/list", "credentials/info", "signatures/signHash"))
                .build();
                
        // Add authentication type information
        Map<String, Object> authType = new HashMap<>();
        authType.put("implicit", true);
        authType.put("oauth2", true);
        response.setAuthType(authType);
        
        return ResponseEntity.ok(response);
    }

    /**
     * List available credentials (certificates)
     */
    @PostMapping("/credentials/list")
    public ResponseEntity<CSCCredentialsListResponse> listCredentials(
            @Valid @RequestBody CSCCredentialsListRequest request) {
        log.debug("CSC API: Request for credentials list from client: {}", request.getClientId());
        
        CSCCredentialsListResponse response = cscApiService.listCredentials(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Get information about a specific credential
     */
    @PostMapping("/credentials/info")
    public ResponseEntity<CSCCertificateInfo> getCredentialInfo(
            @Valid @RequestBody CSCCredentialsListRequest request,
            @RequestParam String credentialID) {
        log.debug("CSC API: Request for credential info, ID: {}, client: {}", 
                credentialID, request.getClientId());
        
        CSCCertificateInfo response = cscApiService.getCredentialInfo(request, credentialID);
        return ResponseEntity.ok(response);
    }

    /**
     * Sign hash(es) with the specified credential
     */
    @PostMapping("/signatures/signHash")
    public ResponseEntity<CSCSignatureResponse> signHash(
            @Valid @RequestBody CSCSignatureRequest request) {
        log.debug("CSC API: Signature request for credential: {}, client: {}", 
                request.getCredentialID(), request.getClientId());
        
        CSCSignatureResponse response = cscApiService.signHash(request);
        return ResponseEntity.ok(response);
    }
}
