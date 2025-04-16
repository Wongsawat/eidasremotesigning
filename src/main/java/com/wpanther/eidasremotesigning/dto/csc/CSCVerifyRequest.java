package com.wpanther.eidasremotesigning.dto.csc;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import jakarta.validation.constraints.NotBlank;

/**
 * CSC API signature verification request
 * Based on CSC API v2.0 specifications
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CSCVerifyRequest {
    @NotBlank(message = "clientId is required")
    private String clientId;
    
    // Either signedDocument or documentDigest + signature must be provided
    private String signedDocument;
    
    private String documentDigest;
    private String signature;
    
    @NotBlank(message = "hashAlgo is required when using documentDigest")
    private String hashAlgo;
    
    private String signatureAlgorithm;
    private String certificate;
    private String signatureType;
}