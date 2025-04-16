package com.wpanther.eidasremotesigning.dto.csc;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import jakarta.validation.constraints.NotBlank;

/**
 * CSC API document signing request
 * Based on CSC API v2.0 specifications
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CSCSignDocumentRequest {
    @NotBlank(message = "clientId is required")
    private String clientId;
    
    private CSCBaseRequest.Credentials credentials;
    
    @NotBlank(message = "credentialID is required")
    private String credentialID;
    
    private String SAD;
    
    @NotBlank(message = "documentID is required")
    private String documentID;
    
    @NotBlank(message = "documentDigest is required")
    private String documentDigest;
    
    @NotBlank(message = "hashAlgo is required")
    private String hashAlgo;
    
    private SignatureAttributes signatureAttributes;
    
    private SignatureOptions signatureOptions;
    
    // Base64 encoded document for direct signing
    private String document;
}
