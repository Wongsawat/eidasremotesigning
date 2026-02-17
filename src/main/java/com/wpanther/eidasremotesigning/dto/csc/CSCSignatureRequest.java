package com.wpanther.eidasremotesigning.dto.csc;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;


/**
 * CSC API signature request
 * Based on CSC API v2.0 specifications
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CSCSignatureRequest{

    @NotBlank(message = "clientId is required")
    private String clientId;
    
    private CSCBaseRequest.Credentials credentials;

    private String SAD;

    @NotBlank(message = "Certificate ID is required")
    private String credentialID;
    
    @NotBlank(message = "Hash algorithm is required")
    private String hashAlgo;
    
    @NotNull(message = "Data to sign is required")
    private SignatureData signatureData;

    private SignatureOptions signatureOptions;

    /**
     * Enable asynchronous operation mode
     * If true, returns operationID immediately instead of waiting for signature completion
     * Default: null (treated as false for backward compatibility)
     */
    private Boolean async;
}