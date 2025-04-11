package com.wpanther.eidasremotesigning.dto.csc;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import jakarta.validation.constraints.NotBlank;

/**
 * CSC API certificate association request
 * Based on CSC API v2.0 specifications with extensions for PKCS#11 functionality
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CSCAssociateCertificateRequest {
    // Fields from CSCBaseRequest
    @NotBlank(message = "clientId is required")
    private String clientId;
    
    private CSCBaseRequest.Credentials credentials;
    
    @NotBlank(message = "Certificate alias is required")
    private String certificateAlias;
    
    private String description;
    
    // Optional slot ID for PKCS#11 token
    private Integer slotId;
}