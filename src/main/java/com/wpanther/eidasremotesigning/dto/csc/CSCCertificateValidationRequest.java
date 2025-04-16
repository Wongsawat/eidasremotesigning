package com.wpanther.eidasremotesigning.dto.csc;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import jakarta.validation.constraints.NotBlank;

/**
 * CSC API certificate validation request
 * Based on CSC API v2.0 specifications
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CSCCertificateValidationRequest {
    @NotBlank(message = "clientId is required")
    private String clientId;
    
    @NotBlank(message = "certificate is required")
    private String certificate;
    
    private Long validationTime;
    private String[] certificatePolicyIDs;
}
