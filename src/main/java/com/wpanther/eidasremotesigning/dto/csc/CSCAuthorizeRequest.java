package com.wpanther.eidasremotesigning.dto.csc;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import jakarta.validation.constraints.NotBlank;

/**
 * CSC API credential authorization request
 * Based on CSC API v2.0 specifications
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CSCAuthorizeRequest {
    @NotBlank(message = "clientId is required")
    private String clientId;
    
    private CSCBaseRequest.Credentials credentials;

    @NotBlank(message = "credentialID is required")
    private String credentialID;
    
    private String numSignatures;
    
    private Long validityPeriod;
    
    private String description;
}
