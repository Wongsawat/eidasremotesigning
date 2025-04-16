package com.wpanther.eidasremotesigning.dto.csc;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import jakarta.validation.constraints.NotBlank;

/**
 * CSC API timestamp request
 * Based on CSC API v2.0 specifications
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CSCTimestampRequest {
    @NotBlank(message = "clientId is required")
    private String clientId;
    
    // Options for timestamp type (document hash or document)
    private String documentDigest;
    private String document;
    
    @NotBlank(message = "hashAlgo is required")
    private String hashAlgo;
    
    // Optional timestamp policy identifier
    private String timestampPolicy;
}
