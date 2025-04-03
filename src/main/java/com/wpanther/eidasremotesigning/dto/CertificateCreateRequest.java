package com.wpanther.eidasremotesigning.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateCreateRequest {
    @NotBlank(message = "Subject DN is required")
    private String subjectDN;
    
    private String keyAlgorithm;
    
    private Integer keySize;
    
    @NotNull(message = "Validity period in months is required")
    private Integer validityMonths;
    
    private String description;
    
    private boolean selfSigned;
    
    // If not self-signed, we need the issuer certificate ID
    private String issuerCertificateId;
}