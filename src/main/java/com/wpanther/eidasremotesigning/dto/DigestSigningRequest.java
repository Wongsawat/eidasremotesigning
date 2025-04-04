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
public class DigestSigningRequest {
    
    @NotBlank(message = "Certificate ID is required")
    private String certificateId;
    
    @NotBlank(message = "Digest value is required")
    private String digestValue;
    
    @NotBlank(message = "Digest algorithm is required")
    private String digestAlgorithm;
    
    @NotNull(message = "Signature type is required")
    private SignatureType signatureType;
    
    // Optional parameters for signature-specific requirements
    private String signatureParams;
    
    // Enumeration for supported signature types
    public enum SignatureType {
        XADES,
        PADES
    }
}