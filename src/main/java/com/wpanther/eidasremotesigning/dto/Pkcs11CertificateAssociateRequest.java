package com.wpanther.eidasremotesigning.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for associating a PKCS#11 certificate with a client
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Pkcs11CertificateAssociateRequest {
    
    @NotBlank(message = "Certificate alias is required")
    private String certificateAlias;
    
    private String description;
    
    // The slot ID where the certificate is located (optional, default will be used if not provided)
    private Integer slotId;
}
