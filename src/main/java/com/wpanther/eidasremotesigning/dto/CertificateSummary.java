package com.wpanther.eidasremotesigning.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateSummary {
    private String id;
    private String subjectDN;
    private String serialNumber;
    private String description;
    private Instant notBefore;
    private Instant notAfter;
    private boolean active;
    private boolean selfSigned;
    private String storageType; // PKCS11 or PKCS12
}
