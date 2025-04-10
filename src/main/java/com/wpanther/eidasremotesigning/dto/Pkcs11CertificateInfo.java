package com.wpanther.eidasremotesigning.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * DTO for certificate information from PKCS#11 token
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Pkcs11CertificateInfo {
    private String alias;
    private String subjectDN;
    private String issuerDN;
    private String serialNumber;
    private Instant notBefore;
    private Instant notAfter;
    private boolean hasPrivateKey;
}
