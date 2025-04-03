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
public class CertificateDetailResponse {
    private String id;
    private String subjectDN;
    private String issuerDN;
    private String serialNumber;
    private String keyAlgorithm;
    private Integer keySize;
    private String description;
    private Instant notBefore;
    private Instant notAfter;
    private String certificateBase64;
    private boolean active;
    private boolean selfSigned;
    private Instant createdAt;
    private Instant updatedAt;
}