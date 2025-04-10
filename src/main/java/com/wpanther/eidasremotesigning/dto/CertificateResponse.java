package com.wpanther.eidasremotesigning.dto;

import java.security.cert.X509Certificate;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Internal wrapper class to hold a certificate response with the actual X509Certificate
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateResponse {
    private CertificateDetailResponse detailResponse;
    private X509Certificate x509Certificate;
}