package com.wpanther.eidasremotesigning.dto.csc;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

/**
 * CSC API certificate info response
 * Based on CSC API v2.0 specifications
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CSCCertificateInfo {
    private String id;
    private String status;
    private CSCCertificateDetails cert;
    private CSCKeyInfo key;
    private String authMode;
    private Map<String, Object> scal;
    private CSCPINInfo pin;
    private CSCOTPInfo otp;
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CSCCertificateDetails {
        private String subject;
        private String issuerDN;
        private String serialNumber;
        private String[] policies;
        private String[] keyUsage;
        private Long validFrom;
        private Long validTo;
        private String certificate; // Base64 encoded certificate
    }
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CSCKeyInfo {
        private String algo;
        private Integer length;
        private String[] curveIds;
    }
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CSCPINInfo {
        private String presence;
        private String format;
        private String label;
        private String description;
    }
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CSCOTPInfo {
        private String presence;
        private String type;
        private String provider;
        private String description;
    }
}
