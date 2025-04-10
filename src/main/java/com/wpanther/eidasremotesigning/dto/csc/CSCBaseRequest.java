package com.wpanther.eidasremotesigning.dto.csc;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import jakarta.validation.constraints.NotBlank;

/**
 * Base request for CSC API operations
 * Based on CSC API v2.0 specifications
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CSCBaseRequest {
    @NotBlank(message = "clientId is required")
    private String clientId;
    
    // Credentials object for token PIN/OTP
    private Credentials credentials;
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Credentials {
        private PIN pin;
        private OTP otp;
    }
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PIN {
        @NotBlank(message = "PIN value is required")
        private String value;
        private String id;
    }
    
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class OTP {
        private String value;
        private String id;
        private String provider;
    }
}




















