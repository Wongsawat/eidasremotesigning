package com.wpanther.eidasremotesigning.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DigestSigningResponse {
    
    private String signatureValue;
    private String signatureAlgorithm;
    private String certificateId;
    private String certificateBase64;
}