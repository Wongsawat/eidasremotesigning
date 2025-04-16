package com.wpanther.eidasremotesigning.dto.csc;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * CSC API certificate validation response
 * Based on CSC API v2.0 specifications
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CSCCertificateValidationResponse {
    private boolean valid;
    private String certificateStatus;
    private String[] certificateStatusDetails;
    private String certificateType;
    private String signedBy;
    private String[] qualifications;
}
