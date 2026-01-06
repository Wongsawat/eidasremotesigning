package com.wpanther.eidasremotesigning.dto.csc;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

/**
 * CSC API signature status response
 * Based on CSC API v2.0 specifications
 * Returns operation status and full results when completed
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CSCSignatureStatusResponse {
    /**
     * Operation status: PROCESSING, COMPLETED, FAILED, EXPIRED
     */
    private String status;

    /**
     * Error message if status is FAILED
     */
    private String errorMessage;

    // Fields for signHash results
    /**
     * Signature algorithm (for signHash operations)
     */
    private String signatureAlgorithm;

    /**
     * Array of Base64-encoded signatures (for signHash operations)
     */
    private String[] signatures;

    /**
     * Certificate used for signing (for signHash operations)
     */
    private String certificate;

    // Fields for signDocument results
    /**
     * Signed document digest (for signDocument operations)
     */
    private String signedDocumentDigest;

    /**
     * Base64-encoded signed document (for signDocument operations)
     */
    private String signedDocument;

    /**
     * Transaction ID (for signDocument operations)
     */
    private String transactionID;

    // Common fields
    /**
     * Timestamp data for both operation types
     */
    private Map<String, Object> timestampData;
}
