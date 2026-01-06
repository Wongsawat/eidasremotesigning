package com.wpanther.eidasremotesigning.dto.csc;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


import java.util.Map;

/**
 * CSC API document signing response
 * Based on CSC API v2.0 specifications
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CSCSignDocumentResponse {
    /**
     * Operation ID for asynchronous operations
     * Present only when async=true in the request
     */
    private String operationID;

    private String transactionID;
    private String signedDocument;
    private String signedDocumentDigest;
    private String signatureAlgorithm;
    private String certificate;
    private Map<String, Object> timestampData;
}