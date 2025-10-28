package com.wpanther.eidasremotesigning.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request DTO for associating an AWS KMS key with a certificate
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AWSKMSCertificateAssociateRequest {

    /**
     * The AWS KMS key ID or ARN
     */
    private String kmsKeyId;

    /**
     * The X.509 certificate in Base64-encoded DER format
     * This certificate's public key should match the KMS key's public key
     */
    private String certificateBase64;

    /**
     * Optional description for the certificate
     */
    private String description;

    /**
     * AWS region where the KMS key is located (optional if using default region)
     */
    private String awsRegion;
}
