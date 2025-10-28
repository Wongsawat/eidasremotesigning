package com.wpanther.eidasremotesigning.dto;

import java.time.Instant;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for AWS KMS key information
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AWSKMSKeyInfo {

    /**
     * The globally unique identifier for the KMS key
     */
    private String keyId;

    /**
     * The Amazon Resource Name (ARN) of the KMS key
     */
    private String keyArn;

    /**
     * Description of the key
     */
    private String description;

    /**
     * The key spec (e.g., RSA_2048, RSA_4096, ECC_NIST_P256)
     */
    private String keySpec;

    /**
     * Whether the key is enabled
     */
    private Boolean enabled;

    /**
     * When the key was created
     */
    private Instant creationDate;
}
