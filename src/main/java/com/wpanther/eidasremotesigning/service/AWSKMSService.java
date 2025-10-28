package com.wpanther.eidasremotesigning.service;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import com.wpanther.eidasremotesigning.dto.AWSKMSKeyInfo;
import com.wpanther.eidasremotesigning.exception.SigningException;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DescribeKeyRequest;
import software.amazon.awssdk.services.kms.model.DescribeKeyResponse;
import software.amazon.awssdk.services.kms.model.GetPublicKeyRequest;
import software.amazon.awssdk.services.kms.model.GetPublicKeyResponse;
import software.amazon.awssdk.services.kms.model.KeyListEntry;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import software.amazon.awssdk.services.kms.model.ListKeysRequest;
import software.amazon.awssdk.services.kms.model.ListKeysResponse;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

/**
 * Service for interacting with AWS KMS for key management and signing operations
 */
@Service
@RequiredArgsConstructor
@Slf4j
@ConditionalOnProperty(name = "app.aws.kms.enabled", havingValue = "true")
public class AWSKMSService {

    private final KmsClient kmsClient;

    /**
     * Lists all asymmetric signing keys in AWS KMS
     *
     * @return List of key information objects
     */
    public List<AWSKMSKeyInfo> listSigningKeys() {
        try {
            List<AWSKMSKeyInfo> keys = new ArrayList<>();

            ListKeysRequest listKeysRequest = ListKeysRequest.builder()
                .limit(100)
                .build();

            ListKeysResponse listKeysResponse = kmsClient.listKeys(listKeysRequest);

            for (KeyListEntry keyEntry : listKeysResponse.keys()) {
                try {
                    // Get key metadata to filter for signing keys
                    DescribeKeyRequest describeRequest = DescribeKeyRequest.builder()
                        .keyId(keyEntry.keyId())
                        .build();

                    DescribeKeyResponse describeResponse = kmsClient.describeKey(describeRequest);

                    // Only include asymmetric signing keys
                    if (describeResponse.keyMetadata().keyUsage() == KeyUsageType.SIGN_VERIFY) {
                        AWSKMSKeyInfo keyInfo = AWSKMSKeyInfo.builder()
                            .keyId(keyEntry.keyId())
                            .keyArn(keyEntry.keyArn())
                            .description(describeResponse.keyMetadata().description())
                            .keySpec(describeResponse.keyMetadata().keySpec().toString())
                            .enabled(describeResponse.keyMetadata().enabled())
                            .creationDate(describeResponse.keyMetadata().creationDate())
                            .build();

                        keys.add(keyInfo);
                    }
                } catch (Exception e) {
                    log.warn("Could not describe key {}: {}", keyEntry.keyId(), e.getMessage());
                }
            }

            return keys;
        } catch (Exception e) {
            log.error("Failed to list keys from AWS KMS", e);
            throw new SigningException("Failed to list keys from AWS KMS: " + e.getMessage(), e);
        }
    }

    /**
     * Gets the public key for a KMS key
     *
     * @param keyId The KMS key ID or ARN
     * @return Base64-encoded public key in DER format
     */
    public String getPublicKey(String keyId) {
        try {
            GetPublicKeyRequest request = GetPublicKeyRequest.builder()
                .keyId(keyId)
                .build();

            GetPublicKeyResponse response = kmsClient.getPublicKey(request);

            // Return the public key in DER format (Base64 encoded)
            byte[] publicKeyBytes = response.publicKey().asByteArray();
            return Base64.getEncoder().encodeToString(publicKeyBytes);

        } catch (Exception e) {
            log.error("Failed to get public key from AWS KMS", e);
            throw new SigningException("Failed to get public key from AWS KMS: " + e.getMessage(), e);
        }
    }

    /**
     * Gets key information for a specific key
     *
     * @param keyId The KMS key ID or ARN
     * @return Key information
     */
    public AWSKMSKeyInfo getKeyInfo(String keyId) {
        try {
            DescribeKeyRequest request = DescribeKeyRequest.builder()
                .keyId(keyId)
                .build();

            DescribeKeyResponse response = kmsClient.describeKey(request);

            return AWSKMSKeyInfo.builder()
                .keyId(response.keyMetadata().keyId())
                .keyArn(response.keyMetadata().arn())
                .description(response.keyMetadata().description())
                .keySpec(response.keyMetadata().keySpec().toString())
                .enabled(response.keyMetadata().enabled())
                .creationDate(response.keyMetadata().creationDate())
                .build();

        } catch (Exception e) {
            log.error("Failed to get key info from AWS KMS", e);
            throw new SigningException("Failed to get key info from AWS KMS: " + e.getMessage(), e);
        }
    }

    /**
     * Signs a digest using AWS KMS
     *
     * @param keyId The KMS key ID or ARN
     * @param digest The digest bytes to sign
     * @param digestAlgorithm The digest algorithm (e.g., "SHA-256", "SHA-384", "SHA-512")
     * @param keyAlgorithm The key algorithm (e.g., "RSA", "EC")
     * @return The signature bytes
     */
    public byte[] signDigest(String keyId, byte[] digest, String digestAlgorithm, String keyAlgorithm) {
        try {
            // Determine the signing algorithm based on key type and digest
            SigningAlgorithmSpec signingAlgorithm = determineSigningAlgorithm(keyAlgorithm, digestAlgorithm);

            // Create the sign request with the digest
            SignRequest signRequest = SignRequest.builder()
                .keyId(keyId)
                .message(SdkBytes.fromByteArray(digest))
                .messageType(MessageType.DIGEST)  // Important: We're providing a digest, not the raw message
                .signingAlgorithm(signingAlgorithm)
                .build();

            SignResponse signResponse = kmsClient.sign(signRequest);

            return signResponse.signature().asByteArray();

        } catch (Exception e) {
            log.error("Failed to sign with AWS KMS", e);
            throw new SigningException("Failed to sign with AWS KMS: " + e.getMessage(), e);
        }
    }

    /**
     * Signs raw data using AWS KMS (KMS will hash it internally)
     *
     * @param keyId The KMS key ID or ARN
     * @param data The data bytes to sign
     * @param digestAlgorithm The digest algorithm (e.g., "SHA-256", "SHA-384", "SHA-512")
     * @param keyAlgorithm The key algorithm (e.g., "RSA", "EC")
     * @return The signature bytes
     */
    public byte[] signData(String keyId, byte[] data, String digestAlgorithm, String keyAlgorithm) {
        try {
            // Determine the signing algorithm based on key type and digest
            SigningAlgorithmSpec signingAlgorithm = determineSigningAlgorithm(keyAlgorithm, digestAlgorithm);

            // Create the sign request with raw data
            SignRequest signRequest = SignRequest.builder()
                .keyId(keyId)
                .message(SdkBytes.fromByteArray(data))
                .messageType(MessageType.RAW)  // KMS will hash the data
                .signingAlgorithm(signingAlgorithm)
                .build();

            SignResponse signResponse = kmsClient.sign(signRequest);

            return signResponse.signature().asByteArray();

        } catch (Exception e) {
            log.error("Failed to sign data with AWS KMS", e);
            throw new SigningException("Failed to sign data with AWS KMS: " + e.getMessage(), e);
        }
    }

    /**
     * Validates if a key exists and is enabled for signing
     *
     * @param keyId The KMS key ID or ARN
     * @return true if the key is valid and enabled
     */
    public boolean validateKey(String keyId) {
        try {
            DescribeKeyRequest request = DescribeKeyRequest.builder()
                .keyId(keyId)
                .build();

            DescribeKeyResponse response = kmsClient.describeKey(request);

            return response.keyMetadata().enabled()
                && response.keyMetadata().keyUsage() == KeyUsageType.SIGN_VERIFY;

        } catch (Exception e) {
            log.error("Failed to validate key in AWS KMS", e);
            return false;
        }
    }

    /**
     * Determines the AWS KMS signing algorithm based on key and digest algorithms
     *
     * @param keyAlgorithm The key algorithm (RSA or EC)
     * @param digestAlgorithm The digest algorithm
     * @return The appropriate SigningAlgorithmSpec
     */
    private SigningAlgorithmSpec determineSigningAlgorithm(String keyAlgorithm, String digestAlgorithm) {
        String normalizedKeyAlgo = keyAlgorithm.toUpperCase();
        String normalizedDigestAlgo = digestAlgorithm.toUpperCase().replace("-", "");

        if (normalizedKeyAlgo.equals("RSA")) {
            switch (normalizedDigestAlgo) {
                case "SHA256":
                    return SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256;
                case "SHA384":
                    return SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_384;
                case "SHA512":
                    return SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_512;
                default:
                    throw new SigningException("Unsupported digest algorithm for RSA: " + digestAlgorithm);
            }
        } else if (normalizedKeyAlgo.equals("EC") || normalizedKeyAlgo.equals("ECDSA")) {
            switch (normalizedDigestAlgo) {
                case "SHA256":
                    return SigningAlgorithmSpec.ECDSA_SHA_256;
                case "SHA384":
                    return SigningAlgorithmSpec.ECDSA_SHA_384;
                case "SHA512":
                    return SigningAlgorithmSpec.ECDSA_SHA_512;
                default:
                    throw new SigningException("Unsupported digest algorithm for ECDSA: " + digestAlgorithm);
            }
        } else {
            throw new SigningException("Unsupported key algorithm: " + keyAlgorithm);
        }
    }

    /**
     * Gets the key algorithm type from a KMS key
     *
     * @param keyId The KMS key ID or ARN
     * @return The key algorithm type (RSA or EC)
     */
    public String getKeyAlgorithmType(String keyId) {
        try {
            DescribeKeyRequest request = DescribeKeyRequest.builder()
                .keyId(keyId)
                .build();

            DescribeKeyResponse response = kmsClient.describeKey(request);
            KeySpec keySpec = response.keyMetadata().keySpec();

            // Determine if it's RSA or EC based on KeySpec
            if (keySpec.toString().startsWith("RSA")) {
                return "RSA";
            } else if (keySpec.toString().startsWith("ECC")) {
                return "EC";
            } else {
                throw new SigningException("Unsupported key spec: " + keySpec);
            }

        } catch (Exception e) {
            log.error("Failed to get key algorithm type from AWS KMS", e);
            throw new SigningException("Failed to get key algorithm type: " + e.getMessage(), e);
        }
    }
}
