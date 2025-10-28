package com.wpanther.eidasremotesigning.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;

/**
 * Configuration for AWS KMS integration
 */
@Configuration
@RequiredArgsConstructor
@Slf4j
public class AWSKMSConfig {

    @Value("${app.aws.kms.enabled:false}")
    private boolean kmsEnabled;

    @Value("${app.aws.kms.region:us-east-1}")
    private String awsRegion;

    @Value("${app.aws.kms.access-key-id:}")
    private String accessKeyId;

    @Value("${app.aws.kms.secret-access-key:}")
    private String secretAccessKey;

    @Value("${app.aws.kms.use-default-credentials:true}")
    private boolean useDefaultCredentials;

    /**
     * Creates AWS KMS client bean
     *
     * @return KmsClient instance configured with credentials and region
     */
    @Bean
    public KmsClient kmsClient() {
        if (!kmsEnabled) {
            log.info("AWS KMS is disabled. Skipping KMS client initialization.");
            return null;
        }

        try {
            log.info("Initializing AWS KMS client for region: {}", awsRegion);

            AwsCredentialsProvider credentialsProvider;

            if (useDefaultCredentials) {
                // Use default credential chain (IAM role, environment variables, etc.)
                log.info("Using AWS default credentials provider chain");
                credentialsProvider = DefaultCredentialsProvider.create();
            } else {
                // Use explicit credentials from configuration
                if (accessKeyId == null || accessKeyId.isEmpty()
                        || secretAccessKey == null || secretAccessKey.isEmpty()) {
                    throw new IllegalStateException(
                        "AWS credentials not configured. Set app.aws.kms.access-key-id and "
                        + "app.aws.kms.secret-access-key or enable use-default-credentials.");
                }
                log.info("Using static AWS credentials");
                credentialsProvider = StaticCredentialsProvider.create(
                    AwsBasicCredentials.create(accessKeyId, secretAccessKey)
                );
            }

            KmsClient client = KmsClient.builder()
                .region(Region.of(awsRegion))
                .credentialsProvider(credentialsProvider)
                .build();

            log.info("AWS KMS client initialized successfully");
            return client;

        } catch (Exception e) {
            log.error("Failed to initialize AWS KMS client", e);
            throw new RuntimeException("Could not initialize AWS KMS client: " + e.getMessage(), e);
        }
    }
}
