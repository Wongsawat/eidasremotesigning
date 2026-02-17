package com.wpanther.eidasremotesigning.service;

import com.wpanther.eidasremotesigning.dto.DigestSigningRequest;
import com.wpanther.eidasremotesigning.dto.csc.*;
import com.wpanther.eidasremotesigning.entity.AsyncOperation;
import com.wpanther.eidasremotesigning.entity.SigningCertificate;
import com.wpanther.eidasremotesigning.entity.TransactionAuthorization;
import com.wpanther.eidasremotesigning.exception.CertificateException;
import com.wpanther.eidasremotesigning.exception.SigningException;
import com.wpanther.eidasremotesigning.repository.OAuth2ClientRepository;
import com.wpanther.eidasremotesigning.repository.SigningCertificateRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

/**
 * Service implementing the Cloud Signature Consortium API v2.0 functionality
 */
@Service
@Slf4j
public class CSCApiService {

    private final SigningCertificateRepository certificateRepository;
    private final SigningCertificateService certificateService;
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private PKCS11Service pkcs11Service;
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private AWSKMSService awskmsService;
    private final EIDASComplianceService eidasComplianceService;
    private final SigningLogService signingLogService;
    private final OAuth2ClientRepository oauth2ClientRepository;
    private final AsyncOperationService asyncOperationService;
    private final CSCAuthorizationService cscAuthorizationService;

    private final Executor asyncExecutor;

    private int operationExpiryMinutes;

    public CSCApiService(SigningCertificateRepository certificateRepository,
                          SigningCertificateService certificateService,
                          EIDASComplianceService eidasComplianceService,
                          SigningLogService signingLogService,
                          OAuth2ClientRepository oauth2ClientRepository,
                          AsyncOperationService asyncOperationService,
                          CSCAuthorizationService cscAuthorizationService,
                          @Qualifier("asyncSigningExecutor") Executor asyncExecutor,
                          @Value("${app.async.operation-expiry-minutes:30}") int operationExpiryMinutes) {
        this.certificateRepository = certificateRepository;
        this.certificateService = certificateService;
        this.eidasComplianceService = eidasComplianceService;
        this.signingLogService = signingLogService;
        this.oauth2ClientRepository = oauth2ClientRepository;
        this.asyncOperationService = asyncOperationService;
        this.cscAuthorizationService = cscAuthorizationService;
        this.asyncExecutor = asyncExecutor;
        this.operationExpiryMinutes = operationExpiryMinutes;
    }

    private PKCS11Service requirePkcs11Service() {
        if (pkcs11Service == null) {
            throw new CertificateException("PKCS#11 is not enabled. Configure app.pkcs11.enabled=true and ensure SoftHSM is installed.");
        }
        return pkcs11Service;
    }

    /**
     * List credentials (certificates) available for the client
     */
    @Transactional(readOnly = true)
    public CSCCredentialsListResponse listCredentials(CSCCredentialsListRequest request) {
        try {
            String clientId = request.getClientId();

            // Get PIN from request if provided
            String pin = extractPinFromRequest(request);

            // Find all certificates for the client
            List<SigningCertificate> certificates = certificateRepository.findByClientId(clientId);

            // Convert to CSC certificate info
            List<CSCCertificateInfo> cscCertificates = new ArrayList<>();

            for (SigningCertificate cert : certificates) {
                try {
                    X509Certificate x509Cert;

                    if ("PKCS11".equals(cert.getStorageType())) {
                        // For PKCS#11 certs, we need the PIN
                        if (pin == null) {
                            // Skip PKCS#11 certs if no PIN provided, but continue with others
                            log.debug("Skipping PKCS#11 certificate (no PIN provided): {}", cert.getId());
                            continue;
                        }
                        x509Cert = requirePkcs11Service().getCertificate(cert.getCertificateAlias(), pin);
                    } else {
                        // For PKCS#12 certs
                        x509Cert = certificateService.loadCertificateFromKeystore(cert);
                    }

                    cscCertificates.add(mapToCscCertificateInfo(cert, x509Cert));
                } catch (Exception e) {
                    // Log error but continue with other certificates
                    log.error("Error loading certificate {}: {}", cert.getId(), e.getMessage());
                }
            }

            // Apply maxResults limit if provided
            if (request.getMaxResults() != null && request.getMaxResults() > 0 &&
                    cscCertificates.size() > request.getMaxResults()) {
                cscCertificates = cscCertificates.subList(0, request.getMaxResults());
            }

            return CSCCredentialsListResponse.builder()
                    .certificates(cscCertificates)
                    .build();
        } catch (Exception e) {
            log.error("Error in listCredentials", e);
            throw new CertificateException("Failed to list credentials: " + e.getMessage(), e);
        }
    }

    /**
     * Get detailed information about a specific credential (certificate)
     */
    @Transactional(readOnly = true)
    public CSCCertificateInfo getCredentialInfo(CSCCredentialsListRequest request, String credentialID) {
        try {
            String clientId = request.getClientId();
            String pin = extractPinFromRequest(request);

            // Find the certificate by ID and client ID
            SigningCertificate cert = certificateRepository.findByIdAndClientId(credentialID, clientId)
                    .orElseThrow(() -> new CertificateException("Certificate not found"));

            // Load the X509Certificate
            X509Certificate x509Cert;
            if ("PKCS11".equals(cert.getStorageType())) {
                // For PKCS#11, we need the PIN
                if (pin == null) {
                    throw new CertificateException("PIN is required for PKCS#11 certificate access");
                }
                x509Cert = requirePkcs11Service().getCertificate(cert.getCertificateAlias(), pin);
            } else {
                // For PKCS#12
                x509Cert = certificateService.loadCertificateFromKeystore(cert);
            }

            return mapToCscCertificateInfo(cert, x509Cert);
        } catch (CertificateException ce) {
            throw ce;
        } catch (Exception e) {
            log.error("Error in getCredentialInfo", e);
            throw new CertificateException("Failed to get credential info: " + e.getMessage(), e);
        }
    }

    /**
     * Sign hash(es) using the specified credential
     * Supports both synchronous and asynchronous modes
     */
    @Transactional
    public CSCSignatureResponse signHash(CSCSignatureRequest request) {
        // Check if async mode is requested
        if (Boolean.TRUE.equals(request.getAsync())) {
            return signHashAsync(request);
        }

        // Execute synchronously for backward compatibility
        return executeSignHash(request);
    }

    /**
     * Handle asynchronous signHash request
     * Creates an async operation and returns operationID immediately
     */
    private CSCSignatureResponse signHashAsync(CSCSignatureRequest request) {
        // Create async operation
        AsyncOperation operation = asyncOperationService.createOperation(
                request.getClientId(),
                AsyncOperationService.TYPE_SIGN_HASH,
                operationExpiryMinutes
        );

        // Submit async task
        CompletableFuture.runAsync(() -> executeAsyncSignHash(operation.getId(), request), asyncExecutor);

        // Return immediately with operationID
        return CSCSignatureResponse.builder()
                .operationID(operation.getId())
                .build();
    }

    /**
     * Execute signHash asynchronously in background thread
     * Updates AsyncOperation with result or error
     */
    @Async("asyncSigningExecutor")
    void executeAsyncSignHash(String operationId, CSCSignatureRequest request) {
        try {
            CSCSignatureResponse result = executeSignHash(request);
            asyncOperationService.updateOperationSuccess(operationId, result);
            log.info("Async signHash completed successfully: operationId={}", operationId);
        } catch (Exception e) {
            asyncOperationService.updateOperationFailure(operationId, e.getMessage());
            log.error("Async signHash failed: operationId={}", operationId, e);
        }
    }

    /**
     * Core logic for signing hash(es)
     * Shared by both sync and async execution paths
     */
    private CSCSignatureResponse executeSignHash(CSCSignatureRequest request) {
        try {
            String credentialID = request.getCredentialID();
            String pin = extractPinFromRequest(request);

            // Validate request
            if (request.getSignatureData() == null ||
                    request.getSignatureData().getHashToSign() == null ||
                    request.getSignatureData().getHashToSign().length == 0) {
                throw new SigningException("No hash values provided to sign");
            }

            // Either PIN or SAD is required
            if (request.getSAD() == null && (pin == null || pin.isEmpty())) {
                throw new SigningException("Either PIN or SAD is required for signing operations");
            }

            // Validate SAD if provided
            TransactionAuthorization transaction = null;
            if (request.getSAD() != null) {
                transaction = cscAuthorizationService.validateTransactionForSigningBySad(
                        request.getClientId(), request.getSAD());
                if (!transaction.getCertificateId().equals(credentialID)) {
                    throw new SigningException("Credential ID does not match authorized transaction");
                }
            }

            // Determine signature type from request if specified
            DigestSigningRequest.SignatureType signatureType = DigestSigningRequest.SignatureType.XADES;
            if (request.getSignatureData().getSignatureAttributes() != null &&
                    request.getSignatureData().getSignatureAttributes().getSignatureType() != null) {
                String requestedType = request.getSignatureData().getSignatureAttributes().getSignatureType();
                if ("PAdES".equalsIgnoreCase(requestedType)) {
                    signatureType = DigestSigningRequest.SignatureType.PADES;
                }
            }

            // Find the certificate (with client ownership check)
            SigningCertificate certEntity = certificateRepository.findByIdAndClientId(credentialID, request.getClientId())
                    .orElseThrow(() -> new SigningException("Certificate not found"));

            // Verify certificate is active
            if (!certEntity.isActive()) {
                throw new SigningException("Certificate is not active");
            }

            // Load certificate and private key based on storage type
            PrivateKey privateKey = null;
            X509Certificate certificate;

            if ("AWSKMS".equals(certEntity.getStorageType())) {
                // For AWS KMS, no private key needed
                if (awskmsService == null) {
                    throw new SigningException("AWS KMS is not enabled or configured");
                }
                certificate = certificateService.getCertificateWithX509(credentialID, null)
                        .getX509Certificate();
            } else {
                // For PKCS#11 and PKCS#12, PIN is required to load the private key
                if (pin == null || pin.isEmpty()) {
                    throw new SigningException("PIN is required for signing with " + certEntity.getStorageType() + " token");
                }
                privateKey = certificateService.getPrivateKey(credentialID, pin);
                certificate = certificateService.getCertificateWithX509(credentialID, pin)
                        .getX509Certificate();
            }

            // Validate hash algorithm
            String hashAlgo = request.getHashAlgo();
            if (!isValidHashAlgorithm(hashAlgo)) {
                throw new SigningException("Unsupported hash algorithm: " + hashAlgo);
            }

            // Create digest signing request for eIDAS compliance validation
            DigestSigningRequest validationRequest = DigestSigningRequest.builder()
                    .certificateId(credentialID)
                    .digestValue(request.getSignatureData().getHashToSign()[0]) // Use first hash for validation
                    .digestAlgorithm(hashAlgo)
                    .signatureType(signatureType)
                    .build();

            // Verify eIDAS compliance
            eidasComplianceService.validateEIDASCompliance(validationRequest, certificate);

            // Determine signature algorithm
            String keyAlgoForSig;
            if ("AWSKMS".equals(certEntity.getStorageType())) {
                keyAlgoForSig = awskmsService.getKeyAlgorithmType(certEntity.getKmsKeyId());
            } else {
                keyAlgoForSig = privateKey.getAlgorithm();
            }
            String signatureAlgorithm = determineSignatureAlgorithm(keyAlgoForSig, hashAlgo);

            // Results for multiple hash values
            String[] signatures = new String[request.getSignatureData().getHashToSign().length];
            String certBase64 = Base64.getEncoder().encodeToString(certificate.getEncoded());

            // Sign each hash
            for (int i = 0; i < request.getSignatureData().getHashToSign().length; i++) {
                String hashToSign = request.getSignatureData().getHashToSign()[i];

                // Decode the hash
                byte[] hashBytes = Base64.getDecoder().decode(hashToSign);

                byte[] signatureBytes;

                if ("AWSKMS".equals(certEntity.getStorageType())) {
                    // For AWS KMS, use the KMS service to sign
                    signatureBytes = awskmsService.signDigest(
                            certEntity.getKmsKeyId(),
                            hashBytes,
                            hashAlgo,
                            keyAlgoForSig);
                } else {
                    // Create signature instance with the appropriate provider
                    Signature signature;
                    if ("PKCS11".equals(certEntity.getStorageType())) {
                        // For PKCS#11, use the HSM provider
                        signature = Signature.getInstance(signatureAlgorithm, certEntity.getProviderName());
                    } else {
                        // For PKCS#12, use the default provider
                        signature = Signature.getInstance(signatureAlgorithm);
                    }

                    // Initialize the signature
                    signature.initSign(privateKey);

                    // Update with the hash value
                    signature.update(hashBytes);

                    // Generate the signature
                    signatureBytes = signature.sign();
                }

                // Encode the signature value
                signatures[i] = Base64.getEncoder().encodeToString(signatureBytes);

                // Create a digest signing request for logging
                DigestSigningRequest logRequest = DigestSigningRequest.builder()
                        .certificateId(credentialID)
                        .digestValue(hashToSign)
                        .digestAlgorithm(hashAlgo)
                        .signatureType(signatureType)
                        .build();

                // Log the successful signing operation
                signingLogService.logSuccessfulSigning(logRequest, signatureAlgorithm);
            }

            // Build and return CSC response
            return CSCSignatureResponse.builder()
                    .signatureAlgorithm(signatureAlgorithm)
                    .signatures(signatures)
                    .certificate(certBase64)
                    .build();
        } catch (SigningException se) {
            throw se;
        } catch (Exception e) {
            log.error("Error in signHash", e);
            throw new SigningException("Failed to sign hash: " + e.getMessage(), e);
        }
    }

    /**
     * Validates if the hash algorithm is supported
     */
    private boolean isValidHashAlgorithm(String algorithm) {
        String upperAlgo = algorithm.toUpperCase();
        return upperAlgo.equals("SHA-256") ||
                upperAlgo.equals("SHA-384") ||
                upperAlgo.equals("SHA-512");
    }

    /**
     * Determines the appropriate signature algorithm based on key and digest
     * algorithms
     */
    private String determineSignatureAlgorithm(String keyAlgorithm, String digestAlgorithm) {
        // Normalize input
        keyAlgorithm = keyAlgorithm.toUpperCase();
        digestAlgorithm = digestAlgorithm.toUpperCase();

        // Map to standard JCA signature algorithm identifiers
        if (keyAlgorithm.equals("RSA")) {
            switch (digestAlgorithm) {
                case "SHA-256":
                    return "SHA256withRSA";
                case "SHA-384":
                    return "SHA384withRSA";
                case "SHA-512":
                    return "SHA512withRSA";
                default:
                    throw new SigningException("Unsupported digest algorithm for RSA: " + digestAlgorithm);
            }
        } else if (keyAlgorithm.equals("EC")) {
            switch (digestAlgorithm) {
                case "SHA-256":
                    return "SHA256withECDSA";
                case "SHA-384":
                    return "SHA384withECDSA";
                case "SHA-512":
                    return "SHA512withECDSA";
                default:
                    throw new SigningException("Unsupported digest algorithm for ECDSA: " + digestAlgorithm);
            }
        } else {
            throw new SigningException("Unsupported key algorithm: " + keyAlgorithm);
        }
    }

    /**
     * Maps a certificate entity and X509Certificate to CSC certificate info format
     */
    private CSCCertificateInfo mapToCscCertificateInfo(SigningCertificate cert, X509Certificate x509Cert)
            throws Exception {
        // Extract certificate details
        String subject = x509Cert.getSubjectX500Principal().getName();
        String issuerDN = x509Cert.getIssuerX500Principal().getName();
        String serialNumber = x509Cert.getSerialNumber().toString();
        long validFrom = x509Cert.getNotBefore().getTime();
        long validTo = x509Cert.getNotAfter().getTime();
        String certBase64 = Base64.getEncoder().encodeToString(x509Cert.getEncoded());

        // Extract key information
        String keyAlgo = x509Cert.getPublicKey().getAlgorithm();
        Integer keyLength = getKeySize(x509Cert.getPublicKey());

        // Extract key usage if available
        String[] keyUsage = null;
        boolean[] keyUsageBits = x509Cert.getKeyUsage();
        if (keyUsageBits != null) {
            List<String> usages = new ArrayList<>();
            if (keyUsageBits[0])
                usages.add("digitalSignature");
            if (keyUsageBits[1])
                usages.add("nonRepudiation");
            if (keyUsageBits[2])
                usages.add("keyEncipherment");
            if (keyUsageBits[3])
                usages.add("dataEncipherment");
            if (keyUsageBits[4])
                usages.add("keyAgreement");
            if (keyUsageBits[5])
                usages.add("keyCertSign");
            if (keyUsageBits[6])
                usages.add("cRLSign");
            keyUsage = usages.toArray(new String[0]);
        }

        // Build certificate details
        CSCCertificateInfo.CSCCertificateDetails certDetails = CSCCertificateInfo.CSCCertificateDetails.builder()
                .subject(subject)
                .issuerDN(issuerDN)
                .serialNumber(serialNumber)
                .keyUsage(keyUsage)
                .validFrom(validFrom)
                .validTo(validTo)
                .certificate(certBase64)
                .build();

        // Build key info
        CSCCertificateInfo.CSCKeyInfo keyInfo = CSCCertificateInfo.CSCKeyInfo.builder()
                .algo(keyAlgo)
                .length(keyLength)
                .build();

        // Build PIN info
        CSCCertificateInfo.CSCPINInfo pinInfo = CSCCertificateInfo.CSCPINInfo.builder()
                .presence("PKCS11".equals(cert.getStorageType()) ? "mandatory" : "notRequired")
                .format("numeric")
                .label("HSM PIN")
                .description("PIN for accessing the PKCS#11 token")
                .build();

        // Build and return complete certificate info
        return CSCCertificateInfo.builder()
                .id(cert.getId())
                .status(cert.isActive() ? "ACTIVE" : "SUSPENDED")
                .cert(certDetails)
                .key(keyInfo)
                .pin(pinInfo)
                .authMode("explicit")
                .build();
    }

    /**
     * Extracts PIN from CSC request
     */
    private String extractPinFromRequest(CSCSignatureRequest request) {
        if (request.getCredentials() != null &&
                request.getCredentials().getPin() != null &&
                request.getCredentials().getPin().getValue() != null) {
            return request.getCredentials().getPin().getValue();
        }
        return null;
    }

    /**
     * Extracts PIN from CSC request
     */
    private String extractPinFromRequest(CSCCredentialsListRequest request) {
        if (request.getCredentials() != null &&
                request.getCredentials().getPin() != null &&
                request.getCredentials().getPin().getValue() != null) {
            return request.getCredentials().getPin().getValue();
        }
        return null;
    }

        /**
     * Associates an existing PKCS#11 certificate with a client
     * @param request The association request
     * @return The associated certificate info
     */
    @Transactional
    public CSCCertificateInfo associateCertificate(CSCAssociateCertificateRequest request) {
        try {
            String clientId = request.getClientId();
            String pin = extractPinFromRequest(request);
            
            if (pin == null || pin.isEmpty()) {
                throw new CertificateException("PIN is required to access PKCS#11 token");
            }
            
            // Verify client exists
            if (!oauth2ClientRepository.existsByClientId(clientId)) {
                throw new CertificateException("Invalid OAuth2 client ID. Client does not exist.");
            }
            
            // Verify certificate exists in the HSM
            X509Certificate certificate = requirePkcs11Service().getCertificate(request.getCertificateAlias(), pin);
            
            // Verify private key is available
            if (!requirePkcs11Service().validateCertificateAndKey(request.getCertificateAlias(), pin)) {
                throw new CertificateException("Private key not found for certificate with alias: " + request.getCertificateAlias());
            }
            
            // Create entity for the certificate association
            SigningCertificate certEntity = SigningCertificate.builder()
                .id(UUID.randomUUID().toString())
                .description(request.getDescription())
                .storageType("PKCS11")
                .certificateAlias(request.getCertificateAlias())
                .providerName(requirePkcs11Service().getProviderName())
                .slotId(request.getSlotId())
                .active(true)
                .clientId(clientId)
                .createdAt(Instant.now())
                .build();
                
            certificateRepository.save(certEntity);
            
            // Map to CSC certificate info format
            return mapToCscCertificateInfo(certEntity, certificate);
        } catch (Exception e) {
            log.error("Error associating certificate", e);
            throw new CertificateException("Failed to associate PKCS#11 certificate: " + e.getMessage(), e);
        }
    }

    /**
     * Extracts PIN from CSC association request
     */
    private String extractPinFromRequest(CSCAssociateCertificateRequest request) {
        if (request.getCredentials() != null && 
            request.getCredentials().getPin() != null && 
            request.getCredentials().getPin().getValue() != null) {
            return request.getCredentials().getPin().getValue();
        }
        return null;
    }

    /**
     * Estimates the key size based on the public key
     */
    private int getKeySize(java.security.PublicKey publicKey) {
        if (publicKey instanceof java.security.interfaces.RSAPublicKey) {
            return ((java.security.interfaces.RSAPublicKey) publicKey).getModulus().bitLength();
        } else if (publicKey instanceof java.security.interfaces.ECPublicKey) {
            // For EC keys, we estimate based on field size
            return ((java.security.interfaces.ECPublicKey) publicKey).getParams().getOrder().bitLength();
        }
        return 0; // Unknown key type
    }
}