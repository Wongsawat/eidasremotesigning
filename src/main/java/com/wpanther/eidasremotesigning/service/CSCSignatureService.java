package com.wpanther.eidasremotesigning.service;

import com.wpanther.eidasremotesigning.dto.DigestSigningRequest;
import com.wpanther.eidasremotesigning.dto.csc.*;
import com.wpanther.eidasremotesigning.entity.SigningCertificate;
import com.wpanther.eidasremotesigning.entity.SigningLog;
import com.wpanther.eidasremotesigning.entity.TransactionAuthorization;
import com.wpanther.eidasremotesigning.exception.SigningException;
import com.wpanther.eidasremotesigning.repository.SigningCertificateRepository;
import com.wpanther.eidasremotesigning.repository.SigningLogRepository;
import com.wpanther.eidasremotesigning.util.DocumentFormatUtil;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import lombok.Builder;
import lombok.Data;

/**
 * Service implementing advanced CSC API signature operations
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CSCSignatureService {

    private final SigningCertificateRepository certificateRepository;
    private final SigningCertificateService certificateService;
    private final SigningLogService signingLogService;
    private final SigningLogRepository signingLogRepository;
    private final CSCAuthorizationService cscAuthorizationService;
    private final EIDASComplianceService eidasComplianceService;
    private final DocumentFormatUtil documentFormatUtil;
    
    // TSP timestamp service URL
    @Value("${app.tsp.url:http://tsa.belgium.be/connect}")
    private String tspUrl;
    
    // Cache of ongoing asynchronous signing operations
    private final Map<String, SigningOperation> ongoingOperations = new ConcurrentHashMap<>();
    
    /**
     * Sign a complete document instead of just a hash
     */
    @Transactional
    public CSCSignDocumentResponse signDocument(CSCSignDocumentRequest request) {
        try {
            String clientId = request.getClientId();
            String credentialId = request.getCredentialID();
            String pin = extractPinFromRequest(request);
            String transactionId = UUID.randomUUID().toString();
            
            // Check if we have a SAD or PIN
            if (request.getSAD() == null && pin == null) {
                throw new SigningException("Either PIN or SAD is required for signing operations");
            }
            
            // If SAD is provided, validate transaction
            TransactionAuthorization transaction = null;
            if (request.getSAD() != null) {
                transaction = cscAuthorizationService.validateTransactionForSigning(
                        clientId, request.getSAD(), null);
                
                // Make sure the credential IDs match
                if (!transaction.getCertificateId().equals(credentialId)) {
                    throw new SigningException("Credential ID does not match authorized transaction");
                }
            }
            
            // Find the certificate
            SigningCertificate certEntity = certificateRepository.findById(credentialId)
                    .orElseThrow(() -> new SigningException("Certificate not found"));
            
            // Verify certificate is active
            if (!certEntity.isActive()) {
                throw new SigningException("Certificate is not active");
            }
            
            // Get the certificate and private key
            X509Certificate certificate;
            PrivateKey privateKey;
            
            if (pin != null) {
                // Load using PIN
                certificate = certificateService.getCertificateWithX509(credentialId, pin)
                        .getX509Certificate();
                privateKey = certificateService.getPrivateKey(credentialId, pin);
            } else {
                // We should have a transaction with SAD already validated
                if (transaction == null) {
                    throw new SigningException("Internal error: No transaction with valid SAD");
                }
                
                // We need the PIN from the request in this case
                if (request.getCredentials() == null || 
                    request.getCredentials().getPin() == null ||
                    request.getCredentials().getPin().getValue() == null) {
                    throw new SigningException("PIN is required for signing with PKCS#11 token");
                }
                
                String tokenPin = request.getCredentials().getPin().getValue();
                certificate = certificateService.getCertificateWithX509(credentialId, tokenPin)
                        .getX509Certificate();
                privateKey = certificateService.getPrivateKey(credentialId, tokenPin);
            }
            
            // Validate hash algorithm
            String hashAlgo = request.getHashAlgo();
            if (!isValidHashAlgorithm(hashAlgo)) {
                throw new SigningException("Unsupported hash algorithm: " + hashAlgo);
            }
            
            // Determine signature type from request
            DigestSigningRequest.SignatureType signatureType = DigestSigningRequest.SignatureType.XADES;
            if (request.getSignatureAttributes() != null &&
                request.getSignatureAttributes().getSignatureType() != null) {
                String requestedType = request.getSignatureAttributes().getSignatureType();
                if ("PAdES".equalsIgnoreCase(requestedType)) {
                    signatureType = DigestSigningRequest.SignatureType.PADES;
                }
            }
            
            // Create digest signing request for eIDAS compliance validation
            DigestSigningRequest validationRequest = DigestSigningRequest.builder()
                    .certificateId(credentialId)
                    .digestValue(request.getDocumentDigest())
                    .digestAlgorithm(hashAlgo)
                    .signatureType(signatureType)
                    .build();
            
            // Verify eIDAS compliance
            eidasComplianceService.validateEIDASCompliance(validationRequest, certificate);
            
            // Determine signature algorithm
            String signatureAlgorithm = determineSignatureAlgorithm(
                    privateKey.getAlgorithm(),
                    hashAlgo);
            
            // For document signing, we need to check if the document is provided or just the digest
            boolean isDocumentProvided = request.getDocument() != null && !request.getDocument().isEmpty();
            byte[] documentBytes = null;
            byte[] digestBytes = null;
            
            if (isDocumentProvided) {
                // Decode document
                documentBytes = Base64.getDecoder().decode(request.getDocument());
                
                // Calculate digest for verification
                MessageDigest digest = MessageDigest.getInstance(hashAlgo);
                digestBytes = digest.digest(documentBytes);
                
                // Compare with provided digest if available
                if (request.getDocumentDigest() != null) {
                    byte[] providedDigest = Base64.getDecoder().decode(request.getDocumentDigest());
                    if (!MessageDigest.isEqual(digestBytes, providedDigest)) {
                        throw new SigningException("Document digest does not match the calculated digest");
                    }
                }
            } else {
                // Use provided digest
                if (request.getDocumentDigest() == null) {
                    throw new SigningException("Either document or documentDigest must be provided");
                }
                digestBytes = Base64.getDecoder().decode(request.getDocumentDigest());
            }
            
            // Create signature
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
            
            // Update with the digest value
            signature.update(digestBytes);
            
            // Generate the signature
            byte[] signatureBytes = signature.sign();
            
            // This would be replaced with actual document signing for PDF/XML documents
            // Here we're just implementing the basic functionality
            
            // For document signing in a production environment, you would:
            // 1. Use DSS library to create proper PAdES/XAdES signatures
            // 2. Apply the signature to the document
            // 3. Return the fully signed document
            
            // Generate timestamp if requested
            Map<String, Object> timestampData = null;
            if (request.getSignatureOptions() != null && 
                request.getSignatureOptions().getServerTimestamp() != null &&
                "true".equalsIgnoreCase(request.getSignatureOptions().getServerTimestamp())) {
                
                timestampData = createTimestampData(digestBytes, hashAlgo);
            }
            
            // Log the successful signing operation
            signingLogService.logSuccessfulSigning(validationRequest, signatureAlgorithm);
            
            // Base64 encode the signature
            String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);
            String certificateBase64 = Base64.getEncoder().encodeToString(certificate.getEncoded());
            
            // Return response with signature
            return CSCSignDocumentResponse.builder()
                    .transactionID(transactionId)
                    .signedDocumentDigest(Base64.getEncoder().encodeToString(digestBytes))
                    .signatureAlgorithm(signatureAlgorithm)
                    .certificate(certificateBase64)
                    .timestampData(timestampData)
                    .build();
            
        } catch (SigningException se) {
            throw se;
        } catch (Exception e) {
            log.error("Error in signDocument", e);
            throw new SigningException("Failed to sign document: " + e.getMessage(), e);
        }
    }
    
    /**
     * Get the status of an asynchronous signing operation
     */
    @Transactional(readOnly = true)
    public CSCSignatureStatusResponse getSignatureStatus(CSCSignatureStatusRequest request) {
        try {
            String clientId = request.getClientId();
            String transactionId = request.getTransactionID();
            
            // Check if we have this transaction in our cache
            SigningOperation operation = ongoingOperations.get(transactionId);
            
            if (operation == null) {
                // Check if we have a completed operation in the database
                SigningLog log = signingLogRepository.findById(transactionId)
                        .orElseThrow(() -> new SigningException("Signature transaction not found"));
                
                // Check if the operation belongs to this client
                if (!log.getClientId().equals(clientId)) {
                    throw new SigningException("Signature transaction not found for this client");
                }
                
                // Determine status
                String status = "SUCCESS".equals(log.getStatus()) ? "COMPLETED" : "FAILED";
                String errorMessage = "FAILED".equals(log.getStatus()) ? log.getErrorMessage() : null;
                
                return CSCSignatureStatusResponse.builder()
                        .status(status)
                        .errorMessage(errorMessage)
                        .build();
            }
            
            // Check if the operation belongs to this client
            if (!operation.getClientId().equals(clientId)) {
                throw new SigningException("Signature transaction not found for this client");
            }
            
            // Return current status
            return CSCSignatureStatusResponse.builder()
                    .status(operation.getStatus())
                    .errorMessage(operation.getErrorMessage())
                    .build();
            
        } catch (Exception e) {
            log.error("Error in getSignatureStatus", e);
            throw new SigningException("Failed to get signature status: " + e.getMessage(), e);
        }
    }
    
    /**
     * Create a timestamp for a document or hash
     */
    @Transactional
    public CSCTimestampResponse createTimestamp(CSCTimestampRequest request) {
        try {
            String clientId = request.getClientId();
            String hashAlgo = request.getHashAlgo();
            
            // Validate hash algorithm
            if (!isValidHashAlgorithm(hashAlgo)) {
                throw new SigningException("Unsupported hash algorithm: " + hashAlgo);
            }
            
            byte[] digestBytes;
            
            // Either document or digest must be provided
            if (request.getDocumentDigest() != null) {
                // Use provided digest
                digestBytes = Base64.getDecoder().decode(request.getDocumentDigest());
            } else if (request.getDocument() != null) {
                // Calculate digest from document
                byte[] documentBytes = Base64.getDecoder().decode(request.getDocument());
                MessageDigest digest = MessageDigest.getInstance(hashAlgo);
                digestBytes = digest.digest(documentBytes);
            } else {
                throw new SigningException("Either document or documentDigest must be provided");
            }
            
            // Create TSP source
            OnlineTSPSource tspSource = new OnlineTSPSource(tspUrl);
            
            // Create a DSS document from the digest
            DigestAlgorithm digestAlgorithm = mapHashAlgorithm(hashAlgo);
            
            // Get timestamp token using the correct method
            TimestampBinary timeStampToken = 
                    tspSource.getTimeStampResponse(digestAlgorithm, digestBytes);
            
            byte[] timestampTokenBytes = timeStampToken.getBytes();
            
            String timestampToken = Base64.getEncoder().encodeToString(timestampTokenBytes);
            String timestampDigest = Base64.getEncoder().encodeToString(digestBytes);
            
            // Return response
            return CSCTimestampResponse.builder()
                    .timestampToken(timestampToken)
                    .timestampDigest(timestampDigest)
                    .timestampGenerationTime(Instant.now().toEpochMilli())
                    .build();
            
        } catch (Exception e) {
            log.error("Error in createTimestamp", e);
            throw new SigningException("Failed to create timestamp: " + e.getMessage(), e);
        }
    }
    
    /**
     * Create timestamp data for signing responses
     */
    private Map<String, Object> createTimestampData(byte[] digest, String hashAlgo) {
        try {
            // Create TSP source
            OnlineTSPSource tspSource = new OnlineTSPSource(tspUrl);
            
            // Map hash algorithm
            DigestAlgorithm digestAlgorithm = mapHashAlgorithm(hashAlgo);
            
            // Get timestamp token
            // Using the correct method from OnlineTSPSource
            TimestampBinary timeStampToken = 
                    tspSource.getTimeStampResponse(digestAlgorithm, digest);
            
            byte[] timestampTokenBytes = timeStampToken.getBytes();
            
            // Create response data
            Map<String, Object> timestampData = new HashMap<>();
            timestampData.put("timestamp", Base64.getEncoder().encodeToString(timestampTokenBytes));
            timestampData.put("timestampGenerationTime", Instant.now().toEpochMilli());
            
            return timestampData;
        } catch (Exception e) {
            log.warn("Failed to create timestamp data: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * Maps a hash algorithm name to DSS DigestAlgorithm enum
     */
    private DigestAlgorithm mapHashAlgorithm(String hashAlgo) {
        String normalized = hashAlgo.toUpperCase().replace("-", "");
        
        switch (normalized) {
            case "SHA256":
                return DigestAlgorithm.SHA256;
            case "SHA384":
                return DigestAlgorithm.SHA384;
            case "SHA512":
                return DigestAlgorithm.SHA512;
            default:
                throw new SigningException("Unsupported hash algorithm for timestamping: " + hashAlgo);
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
     * Determines the appropriate signature algorithm based on key and digest algorithms
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
     * Extracts PIN from CSC request
     */
    private String extractPinFromRequest(CSCSignDocumentRequest request) {
        if (request.getCredentials() != null && 
            request.getCredentials().getPin() != null && 
            request.getCredentials().getPin().getValue() != null) {
            return request.getCredentials().getPin().getValue();
        }
        return null;
    }
    
    /**
     * Internal class for tracking asynchronous signing operations
     */
    @Data
    @Builder
    private static class SigningOperation {
        private String id;
        private String clientId;
        private String status;
        private String errorMessage;
        private Instant createdAt;
        private Instant updatedAt;
        private byte[] signatureResult;
    }
}