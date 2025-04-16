package com.wpanther.eidasremotesigning.service;

import com.wpanther.eidasremotesigning.dto.csc.*;
import com.wpanther.eidasremotesigning.entity.SigningCertificate;
import com.wpanther.eidasremotesigning.entity.TransactionAuthorization;
import com.wpanther.eidasremotesigning.exception.CertificateException;
import com.wpanther.eidasremotesigning.exception.SigningException;
import com.wpanther.eidasremotesigning.repository.SigningCertificateRepository;
import com.wpanther.eidasremotesigning.repository.TransactionAuthorizationRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/**
 * Service implementing the CSC API credential authorization functionality
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CSCAuthorizationService {

    private final SigningCertificateRepository certificateRepository;
    private final TransactionAuthorizationRepository transactionRepository;
    private final SecureRandom secureRandom;
    
    // Default transaction validity period in seconds (15 minutes)
    private static final long DEFAULT_VALIDITY_PERIOD = 15 * 60;
    
    // Maximum validity period in seconds (1 hour)
    private static final long MAX_VALIDITY_PERIOD = 60 * 60;

    /**
     * Authorizes a credential for signing operations
     */
    @Transactional
    public CSCAuthorizeResponse authorizeCredential(CSCAuthorizeRequest request) {
        try {
            String clientId = request.getClientId();
            String credentialId = request.getCredentialID();
            
            // Verify credential exists and belongs to client
            SigningCertificate certificate = certificateRepository.findByIdAndClientId(credentialId, clientId)
                    .orElseThrow(() -> new CertificateException("Certificate not found"));
            
            // Determine validity period
            long validityPeriod = request.getValidityPeriod() != null 
                    ? Math.min(request.getValidityPeriod(), MAX_VALIDITY_PERIOD)
                    : DEFAULT_VALIDITY_PERIOD;
            
            // Generate transaction ID
            String transactionId = UUID.randomUUID().toString();
            
            // Generate Signature Activation Data (SAD) - a secure token for signing
            String sad = generateSignatureActivationData();
            
            // Create expiration time
            Instant expiresAt = Instant.now().plusSeconds(validityPeriod);
            
            // Set up transaction authorization
            TransactionAuthorization transaction = TransactionAuthorization.builder()
                    .id(transactionId)
                    .clientId(clientId)
                    .certificateId(credentialId)
                    .sad(sad)
                    .numSignatures(parseNumSignatures(request.getNumSignatures()))
                    .remainingSignatures(parseNumSignatures(request.getNumSignatures()))
                    .description(request.getDescription())
                    .status("AUTHORIZATION_INITIALIZED")
                    .createdAt(Instant.now())
                    .expiresAt(expiresAt)
                    .build();
            
            transactionRepository.save(transaction);
            log.debug("Created transaction authorization: {}", transactionId);
            
            // For PKCS#11 tokens, we use explicit authentication
            // For PKCS#12, we could use implicit if the client has already provided a password
            String authMode = "PKCS11".equals(certificate.getStorageType()) ? "explicit" : "implicit";
            
            // Build and return response
            return CSCAuthorizeResponse.builder()
                    .transactionID(transactionId)
                    .SAD(sad)
                    .expiresIn(validityPeriod)
                    .authMode(authMode)
                    .build();
            
        } catch (Exception e) {
            log.error("Failed to authorize credential", e);
            throw new SigningException("Failed to authorize credential: " + e.getMessage(), e);
        }
    }
    
    /**
     * Extends the validity period of a transaction
     */
    @Transactional
    public CSCExtendTransactionResponse extendTransaction(CSCExtendTransactionRequest request) {
        try {
            String clientId = request.getClientId();
            String transactionId = request.getTransactionID();
            
            // Find transaction
            TransactionAuthorization transaction = transactionRepository.findByIdAndClientId(transactionId, clientId)
                    .orElseThrow(() -> new SigningException("Transaction not found"));
            
            // Check if transaction has expired
            if (transaction.getExpiresAt().isBefore(Instant.now())) {
                throw new SigningException("Transaction has expired");
            }
            
            // Check if transaction is in a valid state
            if (!"AUTHORIZATION_INITIALIZED".equals(transaction.getStatus()) && 
                !"AUTHORIZED".equals(transaction.getStatus())) {
                throw new SigningException("Transaction cannot be extended in current state: " + transaction.getStatus());
            }
            
            // Extend the transaction by the default validity period
            Instant newExpiresAt = Instant.now().plusSeconds(DEFAULT_VALIDITY_PERIOD);
            transaction.setExpiresAt(newExpiresAt);
            
            transactionRepository.save(transaction);
            log.debug("Extended transaction authorization: {}", transactionId);
            
            // Calculate expires in time in seconds
            long expiresIn = DEFAULT_VALIDITY_PERIOD;
            
            return CSCExtendTransactionResponse.builder()
                    .expiresIn(expiresIn)
                    .build();
            
        } catch (Exception e) {
            log.error("Failed to extend transaction", e);
            throw new SigningException("Failed to extend transaction: " + e.getMessage(), e);
        }
    }
    
    /**
     * Gets the current status of a credential authorization
     */
    @Transactional(readOnly = true)
    public CSCAuthorizeStatusResponse getAuthorizeStatus(CSCAuthorizeStatusRequest request) {
        try {
            String clientId = request.getClientId();
            String transactionId = request.getTransactionID();
            
            // Find transaction
            TransactionAuthorization transaction = transactionRepository.findByIdAndClientId(transactionId, clientId)
                    .orElseThrow(() -> new SigningException("Transaction not found"));
            
            // Check expiration
            boolean isExpired = transaction.getExpiresAt().isBefore(Instant.now());
            
            // Determine status
            String status;
            if (isExpired) {
                status = "EXPIRED";
            } else {
                status = transaction.getStatus();
            }
            
            // Find associated certificate
            SigningCertificate certificate = certificateRepository.findById(transaction.getCertificateId())
                    .orElseThrow(() -> new CertificateException("Certificate not found"));
            
            // Calculate expires in time in seconds
            long expiresIn = 0;
            if (!isExpired) {
                expiresIn = transaction.getExpiresAt().getEpochSecond() - Instant.now().getEpochSecond();
                if (expiresIn < 0) expiresIn = 0;
            }
            
            // Determine auth mode
            String authMode = "PKCS11".equals(certificate.getStorageType()) ? "explicit" : "implicit";
            
            return CSCAuthorizeStatusResponse.builder()
                    .credentialID(transaction.getCertificateId())
                    .status(status)
                    .SAD(isExpired ? null : transaction.getSad())
                    .expiresIn(isExpired ? 0 : expiresIn)
                    .authMode(authMode)
                    .build();
            
        } catch (Exception e) {
            log.error("Failed to get authorization status", e);
            throw new SigningException("Failed to get authorization status: " + e.getMessage(), e);
        }
    }
    
    /**
     * Updates a transaction status
     */
    @Transactional
    public void updateTransactionStatus(String transactionId, String status) {
        TransactionAuthorization transaction = transactionRepository.findById(transactionId)
                .orElseThrow(() -> new SigningException("Transaction not found"));
        
        transaction.setStatus(status);
        transactionRepository.save(transaction);
    }
    
    /**
     * Validates a transaction for signing operation
     */
    @Transactional
    public TransactionAuthorization validateTransactionForSigning(String clientId, String transactionId, String sad) {
        TransactionAuthorization transaction = transactionRepository.findByIdAndClientId(transactionId, clientId)
                .orElseThrow(() -> new SigningException("Transaction not found"));
        
        // Check if transaction has expired
        if (transaction.getExpiresAt().isBefore(Instant.now())) {
            throw new SigningException("Transaction has expired");
        }
        
        // Check SAD if provided
        if (sad != null && !sad.equals(transaction.getSad())) {
            throw new SigningException("Invalid Signature Activation Data (SAD)");
        }
        
        // Check if transaction is in valid state
        if (!"AUTHORIZATION_INITIALIZED".equals(transaction.getStatus()) && 
            !"AUTHORIZED".equals(transaction.getStatus())) {
            throw new SigningException("Transaction is not in a valid state for signing: " + transaction.getStatus());
        }
        
        // Check remaining signatures
        if (transaction.getRemainingSignatures() != null && transaction.getRemainingSignatures() <= 0) {
            throw new SigningException("No remaining signatures allowed for this transaction");
        }
        
        // Update state if needed
        if ("AUTHORIZATION_INITIALIZED".equals(transaction.getStatus())) {
            transaction.setStatus("AUTHORIZED");
        }
        
        // Decrement remaining signatures if tracked
        if (transaction.getRemainingSignatures() != null) {
            transaction.setRemainingSignatures(transaction.getRemainingSignatures() - 1);
        }
        
        transactionRepository.save(transaction);
        return transaction;
    }
    
    /**
     * Generates a secure Signature Activation Data token
     */
    private String generateSignatureActivationData() {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
    
    /**
     * Parses the numSignatures parameter from the request
     * Returns null for unlimited signatures, or the specified number
     */
    private Integer parseNumSignatures(String numSignatures) {
        if (numSignatures == null || numSignatures.isEmpty()) {
            return null; // Unlimited
        }
        
        try {
            return Integer.parseInt(numSignatures);
        } catch (NumberFormatException e) {
            log.warn("Invalid numSignatures value: {}", numSignatures);
            return null; // Default to unlimited on parsing error
        }
    }
}