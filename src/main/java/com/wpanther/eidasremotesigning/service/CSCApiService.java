package com.wpanther.eidasremotesigning.service;

import com.wpanther.eidasremotesigning.dto.DigestSigningRequest;
import com.wpanther.eidasremotesigning.dto.csc.*;
import com.wpanther.eidasremotesigning.entity.SigningCertificate;
import com.wpanther.eidasremotesigning.exception.CertificateException;
import com.wpanther.eidasremotesigning.exception.SigningException;
import com.wpanther.eidasremotesigning.repository.SigningCertificateRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Service implementing the Cloud Signature Consortium API v2.0 functionality
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CSCApiService {

    private final SigningCertificateRepository certificateRepository;
    private final SigningCertificateService certificateService;
    private final PKCS11Service pkcs11Service;
    private final EIDASComplianceService eidasComplianceService;
    private final SigningLogService signingLogService;

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
                        x509Cert = pkcs11Service.getCertificate(cert.getCertificateAlias(), pin);
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
                x509Cert = pkcs11Service.getCertificate(cert.getCertificateAlias(), pin);
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
     */
    @Transactional
    public CSCSignatureResponse signHash(CSCSignatureRequest request) {
        try {
            String clientId = request.getClientId();
            String credentialID = request.getCredentialID();
            String pin = extractPinFromRequest(request);
            
            // Validate request
            if (request.getSignatureData() == null || 
                request.getSignatureData().getHashToSign() == null ||
                request.getSignatureData().getHashToSign().length == 0) {
                throw new SigningException("No hash values provided to sign");
            }
            
            if (pin == null || pin.isEmpty()) {
                throw new SigningException("PIN is required for signing operations");
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
            
            // Find the certificate
            SigningCertificate certEntity = certificateRepository.findById(credentialID)
                .orElseThrow(() -> new SigningException("Certificate not found"));
                
            // Verify certificate is active
            if (!certEntity.isActive()) {
                throw new SigningException("Certificate is not active");
            }
            
            // Load certificate and private key
            PrivateKey privateKey = certificateService.getPrivateKey(credentialID, pin);
            X509Certificate certificate = certificateService.getCertificateWithX509(credentialID, pin).getX509Certificate();
            
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
            String signatureAlgorithm = determineSignatureAlgorithm(
                privateKey.getAlgorithm(), 
                hashAlgo
            );
            
            // Results for multiple hash values
            String[] signatures = new String[request.getSignatureData().getHashToSign().length];
            String certBase64 = Base64.getEncoder().encodeToString(certificate.getEncoded());
            
            // Sign each hash
            for (int i = 0; i < request.getSignatureData().getHashToSign().length; i++) {
                String hashToSign = request.getSignatureData().getHashToSign()[i];
                
                // Decode the hash
                byte[] hashBytes = Base64.getDecoder().decode(hashToSign);
                
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
                byte[] signatureBytes = signature.sign();
                
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
     * Maps a certificate entity and X509Certificate to CSC certificate info format
     */
    private CSCCertificateInfo mapToCscCertificateInfo(SigningCertificate cert, X509Certificate x509Cert) throws Exception {
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
            if (keyUsageBits[0]) usages.add("digitalSignature");
            if (keyUsageBits[1]) usages.add("nonRepudiation");
            if (keyUsageBits[2]) usages.add("keyEncipherment");
            if (keyUsageBits[3]) usages.add("dataEncipherment");
            if (keyUsageBits[4]) usages.add("keyAgreement");
            if (keyUsageBits[5]) usages.add("keyCertSign");
            if (keyUsageBits[6]) usages.add("cRLSign");
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