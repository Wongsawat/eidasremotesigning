package com.wpanther.eidasremotesigning.service;

import com.wpanther.eidasremotesigning.dto.DigestSigningRequest;
import com.wpanther.eidasremotesigning.dto.DigestSigningResponse;
import com.wpanther.eidasremotesigning.dto.csc.*;
import com.wpanther.eidasremotesigning.entity.SigningCertificate;
import com.wpanther.eidasremotesigning.exception.CertificateException;
import com.wpanther.eidasremotesigning.exception.SigningException;
import com.wpanther.eidasremotesigning.repository.SigningCertificateRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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
    private final RemoteSigningService remoteSigningService;
    private final PKCS11Service pkcs11Service;

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
            
            // Create a digest signing request for our existing service
            DigestSigningRequest.SignatureType signatureType = DigestSigningRequest.SignatureType.XADES;
            
            // Determine signature type from request if specified
            if (request.getSignatureData().getSignatureAttributes() != null && 
                request.getSignatureData().getSignatureAttributes().getSignatureType() != null) {
                String requestedType = request.getSignatureData().getSignatureAttributes().getSignatureType();
                if ("PAdES".equalsIgnoreCase(requestedType)) {
                    signatureType = DigestSigningRequest.SignatureType.PADES;
                }
            }
            
            // Results for multiple hash values
            String[] signatures = new String[request.getSignatureData().getHashToSign().length];
            String signatureAlgorithm = null;
            String certificate = null;
            
            // Sign each hash
            for (int i = 0; i < request.getSignatureData().getHashToSign().length; i++) {
                String hashToSign = request.getSignatureData().getHashToSign()[i];
                
                DigestSigningRequest signingRequest = DigestSigningRequest.builder()
                        .certificateId(credentialID)
                        .digestValue(hashToSign)
                        .digestAlgorithm(request.getHashAlgo())
                        .signatureType(signatureType)
                        .build();
                
                // Set PIN in thread local for service to use
                PinThreadLocal.set(pin);
                
                try {
                    // Call the existing signing service
                    DigestSigningResponse signingResponse = remoteSigningService.signDigest(signingRequest);
                    
                    // Save results
                    signatures[i] = signingResponse.getSignatureValue();
                    signatureAlgorithm = signingResponse.getSignatureAlgorithm();
                    certificate = signingResponse.getCertificateBase64();
                } finally {
                    // Always clear the thread local
                    PinThreadLocal.remove();
                }
            }
            
            // Build and return CSC response
            return CSCSignatureResponse.builder()
                    .signatureAlgorithm(signatureAlgorithm)
                    .signatures(signatures)
                    .certificate(certificate)
                    .build();
        } catch (SigningException se) {
            throw se;
        } catch (Exception e) {
            log.error("Error in signHash", e);
            throw new SigningException("Failed to sign hash: " + e.getMessage(), e);
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
    
    /**
     * Thread local utility for storing PIN during signing operations
     */
    public static class PinThreadLocal {
        private static final ThreadLocal<String> PIN_HOLDER = new ThreadLocal<>();
        
        public static void set(String pin) {
            PIN_HOLDER.set(pin);
        }
        
        public static String get() {
            return PIN_HOLDER.get();
        }
        
        public static void remove() {
            PIN_HOLDER.remove();
        }
    }
}
