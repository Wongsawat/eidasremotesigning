package com.wpanther.eidasremotesigning.service;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.wpanther.eidasremotesigning.dto.CertificateDetailResponse;
import com.wpanther.eidasremotesigning.dto.CertificateListResponse;
import com.wpanther.eidasremotesigning.dto.CertificateResponse;
import com.wpanther.eidasremotesigning.dto.CertificateSummary;
import com.wpanther.eidasremotesigning.dto.CertificateUpdateRequest;
import com.wpanther.eidasremotesigning.dto.Pkcs11CertificateAssociateRequest;
import com.wpanther.eidasremotesigning.dto.Pkcs11CertificateInfo;
import com.wpanther.eidasremotesigning.dto.AWSKMSCertificateAssociateRequest;
import com.wpanther.eidasremotesigning.dto.AWSKMSKeyInfo;
import com.wpanther.eidasremotesigning.entity.SigningCertificate;
import com.wpanther.eidasremotesigning.exception.CertificateException;
import com.wpanther.eidasremotesigning.repository.OAuth2ClientRepository;
import com.wpanther.eidasremotesigning.repository.SigningCertificateRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class SigningCertificateService {

    private final SigningCertificateRepository certificateRepository;
    private final OAuth2ClientRepository oauth2ClientRepository;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private PKCS11Service pkcs11Service;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private AWSKMSService awskmsService;

    @Value("${app.keystore.base-path:/app/keystores}")
    private String keystoreBasePath;

    /**
     * Returns PKCS11Service or throws if not enabled
     */
    private PKCS11Service requirePkcs11Service() {
        if (pkcs11Service == null) {
            throw new CertificateException("PKCS#11 is not enabled. Configure app.pkcs11.enabled=true and ensure SoftHSM is installed.");
        }
        return pkcs11Service;
    }

    /**
     * Lists all certificates from PKCS#11 token
     *
     * @param pin The PIN to access the PKCS#11 token
     */
    public List<Pkcs11CertificateInfo> listPkcs11Certificates(String pin) {
        if (pin == null || pin.isEmpty()) {
            throw new CertificateException("PIN is required to access PKCS#11 token");
        }
        return requirePkcs11Service().listCertificates(pin);
    }

    /**
     * Lists all signing keys from AWS KMS
     */
    public List<AWSKMSKeyInfo> listAWSKMSKeys() {
        if (awskmsService == null) {
            throw new CertificateException("AWS KMS is not enabled or configured");
        }
        return awskmsService.listSigningKeys();
    }

    /**
     * Associates an AWS KMS key with a client certificate
     *
     * @param request The AWS KMS certificate association request
     */
    @Transactional
    public CertificateDetailResponse associateAWSKMSCertificate(AWSKMSCertificateAssociateRequest request) {
        try {
            if (awskmsService == null) {
                throw new CertificateException("AWS KMS is not enabled or configured");
            }

            // Get client ID from authentication
            String clientId = getCurrentClientId();

            // Verify client exists
            if (!oauth2ClientRepository.existsByClientId(clientId)) {
                throw new CertificateException("Invalid OAuth2 client ID. Client does not exist.");
            }

            // Validate the KMS key
            if (!awskmsService.validateKey(request.getKmsKeyId())) {
                throw new CertificateException("KMS key not found or not enabled: " + request.getKmsKeyId());
            }

            // Get key info
            AWSKMSKeyInfo keyInfo = awskmsService.getKeyInfo(request.getKmsKeyId());

            // Decode and validate the certificate
            byte[] certBytes = Base64.getDecoder().decode(request.getCertificateBase64());
            java.io.ByteArrayInputStream bis = new java.io.ByteArrayInputStream(certBytes);
            java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(bis);

            // Create a unique alias using the key ID
            String alias = "kms-" + keyInfo.getKeyId();

            // Create entity for the certificate association
            SigningCertificate certEntity = SigningCertificate.builder()
                .id(UUID.randomUUID().toString())
                .description(request.getDescription() != null ? request.getDescription() : "AWS KMS Key: " + keyInfo.getKeyId())
                .storageType("AWSKMS")
                .certificateAlias(alias)
                .kmsKeyId(request.getKmsKeyId())
                .awsRegion(request.getAwsRegion())
                .certificateData(request.getCertificateBase64())
                .active(true)
                .clientId(clientId)
                .createdAt(Instant.now())
                .build();

            certificateRepository.save(certEntity);

            return mapToDetailResponse(certEntity, certificate);
        } catch (Exception e) {
            throw new CertificateException("Failed to associate AWS KMS certificate: " + e.getMessage(), e);
        }
    }
    
    /**
     * Associates an existing PKCS#11 certificate with a client
     * 
     * @param request The certificate association request
     * @param pin The PIN to access the PKCS#11 token
     */
    @Transactional
    public CertificateDetailResponse associatePkcs11Certificate(Pkcs11CertificateAssociateRequest request, String pin) {
        try {
            if (pin == null || pin.isEmpty()) {
                throw new CertificateException("PIN is required to access PKCS#11 token");
            }
            
            // Get client ID from authentication or context
            String clientId = getCurrentClientId();
            
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
            
            return mapToDetailResponse(certEntity, certificate);
        } catch (Exception e) {
            throw new CertificateException("Failed to associate PKCS#11 certificate: " + e.getMessage(), e);
        }
    }
    
    @Transactional(readOnly = true)
    public CertificateListResponse listCertificates() {
        String clientId = getCurrentClientId();
        List<SigningCertificate> certificates = certificateRepository.findByClientId(clientId);
        
        List<CertificateSummary> summaries = certificates.stream()
            .map(cert -> mapToSummary(cert, null)) // No PIN provided for summary list
            .collect(Collectors.toList());
            
        return CertificateListResponse.builder()
            .certificates(summaries)
            .total(summaries.size())
            .build();
    }
    
    @Transactional(readOnly = true)
    public CertificateDetailResponse getCertificate(String certificateId, String pin) {
        CertificateResponse response = getCertificateWithX509(certificateId, pin);
        return response.getDetailResponse();
    }
    
    /**
     * Gets a certificate with its X509Certificate object
     * Internal method used by other services
     * 
     * @param certificateId The certificate ID
     * @param pin The PIN for PKCS#11 tokens
     */
    @Transactional(readOnly = true)
    public CertificateResponse getCertificateWithX509(String certificateId, String pin) {
        String clientId = getCurrentClientId();
        SigningCertificate certificate = certificateRepository.findByIdAndClientId(certificateId, clientId)
            .orElseThrow(() -> new CertificateException("Certificate not found"));
        
        // Load certificate details
        X509Certificate x509Cert;
        if ("PKCS11".equals(certificate.getStorageType())) {
            // For PKCS#11, load from token
            if (pin == null || pin.isEmpty()) {
                throw new CertificateException("PIN is required to access PKCS#11 token");
            }
            x509Cert = requirePkcs11Service().getCertificate(certificate.getCertificateAlias(), pin);
        } else if ("AWSKMS".equals(certificate.getStorageType())) {
            // For AWS KMS, load from stored certificate data
            try {
                byte[] certBytes = Base64.getDecoder().decode(certificate.getCertificateData());
                java.io.ByteArrayInputStream bis = new java.io.ByteArrayInputStream(certBytes);
                java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
                x509Cert = (X509Certificate) cf.generateCertificate(bis);
            } catch (Exception e) {
                throw new CertificateException("Failed to load AWS KMS certificate: " + e.getMessage(), e);
            }
        } else {
            // For PKCS#12, load from file
            try {
                x509Cert = loadCertificateFromKeystore(certificate);
            } catch (Exception e) {
                throw new CertificateException("Failed to load certificate: " + e.getMessage(), e);
            }
        }
        
        CertificateDetailResponse detailResponse = mapToDetailResponse(certificate, x509Cert);
        return CertificateResponse.builder()
            .detailResponse(detailResponse)
            .x509Certificate(x509Cert)
            .build();
    }
    
    @Transactional
    public CertificateDetailResponse updateCertificate(String certificateId, CertificateUpdateRequest request, String pin) {
        String clientId = getCurrentClientId();
        SigningCertificate certificate = certificateRepository.findByIdAndClientId(certificateId, clientId)
            .orElseThrow(() -> new CertificateException("Certificate not found"));
            
        if (request.getDescription() != null) {
            certificate.setDescription(request.getDescription());
        }
        
        if (request.getActive() != null) {
            certificate.setActive(request.getActive());
        }
        
        certificate.setUpdatedAt(Instant.now());
        certificateRepository.save(certificate);
        
        // Load certificate details
        X509Certificate x509Cert;
        if ("PKCS11".equals(certificate.getStorageType())) {
            // For PKCS#11, load from token
            if (pin == null || pin.isEmpty()) {
                throw new CertificateException("PIN is required to access PKCS#11 token");
            }
            x509Cert = requirePkcs11Service().getCertificate(certificate.getCertificateAlias(), pin);
        } else {
            try {
                x509Cert = loadCertificateFromKeystore(certificate);
            } catch (Exception e) {
                throw new CertificateException("Failed to load certificate: " + e.getMessage(), e);
            }
        }
        
        return mapToDetailResponse(certificate, x509Cert);
    }
    
    @Transactional
    public void deleteCertificate(String certificateId) {
        String clientId = getCurrentClientId();
        SigningCertificate certificate = certificateRepository.findByIdAndClientId(certificateId, clientId)
            .orElseThrow(() -> new CertificateException("Certificate not found"));
        
        // For PKCS#12, delete the keystore file
        if ("PKCS12".equals(certificate.getStorageType()) && certificate.getKeystorePath() != null) {
            try {
                File keystoreFile = new File(certificate.getKeystorePath());
                if (keystoreFile.exists()) {
                    keystoreFile.delete();
                }
            } catch (Exception e) {
                log.warn("Could not delete keystore file: {}", e.getMessage());
            }
        }
        
        // For PKCS#11, we only remove the association, not the certificate itself
        certificateRepository.delete(certificate);
    }
    
    /**
     * Maps entity to detail response
     */
    private CertificateDetailResponse mapToDetailResponse(SigningCertificate cert, X509Certificate x509Cert) {
        try {
            boolean selfSigned = x509Cert.getSubjectX500Principal().equals(x509Cert.getIssuerX500Principal());
            int keySize = getKeySize(x509Cert.getPublicKey());
            
            return CertificateDetailResponse.builder()
                .id(cert.getId())
                .subjectDN(x509Cert.getSubjectX500Principal().getName())
                .issuerDN(x509Cert.getIssuerX500Principal().getName())
                .serialNumber(x509Cert.getSerialNumber().toString())
                .keyAlgorithm(x509Cert.getPublicKey().getAlgorithm())
                .keySize(keySize)
                .description(cert.getDescription())
                .notBefore(x509Cert.getNotBefore().toInstant())
                .notAfter(x509Cert.getNotAfter().toInstant())
                .certificateBase64(Base64.getEncoder().encodeToString(x509Cert.getEncoded()))
                .active(cert.isActive())
                .selfSigned(selfSigned)
                .storageType(cert.getStorageType())
                .createdAt(cert.getCreatedAt())
                .updatedAt(cert.getUpdatedAt())
                .build();
        } catch (Exception e) {
            throw new CertificateException("Failed to map certificate details: " + e.getMessage(), e);
        }
    }
    
    /**
     * Maps entity to summary
     */
    private CertificateSummary mapToSummary(SigningCertificate cert, String pin) {
        try {
            X509Certificate x509Cert;
            
            if ("PKCS11".equals(cert.getStorageType())) {
                // For PKCS#11, load from token if PIN is provided
                if (pin != null && !pin.isEmpty()) {
                    try {
                        x509Cert = requirePkcs11Service().getCertificate(cert.getCertificateAlias(), pin);
                    } catch (Exception e) {
                        // If we can't access the token, create a minimal summary
                        return createMinimalSummary(cert);
                    }
                } else {
                    // No PIN provided, create minimal summary
                    return createMinimalSummary(cert);
                }
            } else {
                // For PKCS#12, load from file
                x509Cert = loadCertificateFromKeystore(cert);
            }
            
            boolean selfSigned = x509Cert.getSubjectX500Principal().equals(x509Cert.getIssuerX500Principal());
            
            return CertificateSummary.builder()
                .id(cert.getId())
                .subjectDN(x509Cert.getSubjectX500Principal().getName())
                .serialNumber(x509Cert.getSerialNumber().toString())
                .description(cert.getDescription())
                .notBefore(x509Cert.getNotBefore().toInstant())
                .notAfter(x509Cert.getNotAfter().toInstant())
                .active(cert.isActive())
                .selfSigned(selfSigned)
                .storageType(cert.getStorageType())
                .build();
        } catch (Exception e) {
            // If we can't load certificate details, return minimal information
            log.warn("Could not load certificate details for summary: {}", e.getMessage());
            return createMinimalSummary(cert);
        }
    }
    
    private CertificateSummary createMinimalSummary(SigningCertificate cert) {
        return CertificateSummary.builder()
            .id(cert.getId())
            .description(cert.getDescription())
            .active(cert.isActive())
            .storageType(cert.getStorageType())
            .build();
    }
    
    /**
     * Loads an X509Certificate from a PKCS12 keystore
     */
    public X509Certificate loadCertificateFromKeystore(SigningCertificate cert) throws Exception {
        if (!"PKCS12".equals(cert.getStorageType())) {
            throw new CertificateException("Certificate is not stored in PKCS12 format");
        }
        
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(cert.getKeystorePath())) {
            keyStore.load(fis, cert.getKeystorePassword().toCharArray());
            return (X509Certificate) keyStore.getCertificate(cert.getCertificateAlias());
        }
    }
    
    /**
     * Gets the private key for a certificate
     * Note: For AWS KMS certificates, this will throw an exception as keys cannot be exported
     *
     * @param certificateId The certificate ID
     * @param pin The PIN for PKCS#11 token
     * @return The private key (only for PKCS11 and PKCS12)
     */
    public PrivateKey getPrivateKey(String certificateId, String pin) {
        try {
            SigningCertificate cert = certificateRepository.findById(certificateId)
                .orElseThrow(() -> new CertificateException("Certificate not found"));

            if ("AWSKMS".equals(cert.getStorageType())) {
                throw new CertificateException(
                    "Private keys stored in AWS KMS cannot be exported. Use AWS KMS signing operations instead.");
            }

            if ("PKCS11".equals(cert.getStorageType())) {
                // For PKCS#11, get from token
                if (pin == null || pin.isEmpty()) {
                    throw new CertificateException("PIN is required to access PKCS#11 token");
                }
                return requirePkcs11Service().getPrivateKey(cert.getCertificateAlias(), pin);
            } else {
                // For PKCS#12, get from file
                KeyStore keyStore = KeyStore.getInstance("PKCS12");
                try (FileInputStream fis = new FileInputStream(cert.getKeystorePath())) {
                    keyStore.load(fis, cert.getKeystorePassword().toCharArray());
                    PrivateKey privateKey = (PrivateKey) keyStore.getKey(
                        cert.getCertificateAlias(),
                        cert.getKeystorePassword().toCharArray());

                    if (privateKey == null) {
                        throw new CertificateException("Private key not found in keystore");
                    }

                    return privateKey;
                }
            }
        } catch (CertificateException ce) {
            throw ce;
        } catch (Exception e) {
            throw new CertificateException("Failed to get private key: " + e.getMessage(), e);
        }
    }
    
    /**
     * Retrieves the current client ID from the security context
     */
    private String getCurrentClientId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication instanceof JwtAuthenticationToken) {
            JwtAuthenticationToken jwtAuth = (JwtAuthenticationToken) authentication;
            return jwtAuth.getName();
        }
        
        // For client credential flow, check if client ID is available in security context
        if (authentication != null && authentication.getPrincipal() != null) {
            return authentication.getName();
        }
        
        throw new CertificateException("Unable to determine client ID from security context");
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