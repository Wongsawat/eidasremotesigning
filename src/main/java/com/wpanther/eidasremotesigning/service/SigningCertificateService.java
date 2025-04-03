package com.wpanther.eidasremotesigning.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.wpanther.eidasremotesigning.dto.CertificateCreateRequest;
import com.wpanther.eidasremotesigning.dto.CertificateDetailResponse;
import com.wpanther.eidasremotesigning.dto.CertificateListResponse;
import com.wpanther.eidasremotesigning.dto.CertificateSummary;
import com.wpanther.eidasremotesigning.dto.CertificateUpdateRequest;
import com.wpanther.eidasremotesigning.entity.SigningCertificate;
import com.wpanther.eidasremotesigning.exception.CertificateException;
import com.wpanther.eidasremotesigning.repository.OAuth2ClientRepository;
import com.wpanther.eidasremotesigning.repository.SigningCertificateRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class SigningCertificateService {

    private final SigningCertificateRepository certificateRepository;
    private final OAuth2ClientRepository oauth2ClientRepository;
    
    @Value("${app.keystore.base-path:/app/keystores}")
    private String keystoreBasePath;
    
    @Value("${app.keystore.directory-permissions:rwx------}")
    private String directoryPermissions;
    
    @Transactional
    public CertificateDetailResponse createCertificate(CertificateCreateRequest request) {
        try {
            // Get client ID from authentication or context
            String clientId = getCurrentClientId();
            
            // Verify client exists
            if (!oauth2ClientRepository.existsByClientId(clientId)) {
                throw new CertificateException("Invalid OAuth2 client ID. Client does not exist.");
            }
            
            // Optional: Check if the client has reached the maximum allowed certificates
            // This is configurable based on your business rules
            long clientCertCount = certificateRepository.countByClientId(clientId);
            if (clientCertCount >= 10) { // Example limit
                throw new CertificateException("Maximum number of certificates reached for this client");
            }
            
            // Default values if not provided
            String keyAlgorithm = request.getKeyAlgorithm() != null ? 
                                  request.getKeyAlgorithm() : "RSA";
            int keySize = request.getKeySize() != null ? 
                         request.getKeySize() : 2048;
            
            // Generate key pair
            KeyPair keyPair = generateKeyPair(keyAlgorithm, keySize);
            
            // Create certificate
            Instant notBefore = Instant.now();
            Instant notAfter = notBefore.plus(request.getValidityMonths() * 30L, ChronoUnit.DAYS);
            
            X509Certificate certificate;
            
            if (request.isSelfSigned()) {
                certificate = generateSelfSignedCertificate(
                    keyPair, 
                    request.getSubjectDN(), 
                    notBefore, 
                    notAfter
                );
            } else {
                // For CA-signed certificates, we'd need to create a CSR and have it signed
                // by the CA certificate referenced by issuerCertificateId
                // This is a simplified version that just creates another self-signed cert
                throw new CertificateException("Non-self-signed certificates are not implemented yet");
            }
            
            // Create a random password for the keystore
            String keystorePassword = generateKeystorePassword();
            
            // Generate a unique filename for the keystore
            String keystoreFileName = clientId + "_" + UUID.randomUUID().toString() + ".p12";
            
            // Ensure the keystore directory exists with proper permissions
            Path keystoreDir = ensureKeystoreDirectory(clientId);
            Path keystorePath = keystoreDir.resolve(keystoreFileName);
            
            // Store the certificate's serial number to use as the keystore alias
            String keystoreAlias = certificate.getSerialNumber().toString();
            
            // Create and save the PKCS12 keystore to file
            createPkcs12KeystoreFile(
                keyPair.getPrivate(), 
                certificate, 
                keystorePassword,
                keystoreAlias,
                keystorePath.toString()
            );
            
            // Create entity with minimal information, relying on the keystore for certificate details
            SigningCertificate certEntity = SigningCertificate.builder()
                .id(UUID.randomUUID().toString())
                .description(request.getDescription())
                .keystorePath(keystorePath.toString())
                .keystorePassword(keystorePassword) // In production, encrypt this password
                .keystoreAlias(keystoreAlias)
                .active(true)
                .clientId(clientId)
                .createdAt(Instant.now())
                .build();
                
            certificateRepository.save(certEntity);
            
            return mapToDetailResponse(certEntity);
        } catch (Exception e) {
            throw new CertificateException("Failed to create certificate: " + e.getMessage(), e);
        }
    }
    
    @Transactional(readOnly = true)
    public CertificateListResponse listCertificates() {
        String clientId = getCurrentClientId();
        List<SigningCertificate> certificates = certificateRepository.findByClientId(clientId);
        
        List<CertificateSummary> summaries = certificates.stream()
            .map(this::mapToSummary)
            .collect(Collectors.toList());
            
        return CertificateListResponse.builder()
            .certificates(summaries)
            .total(summaries.size())
            .build();
    }
    
    @Transactional(readOnly = true)
    public CertificateDetailResponse getCertificate(String certificateId) {
        String clientId = getCurrentClientId();
        SigningCertificate certificate = certificateRepository.findByIdAndClientId(certificateId, clientId)
            .orElseThrow(() -> new CertificateException("Certificate not found"));
            
        return mapToDetailResponse(certificate);
    }
    
    @Transactional
    public CertificateDetailResponse updateCertificate(String certificateId, CertificateUpdateRequest request) {
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
        
        return mapToDetailResponse(certificate);
    }
    
    @Transactional
    public void deleteCertificate(String certificateId) {
        String clientId = getCurrentClientId();
        SigningCertificate certificate = certificateRepository.findByIdAndClientId(certificateId, clientId)
            .orElseThrow(() -> new CertificateException("Certificate not found"));
            
        // Delete the keystore file
        try {
            Files.deleteIfExists(Paths.get(certificate.getKeystorePath()));
        } catch (IOException e) {
            throw new CertificateException("Failed to delete keystore file: " + e.getMessage(), e);
        }
            
        certificateRepository.delete(certificate);
    }
    
    // Helper methods
    private KeyPair generateKeyPair(String algorithm, int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }
    
    private String generateKeystorePassword() {
        byte[] randomBytes = new byte[24]; // 192 bits
        new SecureRandom().nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
    
    /**
     * Ensures that the keystore directory exists for the given client
     * Creates it with proper permissions if it doesn't exist
     */
    private Path ensureKeystoreDirectory(String clientId) throws IOException {
        // Create base and client-specific directories
        Path baseDir = Paths.get(keystoreBasePath);
        Path clientDir = baseDir.resolve(clientId);
        
        // Create directories if they don't exist
        if (!Files.exists(baseDir)) {
            if (directoryPermissions != null && !directoryPermissions.isEmpty()) {
                // Create with specific permissions on Unix-like systems
                Set<PosixFilePermission> permissions = PosixFilePermissions.fromString(directoryPermissions);
                Files.createDirectories(baseDir, PosixFilePermissions.asFileAttribute(permissions));
            } else {
                Files.createDirectories(baseDir);
            }
        }
        
        if (!Files.exists(clientDir)) {
            if (directoryPermissions != null && !directoryPermissions.isEmpty()) {
                Set<PosixFilePermission> permissions = PosixFilePermissions.fromString(directoryPermissions);
                Files.createDirectories(clientDir, PosixFilePermissions.asFileAttribute(permissions));
            } else {
                Files.createDirectories(clientDir);
            }
        }
        
        return clientDir;
    }
    
    /**
     * Creates a PKCS12 keystore file with the given private key and certificate
     */
    private void createPkcs12KeystoreFile(PrivateKey privateKey, X509Certificate certificate, 
                                        String password, String alias, String filePath) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null); // Initialize empty keystore
        
        // Create certificate chain
        X509Certificate[] certChain = new X509Certificate[]{certificate};
        
        // Store private key and certificate in the keystore
        keyStore.setKeyEntry(alias, privateKey, password.toCharArray(), certChain);
        
        // Save the keystore to a file
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            keyStore.store(fos, password.toCharArray());
        }
        
        // Set restrictive file permissions on Unix-like systems
        try {
            File file = new File(filePath);
            file.setReadable(false, false);
            file.setReadable(true, true);
            file.setWritable(false, false);
            file.setWritable(true, true);
            file.setExecutable(false, false);
        } catch (Exception e) {
            // Log warning but continue - this is a best-effort attempt
            // This might fail on non-Unix systems
            System.err.println("Warning: Could not set file permissions: " + e.getMessage());
        }
    }
    
    private X509Certificate generateSelfSignedCertificate(KeyPair keyPair, String subjectDN, 
                                                        Instant notBefore, Instant notAfter) throws Exception {
        X500Name subject = new X500Name(subjectDN);
        BigInteger serialNumber = new BigInteger(64, new SecureRandom());
        
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
            subject,
            serialNumber,
            Date.from(notBefore),
            Date.from(notAfter),
            subject,
            SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded())
        );
        
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
            .build(keyPair.getPrivate());
            
        X509CertificateHolder certHolder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }
    
    /**
     * Retrieves the current client ID from the security context
     * In a production environment, this would extract the client ID from the OAuth token
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
        
        // Fallback (should be replaced with proper exception in production)
        throw new CertificateException("Unable to determine client ID from security context");
    }
    
    private CertificateDetailResponse mapToDetailResponse(SigningCertificate cert) {
        try {
            // Load certificate details from the keystore file
            X509Certificate certificate = loadCertificateFromKeystore(cert);
            
            return CertificateDetailResponse.builder()
                .id(cert.getId())
                .subjectDN(certificate.getSubjectX500Principal().getName())
                .issuerDN(certificate.getIssuerX500Principal().getName())
                .serialNumber(certificate.getSerialNumber().toString())
                .keyAlgorithm(certificate.getPublicKey().getAlgorithm())
                .keySize(getKeySize(certificate.getPublicKey()))
                .description(cert.getDescription())
                .notBefore(certificate.getNotBefore().toInstant())
                .notAfter(certificate.getNotAfter().toInstant())
                .certificateBase64(Base64.getEncoder().encodeToString(certificate.getEncoded()))
                .active(cert.isActive())
                .selfSigned(isSelfSigned(certificate))
                .createdAt(cert.getCreatedAt())
                .updatedAt(cert.getUpdatedAt())
                .build();
        } catch (Exception e) {
            throw new CertificateException("Failed to load certificate details: " + e.getMessage(), e);
        }
    }
    
    private CertificateSummary mapToSummary(SigningCertificate cert) {
        try {
            // Load certificate details from the keystore file
            X509Certificate certificate = loadCertificateFromKeystore(cert);
            
            return CertificateSummary.builder()
                .id(cert.getId())
                .subjectDN(certificate.getSubjectX500Principal().getName())
                .serialNumber(certificate.getSerialNumber().toString())
                .description(cert.getDescription())
                .notBefore(certificate.getNotBefore().toInstant())
                .notAfter(certificate.getNotAfter().toInstant())
                .active(cert.isActive())
                .selfSigned(isSelfSigned(certificate))
                .build();
        } catch (Exception e) {
            throw new CertificateException("Failed to load certificate summary: " + e.getMessage(), e);
        }
    }
    
    /**
     * Loads an X509Certificate from a PKCS12 keystore
     */
    private X509Certificate loadCertificateFromKeystore(SigningCertificate cert) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(cert.getKeystorePath())) {
            keyStore.load(fis, cert.getKeystorePassword().toCharArray());
            return (X509Certificate) keyStore.getCertificate(cert.getKeystoreAlias());
        }
    }
    
    /**
     * Determines if a certificate is self-signed by comparing subject and issuer DNs
     */
    private boolean isSelfSigned(X509Certificate cert) {
        return cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
    }
    
    /**
     * Estimates the key size based on the public key
     */
    private Integer getKeySize(PublicKey publicKey) {
        if (publicKey instanceof RSAPublicKey) {
            return ((RSAPublicKey) publicKey).getModulus().bitLength();
        } else if (publicKey instanceof ECPublicKey) {
            // For EC keys, we estimate based on field size
            return ((ECPublicKey) publicKey).getParams().getOrder().bitLength();
        }
        return null; // Unknown key type
    }
    
    /**
     * Retrieves the private key from the stored PKCS12 keystore file
     * This would be used by the signing service when needed
     */
    public PrivateKey getPrivateKey(String certificateId) {
        try {
            SigningCertificate cert = certificateRepository.findById(certificateId)
                .orElseThrow(() -> new CertificateException("Certificate not found"));
                
            // Path to the keystore file
            String keystorePath = cert.getKeystorePath();
            File keystoreFile = new File(keystorePath);
            
            if (!keystoreFile.exists()) {
                throw new CertificateException("Keystore file not found: " + keystorePath);
            }
            
            // Load the keystore from file
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(keystoreFile)) {
                keyStore.load(fis, cert.getKeystorePassword().toCharArray());
            }
                         
            // Get the private key using the stored alias
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(
                cert.getKeystoreAlias(), 
                cert.getKeystorePassword().toCharArray());
                
            if (privateKey == null) {
                throw new CertificateException("Private key not found in keystore");
            }
            
            return privateKey;
        } catch (Exception e) {
            throw new CertificateException("Failed to retrieve private key: " + e.getMessage(), e);
        }
    }
}