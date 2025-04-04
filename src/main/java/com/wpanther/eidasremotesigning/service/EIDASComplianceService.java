package com.wpanther.eidasremotesigning.service;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

import org.springframework.stereotype.Service;

import com.wpanther.eidasremotesigning.dto.DigestSigningRequest;
import com.wpanther.eidasremotesigning.exception.SigningException;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Service responsible for ensuring eIDAS compliance in signing operations
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class EIDASComplianceService {

    private static final DateTimeFormatter DATE_FORMATTER = 
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")
                .withZone(ZoneId.of("UTC"));

    /**
     * Validates a signing request against eIDAS requirements
     * 
     * @param request The signing request
     * @param certificate The certificate used for signing
     */
    public void validateEIDASCompliance(DigestSigningRequest request, X509Certificate certificate) {
        // Check certificate validity
        checkCertificateValidity(certificate);
        
        // Check algorithm compliance
        checkAlgorithmCompliance(request.getDigestAlgorithm());
        
        // Check signature type compliance
        checkSignatureTypeCompliance(request.getSignatureType());
        
        // Log compliance validation
        log.debug("eIDAS compliance validation passed for request with certificate: {}", 
                certificate.getSubjectX500Principal().getName());
    }
    
    /**
     * Verifies that the certificate is valid for eIDAS-compliant signatures
     */
    private void checkCertificateValidity(X509Certificate certificate) {
        // Check that the certificate is currently valid
        try {
            certificate.checkValidity();
        } catch (Exception e) {
            throw new SigningException("Certificate is not valid: " + e.getMessage());
        }
        
        // Check for qualified status - in a full implementation, this would involve
        // checking for QCStatements extension, QSCD managed keys, etc.
        
        // Check for key length - eIDAS requires minimum 2048 bits for RSA
        if ("RSA".equalsIgnoreCase(certificate.getPublicKey().getAlgorithm())) {
            int keySize = getKeySizeFromRSACertificate(certificate);
            if (keySize < 2048) {
                throw new SigningException("RSA key size is below eIDAS minimum requirement of 2048 bits");
            }
        }
        
        // Check that the certificate is not expired or about to expire
        Instant notAfter = certificate.getNotAfter().toInstant();
        Instant now = Instant.now();
        if (notAfter.isBefore(now)) {
            throw new SigningException("Certificate has expired on " + 
                    DATE_FORMATTER.format(notAfter));
        }
        
        // Check if certificate is about to expire in the next 7 days
        Instant sevenDaysLater = now.plusSeconds(7 * 24 * 60 * 60);
        if (notAfter.isBefore(sevenDaysLater)) {
            log.warn("Certificate will expire soon on {}", DATE_FORMATTER.format(notAfter));
        }
    }
    
    /**
     * Verifies that the digest algorithm is compliant with eIDAS requirements
     */
    private void checkAlgorithmCompliance(String digestAlgorithm) {
        // Normalize algorithm name
        String normalizedAlgo = digestAlgorithm.toUpperCase(Locale.ENGLISH);
        
        // eIDAS requires at minimum SHA-256
        if (normalizedAlgo.equals("SHA-1") || normalizedAlgo.equals("SHA1") || 
            normalizedAlgo.equals("MD5")) {
            throw new SigningException("Digest algorithm " + digestAlgorithm + 
                " is not compliant with eIDAS requirements. Minimum required is SHA-256.");
        }
        
        // Check if it's one of the approved algorithms
        if (!normalizedAlgo.equals("SHA-256") && 
            !normalizedAlgo.equals("SHA-384") && 
            !normalizedAlgo.equals("SHA-512")) {
            throw new SigningException("Digest algorithm " + digestAlgorithm + 
                " is not recognized or supported for eIDAS signatures");
        }
    }
    
    /**
     * Verifies that the signature type is compliant with eIDAS requirements
     */
    private void checkSignatureTypeCompliance(DigestSigningRequest.SignatureType signatureType) {
        // Both XAdES and PAdES are eIDAS-compliant signature formats
        if (signatureType != DigestSigningRequest.SignatureType.XADES && 
            signatureType != DigestSigningRequest.SignatureType.PADES) {
            throw new SigningException("Signature type " + signatureType + 
                " is not supported for eIDAS signatures");
        }
        
        // Additional checks specific to signature format could be added here
    }
    
    /**
     * Extracts the key size from an RSA certificate
     */
    private int getKeySizeFromRSACertificate(X509Certificate certificate) {
        // This is a simplistic approach - in a real implementation,
        // you'd use proper key inspection
        try {
            java.security.interfaces.RSAPublicKey rsaKey = 
                    (java.security.interfaces.RSAPublicKey) certificate.getPublicKey();
            return rsaKey.getModulus().bitLength();
        } catch (Exception e) {
            log.error("Error determining RSA key size", e);
            return 0; // This will trigger the validation failure
        }
    }
}