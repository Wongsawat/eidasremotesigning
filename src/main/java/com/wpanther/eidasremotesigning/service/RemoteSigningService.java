package com.wpanther.eidasremotesigning.service;

import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.wpanther.eidasremotesigning.dto.DigestSigningRequest;
import com.wpanther.eidasremotesigning.dto.DigestSigningResponse;
import com.wpanther.eidasremotesigning.entity.SigningCertificate;
import com.wpanther.eidasremotesigning.exception.SigningException;
import com.wpanther.eidasremotesigning.repository.SigningCertificateRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class RemoteSigningService {

    private final SigningCertificateService certificateService;
    private final SigningCertificateRepository certificateRepository;
    private final EIDASComplianceService eidasComplianceService;
    private final SigningLogService signingLogService;
    
    /**
     * Signs a document digest with the specified certificate
     * 
     * @param request The signing request containing the digest and certificate information
     * @return A signing response with the signature value
     */
    @Transactional(readOnly = true)
    public DigestSigningResponse signDigest(DigestSigningRequest request) {
        try {
            // Validate the request
            validateSigningRequest(request);
            
            // Get the client ID from the security context - will be done by the certificate service
            
            // Load certificate and private key
            String certificateId = request.getCertificateId();
            PrivateKey privateKey = certificateService.getPrivateKey(certificateId);
            
            // Find the certificate entity
            SigningCertificate certEntity = certificateRepository.findById(certificateId)
                .orElseThrow(() -> new SigningException("Certificate not found"));
                
            // Verify certificate is active
            if (!certEntity.isActive()) {
                throw new SigningException("Certificate is not active");
            }
            
            // Load X509Certificate 
            X509Certificate certificate = certificateService.getCertificateWithX509(certificateId).getX509Certificate();
            
            // Verify eIDAS compliance
            eidasComplianceService.validateEIDASCompliance(request, certificate);
            
            // Determine signature algorithm based on digest algorithm and key type
            String signatureAlgorithm = determineSignatureAlgorithm(
                privateKey.getAlgorithm(), 
                request.getDigestAlgorithm()
            );
            
            // Decode the digest value
            byte[] digestBytes = Base64.getDecoder().decode(request.getDigestValue());
            
            // Create signature instance with the appropriate provider
            Signature signature;
            if ("PKCS11".equals(certEntity.getStorageType())) {
                // For PKCS#11, use the HSM provider
                signature = Signature.getInstance(signatureAlgorithm, certEntity.getProviderName());
            } else {
                // For PKCS#12, use the default provider
                signature = Signature.getInstance(signatureAlgorithm);
            }
            
            signature.initSign(privateKey);
            
            // For digest signing, we directly sign the digest value
            signature.update(digestBytes);
            
            // Generate the signature
            byte[] signatureBytes = signature.sign();
            
            // Encode the signature value
            String signatureValue = Base64.getEncoder().encodeToString(signatureBytes);
            
            // Return the signature response
            DigestSigningResponse response = DigestSigningResponse.builder()
                .signatureValue(signatureValue)
                .signatureAlgorithm(signatureAlgorithm)
                .certificateId(certificateId)
                .certificateBase64(Base64.getEncoder().encodeToString(certificate.getEncoded()))
                .build();
                
            // Log the successful signing operation
            signingLogService.logSuccessfulSigning(request, signatureAlgorithm);
                
            return response;
                
        } catch (SigningException e) {
            // Re-throw SigningExceptions as is
            throw e;
        } catch (Exception e) {
            // Wrap other exceptions
            log.error("Error during digest signing", e);
            throw new SigningException("Failed to sign digest: " + e.getMessage(), e);
        }
    }
    
    /**
     * Validates the signing request
     */
    private void validateSigningRequest(DigestSigningRequest request) {
        // Check that the digest value is properly encoded
        try {
            Base64.getDecoder().decode(request.getDigestValue());
        } catch (IllegalArgumentException e) {
            throw new SigningException("Digest value must be Base64 encoded");
        }
        
        // Validate digest algorithm - only allow secure algorithms
        String digestAlgorithm = request.getDigestAlgorithm().toUpperCase();
        if (!digestAlgorithm.equals("SHA-256") && 
            !digestAlgorithm.equals("SHA-384") && 
            !digestAlgorithm.equals("SHA-512")) {
            throw new SigningException("Unsupported digest algorithm: " + digestAlgorithm);
        }
        
        // Additional validations for specific signature types
        if (request.getSignatureType() == DigestSigningRequest.SignatureType.XADES) {
            // XAdES specific validations
        } else if (request.getSignatureType() == DigestSigningRequest.SignatureType.PADES) {
            // PAdES specific validations
        }
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
}
