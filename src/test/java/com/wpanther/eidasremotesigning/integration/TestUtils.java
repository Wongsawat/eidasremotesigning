package com.wpanther.eidasremotesigning.integration;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * Utility methods for integration testing
 */
public class TestUtils {

    /**
     * Calculates the SHA-256 digest of the input content
     * 
     * @param content The content to digest
     * @return Base64-encoded digest value
     */
    public static String calculateSHA256Digest(String content) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] digestBytes = digest.digest(content.getBytes());
        return Base64.getEncoder().encodeToString(digestBytes);
    }
    
    /**
     * Extracts the modulus length (key size) from an RSA certificate
     * 
     * @param certificateBase64 Base64-encoded X.509 certificate
     * @return Key size in bits
     */
    public static int getKeySize(String certificateBase64) throws Exception {
        byte[] certificateBytes = Base64.getDecoder().decode(certificateBase64);
        
        java.security.cert.CertificateFactory certFactory = 
                java.security.cert.CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(
                new java.io.ByteArrayInputStream(certificateBytes));
        
        if ("RSA".equals(cert.getPublicKey().getAlgorithm())) {
            java.security.interfaces.RSAPublicKey rsaKey = 
                    (java.security.interfaces.RSAPublicKey) cert.getPublicKey();
            return rsaKey.getModulus().bitLength();
        } else if ("EC".equals(cert.getPublicKey().getAlgorithm())) {
            java.security.interfaces.ECPublicKey ecKey = 
                    (java.security.interfaces.ECPublicKey) cert.getPublicKey();
            return ecKey.getParams().getCurve().getField().getFieldSize();
        }
        
        return 0;
    }
    
    /**
     * Verifies RSA signature
     * 
     * @param data The original data that was signed
     * @param signatureBase64 Base64-encoded signature
     * @param certificateBase64 Base64-encoded certificate
     * @param digestAlgorithm Digest algorithm used
     * @return true if signature is valid
     */
    public static boolean verifySignature(byte[] data, String signatureBase64, 
                                         String certificateBase64, String digestAlgorithm) throws Exception {
        // Decode the signature
        byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);
        
        // Get the certificate
        byte[] certificateBytes = Base64.getDecoder().decode(certificateBase64);
        java.security.cert.CertificateFactory certFactory = 
                java.security.cert.CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(
                new java.io.ByteArrayInputStream(certificateBytes));
        
        // Create the signature algorithm name based on digest algorithm
        String signatureAlgorithm;
        if ("RSA".equals(cert.getPublicKey().getAlgorithm())) {
            signatureAlgorithm = digestAlgorithm.replace("-", "") + "withRSA";
        } else if ("EC".equals(cert.getPublicKey().getAlgorithm())) {
            signatureAlgorithm = digestAlgorithm.replace("-", "") + "withECDSA";
        } else {
            throw new IllegalArgumentException("Unsupported key algorithm: " + cert.getPublicKey().getAlgorithm());
        }
        
        // Create a signature verifier
        java.security.Signature sig = java.security.Signature.getInstance(signatureAlgorithm);
        sig.initVerify(cert.getPublicKey());
        sig.update(data);
        
        // Verify the signature
        return sig.verify(signatureBytes);
    }
    
    /**
     * Verifies a digest signature
     * 
     * @param digestBase64 Base64-encoded digest that was signed
     * @param signatureBase64 Base64-encoded signature
     * @param certificateBase64 Base64-encoded certificate
     * @param signatureAlgorithm Signature algorithm used
     * @return true if signature is valid
     */
    public static boolean verifyDigestSignature(String digestBase64, String signatureBase64, 
                                              String certificateBase64, String signatureAlgorithm) throws Exception {
        // Decode the signature and digest
        byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);
        byte[] digestBytes = Base64.getDecoder().decode(digestBase64);
        
        // Get the certificate
        byte[] certificateBytes = Base64.getDecoder().decode(certificateBase64);
        java.security.cert.CertificateFactory certFactory = 
                java.security.cert.CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(
                new java.io.ByteArrayInputStream(certificateBytes));
        
        // Create a signature verifier
        java.security.Signature sig = java.security.Signature.getInstance(signatureAlgorithm);
        sig.initVerify(cert.getPublicKey());
        sig.update(digestBytes);
        
        // Verify the signature
        return sig.verify(signatureBytes);
    }
}
