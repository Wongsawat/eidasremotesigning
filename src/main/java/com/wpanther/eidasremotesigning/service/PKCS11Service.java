package com.wpanther.eidasremotesigning.service;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.wpanther.eidasremotesigning.dto.Pkcs11CertificateInfo;
import com.wpanther.eidasremotesigning.exception.CertificateException;
import com.wpanther.eidasremotesigning.service.CSCApiService.PinThreadLocal;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Service for interacting with PKCS#11 tokens
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class PKCS11Service {

    private final KeyStore pkcs11KeyStore;
    private final Provider pkcs11Provider;

    private static final String PIN_HEADER = "X-HSM-PIN"; // For backward compatibility

    /**
     * Lists all certificates available in the PKCS#11 token
     * 
     * @param pin The user PIN to access the token
     * @return List of certificate information objects
     */
    public List<Pkcs11CertificateInfo> listCertificates(String pin) {
        try {
            List<Pkcs11CertificateInfo> certificates = new ArrayList<>();
            
            // Initialize the keystore with the PIN
            pkcs11KeyStore.load(null, pin.toCharArray());
            
            // Enumerate all aliases in the token
            Enumeration<String> aliases = pkcs11KeyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                
                // Check if it's a certificate
                if (pkcs11KeyStore.isCertificateEntry(alias) || pkcs11KeyStore.isKeyEntry(alias)) {
                    X509Certificate cert = (X509Certificate) pkcs11KeyStore.getCertificate(alias);
                    if (cert != null) {
                        Pkcs11CertificateInfo certInfo = Pkcs11CertificateInfo.builder()
                                .alias(alias)
                                .subjectDN(cert.getSubjectX500Principal().getName())
                                .issuerDN(cert.getIssuerX500Principal().getName())
                                .serialNumber(cert.getSerialNumber().toString())
                                .notBefore(cert.getNotBefore().toInstant())
                                .notAfter(cert.getNotAfter().toInstant())
                                .hasPrivateKey(pkcs11KeyStore.isKeyEntry(alias))
                                .build();
                        
                        certificates.add(certInfo);
                    }
                }
            }
            
            return certificates;
        } catch (Exception e) {
            log.error("Failed to list certificates from PKCS#11 token", e);
            throw new CertificateException("Failed to list certificates from PKCS#11 token: " + e.getMessage(), e);
        }
    }
    
    /**
     * Gets a certificate from the PKCS#11 token by its alias
     * 
     * @param alias The certificate alias
     * @param pin The user PIN
     * @return The X509Certificate
     */
    public X509Certificate getCertificate(String alias, String pin) {
        try {
            // Initialize the keystore with the PIN
            pkcs11KeyStore.load(null, pin.toCharArray());
            
            // Get the certificate
            X509Certificate cert = (X509Certificate) pkcs11KeyStore.getCertificate(alias);
            if (cert == null) {
                throw new CertificateException("Certificate not found with alias: " + alias);
            }
            
            return cert;
        } catch (CertificateException ce) {
            throw ce;
        } catch (Exception e) {
            log.error("Failed to get certificate from PKCS#11 token", e);
            throw new CertificateException("Failed to get certificate from PKCS#11 token: " + e.getMessage(), e);
        }
    }
    
    /**
     * Gets a private key from the PKCS#11 token by its alias
     * 
     * @param alias The key alias
     * @param pin The user PIN
     * @return The PrivateKey
     */
    public PrivateKey getPrivateKey(String alias, String pin) {
        try {
            // Initialize the keystore with the PIN
            pkcs11KeyStore.load(null, pin.toCharArray());
            
            // Check if the alias exists and is a key entry
            if (!pkcs11KeyStore.containsAlias(alias)) {
                throw new CertificateException("No entry found with alias: " + alias);
            }
            
            if (!pkcs11KeyStore.isKeyEntry(alias)) {
                throw new CertificateException("Alias does not contain a private key: " + alias);
            }
            
            // Get the private key
            PrivateKey privateKey = (PrivateKey) pkcs11KeyStore.getKey(alias, pin.toCharArray());
            if (privateKey == null) {
                throw new CertificateException("Failed to retrieve private key for alias: " + alias);
            }
            
            return privateKey;
        } catch (CertificateException ce) {
            throw ce;
        } catch (Exception e) {
            log.error("Failed to get private key from PKCS#11 token", e);
            throw new CertificateException("Failed to get private key from PKCS#11 token: " + e.getMessage(), e);
        }
    }
    
    /**
     * Checks if a certificate and its private key are available in the token
     * 
     * @param alias The certificate alias
     * @param pin The user PIN
     * @return true if both certificate and private key are available
     */
    public boolean validateCertificateAndKey(String alias, String pin) {
        try {
            // Initialize the keystore with the PIN
            pkcs11KeyStore.load(null, pin.toCharArray());
            
            // Check if the alias exists
            if (!pkcs11KeyStore.containsAlias(alias)) {
                return false;
            }
            
            // Check for certificate
            X509Certificate cert = (X509Certificate) pkcs11KeyStore.getCertificate(alias);
            if (cert == null) {
                return false;
            }
            
            // Check for private key
            if (!pkcs11KeyStore.isKeyEntry(alias)) {
                return false;
            }
            
            // Try to actually load the private key
            PrivateKey privateKey = (PrivateKey) pkcs11KeyStore.getKey(alias, pin.toCharArray());
            return privateKey != null;
            
        } catch (Exception e) {
            log.error("Failed to validate certificate and key in PKCS#11 token", e);
            return false;
        }
    }
    
    /**
     * Gets the provider name for this PKCS#11 instance
     */
    public String getProviderName() {
        return pkcs11Provider.getName();
    }
    
    /**
     * Get PIN from various sources - thread local, header, etc.
     * This method supports backward compatibility while transitioning to CSC API
     * 
     * @return The PIN or null if not found
     */
    public String getPIN() {
        // First check thread local (set by CSC API service)
        String pin = PinThreadLocal.get();
        if (pin != null) {
            return pin;
        }
        
        // Then check header (legacy approach)
        try {
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attributes != null) {
                HttpServletRequest request = attributes.getRequest();
                pin = request.getHeader(PIN_HEADER);
                if (pin != null && !pin.isEmpty()) {
                    return pin;
                }
            }
        } catch (Exception e) {
            log.warn("Error accessing request attributes", e);
        }
        
        return null;
    }
}