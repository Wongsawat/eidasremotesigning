package com.wpanther.eidasremotesigning.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.DependsOn;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.UUID;

@Slf4j
@Service
@DependsOn("bouncyCastleFipsProvider")
public class BCFKSService {

    static final String KEYSTORE_TYPE = "BCFKS";
    static final String PROVIDER = "BCFIPS";
    static final String FILE_EXTENSION = ".bfks";
    static final int MIN_PASSWORD_LENGTH = 14;

    @Value("${app.keystore.base-path:/app/keystores}")
    private String keystoreBasePath;

    /**
     * Creates a new BCFKS keystore file containing the given private key and certificate.
     *
     * @return the absolute path to the created .bfks file
     */
    public String createKeystore(String alias, PrivateKey privateKey,
                                 X509Certificate certificate, String password) throws Exception {
        validatePassword(password);
        Files.createDirectories(Paths.get(keystoreBasePath));
        String keystorePath = keystoreBasePath + "/" + UUID.randomUUID() + FILE_EXTENSION;

        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE, PROVIDER);
        ks.load(null, password.toCharArray());
        ks.setKeyEntry(alias, privateKey, password.toCharArray(), new Certificate[]{certificate});

        try (FileOutputStream fos = new FileOutputStream(keystorePath)) {
            ks.store(fos, password.toCharArray());
        }
        log.info("Created BCFKS keystore at: {}", keystorePath);
        return keystorePath;
    }

    /**
     * Loads the X509Certificate for the given alias from a BCFKS keystore file.
     */
    public X509Certificate loadCertificate(String keystorePath, String alias,
                                           String password) throws Exception {
        return (X509Certificate) loadKeyStore(keystorePath, password).getCertificate(alias);
    }

    /**
     * Loads the PrivateKey for the given alias from a BCFKS keystore file.
     */
    public PrivateKey getPrivateKey(String keystorePath, String alias,
                                   String password) throws Exception {
        return (PrivateKey) loadKeyStore(keystorePath, password)
                .getKey(alias, password.toCharArray());
    }

    /**
     * Signs data using the BCFIPS provider.
     */
    public byte[] sign(byte[] data, PrivateKey privateKey,
                       String signatureAlgorithm) throws Exception {
        Signature sig = Signature.getInstance(signatureAlgorithm, PROVIDER);
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }

    /**
     * Silently deletes the keystore file at the given path (no-op if it does not exist).
     */
    public void deleteKeystore(String keystorePath) {
        try {
            Files.deleteIfExists(Paths.get(keystorePath));
            log.info("Deleted BCFKS keystore: {}", keystorePath);
        } catch (Exception e) {
            log.warn("Could not delete BCFKS keystore {}: {}", keystorePath, e.getMessage());
        }
    }

    /**
     * Asserts that both the certificate and private key exist in the keystore under the given alias.
     *
     * @throws KeyStoreException if certificate or private key is missing
     */
    public void validateKeystoreAndKey(String keystorePath, String alias,
                                       String password) throws Exception {
        KeyStore ks = loadKeyStore(keystorePath, password);
        if (ks.getCertificate(alias) == null) {
            throw new KeyStoreException("Certificate not found for alias: " + alias);
        }
        if (ks.getKey(alias, password.toCharArray()) == null) {
            throw new KeyStoreException("Private key not found for alias: " + alias);
        }
    }

    private KeyStore loadKeyStore(String keystorePath, String password) throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE, PROVIDER);
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            ks.load(fis, password.toCharArray());
        }
        return ks;
    }

    private void validatePassword(String password) {
        if (password == null || password.length() < MIN_PASSWORD_LENGTH) {
            throw new IllegalArgumentException(
                    "BCFKS keystore password must be at least " + MIN_PASSWORD_LENGTH
                    + " characters (FIPS requirement)");
        }
    }
}
