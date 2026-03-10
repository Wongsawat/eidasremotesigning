package com.wpanther.eidasremotesigning.service;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.test.util.ReflectionTestUtils;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.assertj.core.api.Assertions.*;

class BCFKSServiceTest {

    @TempDir
    Path tempDir;

    BCFKSService service;

    static KeyPair testKeyPair;
    static X509Certificate testCertificate;
    static final String TEST_ALIAS = "test-key";
    static final String TEST_PASSWORD = "SuperSecret1234!"; // >= 14 chars

    @BeforeAll
    static void setupProvider() throws Exception {
        if (Security.getProvider("BCFIPS") == null) {
            Security.insertProviderAt(new BouncyCastleFipsProvider(), 2);
        }
        testKeyPair = generateRSAKeyPair();
        testCertificate = generateSelfSignedCert(testKeyPair);
    }

    @BeforeEach
    void setUp() {
        service = new BCFKSService();
        ReflectionTestUtils.setField(service, "keystoreBasePath", tempDir.toString());
    }

    // --- createKeystore ---

    @Test
    void createKeystore_createsFileWithBfksExtension() throws Exception {
        String path = service.createKeystore(TEST_ALIAS, testKeyPair.getPrivate(), testCertificate, TEST_PASSWORD);

        assertThat(path).endsWith(".bfks");
        assertThat(Files.exists(Path.of(path))).isTrue();
    }

    @Test
    void createKeystore_rejectsShortPassword() {
        assertThatThrownBy(() ->
            service.createKeystore(TEST_ALIAS, testKeyPair.getPrivate(), testCertificate, "short"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("14");
    }

    @Test
    void createKeystore_pathIsUnderConfiguredBaseDir() throws Exception {
        String path = service.createKeystore(TEST_ALIAS, testKeyPair.getPrivate(), testCertificate, TEST_PASSWORD);

        assertThat(path).startsWith(tempDir.toString());
    }

    // --- loadCertificate ---

    @Test
    void loadCertificate_returnsCorrectCertificate() throws Exception {
        String path = service.createKeystore(TEST_ALIAS, testKeyPair.getPrivate(), testCertificate, TEST_PASSWORD);

        X509Certificate loaded = service.loadCertificate(path, TEST_ALIAS, TEST_PASSWORD);

        assertThat(loaded.getEncoded()).isEqualTo(testCertificate.getEncoded());
    }

    @Test
    void loadCertificate_throwsOnWrongPassword() {
        assertThatThrownBy(() -> {
            String path = service.createKeystore(TEST_ALIAS, testKeyPair.getPrivate(), testCertificate, TEST_PASSWORD);
            service.loadCertificate(path, TEST_ALIAS, "WrongPassword1234!");
        }).isInstanceOf(Exception.class);
    }

    // --- getPrivateKey ---

    @Test
    void getPrivateKey_returnsCorrectKey() throws Exception {
        String path = service.createKeystore(TEST_ALIAS, testKeyPair.getPrivate(), testCertificate, TEST_PASSWORD);

        PrivateKey loaded = service.getPrivateKey(path, TEST_ALIAS, TEST_PASSWORD);

        assertThat(loaded.getEncoded()).isEqualTo(testKeyPair.getPrivate().getEncoded());
    }

    // --- sign ---

    @Test
    void sign_producesVerifiableSignature() throws Exception {
        byte[] data = "Hello BCFIPS".getBytes();
        String path = service.createKeystore(TEST_ALIAS, testKeyPair.getPrivate(), testCertificate, TEST_PASSWORD);
        PrivateKey key = service.getPrivateKey(path, TEST_ALIAS, TEST_PASSWORD);

        byte[] signature = service.sign(data, key, "SHA256withRSA");

        Signature verifier = Signature.getInstance("SHA256withRSA", "BCFIPS");
        verifier.initVerify(testCertificate.getPublicKey());
        verifier.update(data);
        assertThat(verifier.verify(signature)).isTrue();
    }

    // --- validateKeystoreAndKey ---

    @Test
    void validateKeystoreAndKey_doesNotThrowForValidKeystore() throws Exception {
        String path = service.createKeystore(TEST_ALIAS, testKeyPair.getPrivate(), testCertificate, TEST_PASSWORD);

        assertThatNoException().isThrownBy(() ->
            service.validateKeystoreAndKey(path, TEST_ALIAS, TEST_PASSWORD));
    }

    @Test
    void validateKeystoreAndKey_throwsForWrongAlias() throws Exception {
        String path = service.createKeystore(TEST_ALIAS, testKeyPair.getPrivate(), testCertificate, TEST_PASSWORD);

        assertThatThrownBy(() -> service.validateKeystoreAndKey(path, "wrong-alias", TEST_PASSWORD))
            .isInstanceOf(KeyStoreException.class);
    }

    // --- deleteKeystore ---

    @Test
    void deleteKeystore_removesFile() throws Exception {
        String path = service.createKeystore(TEST_ALIAS, testKeyPair.getPrivate(), testCertificate, TEST_PASSWORD);
        assertThat(Files.exists(Path.of(path))).isTrue();

        service.deleteKeystore(path);

        assertThat(Files.exists(Path.of(path))).isFalse();
    }

    @Test
    void deleteKeystore_doesNotThrowForNonExistentFile() {
        assertThatNoException().isThrownBy(() ->
            service.deleteKeystore(tempDir + "/nonexistent.bfks"));
    }

    // --- helpers ---

    static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BCFIPS");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    static X509Certificate generateSelfSignedCert(KeyPair keyPair) throws Exception {
        X500Name subject = new X500Name("CN=Test,O=Test,C=TH");
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, BigInteger.ONE, notBefore, notAfter, subject, keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BCFIPS")
                .build(keyPair.getPrivate());

        return new JcaX509CertificateConverter()
                .setProvider("BCFIPS")
                .getCertificate(builder.build(signer));
    }
}
