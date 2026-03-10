package com.wpanther.eidasremotesigning.service;

import com.wpanther.eidasremotesigning.entity.SigningCertificate;
import com.wpanther.eidasremotesigning.exception.CertificateException;
import com.wpanther.eidasremotesigning.repository.OAuth2ClientRepository;
import com.wpanther.eidasremotesigning.repository.SigningCertificateRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SigningCertificateServiceTest {

    @Mock BCFKSService bcfksService;
    @Mock SigningCertificateRepository certificateRepository;
    @Mock OAuth2ClientRepository oauth2ClientRepository;
    @Mock PKCS11Service pkcs11Service;

    SigningCertificateService service;

    SigningCertificate bcfksCert;

    @BeforeEach
    void setUp() {
        // SigningCertificateService uses @RequiredArgsConstructor, generating a 2-arg constructor
        service = new SigningCertificateService(certificateRepository, oauth2ClientRepository);
        ReflectionTestUtils.setField(service, "bcfksService", bcfksService);

        bcfksCert = new SigningCertificate();
        bcfksCert.setId("cert-1");
        bcfksCert.setStorageType("BCFKS");
        bcfksCert.setKeystorePath("/app/keystores/test.bfks");
        bcfksCert.setKeystorePassword("SuperSecret1234!");
        bcfksCert.setCertificateAlias("test-key");
        bcfksCert.setClientId("client-1");
        bcfksCert.setActive(true);

        SecurityContextHolder.getContext().setAuthentication(
            new UsernamePasswordAuthenticationToken("client-1", null, List.of()));
    }

    @Test
    void loadCertificateFromBCFKS_delegatesToBCFKSService() throws Exception {
        X509Certificate mockCert = mock(X509Certificate.class);
        when(bcfksService.loadCertificate(
                bcfksCert.getKeystorePath(),
                bcfksCert.getCertificateAlias(),
                bcfksCert.getKeystorePassword()))
            .thenReturn(mockCert);

        X509Certificate result = service.loadCertificateFromBCFKS(bcfksCert);

        assertThat(result).isSameAs(mockCert);
        verify(bcfksService).loadCertificate(
                bcfksCert.getKeystorePath(),
                bcfksCert.getCertificateAlias(),
                bcfksCert.getKeystorePassword());
    }

    @Test
    void loadCertificateFromBCFKS_throwsForNonBcfksCert() {
        bcfksCert.setStorageType("PKCS11");

        assertThatThrownBy(() -> service.loadCertificateFromBCFKS(bcfksCert))
            .isInstanceOf(CertificateException.class);
    }

    @Test
    void deleteCertificate_delegatesKeystoreDeletionToBCFKSService() {
        when(certificateRepository.findByIdAndClientId(eq("cert-1"), any()))
            .thenReturn(Optional.of(bcfksCert));

        service.deleteCertificate("cert-1");

        verify(bcfksService).deleteKeystore(bcfksCert.getKeystorePath());
        verify(certificateRepository).delete(bcfksCert);
    }
}
