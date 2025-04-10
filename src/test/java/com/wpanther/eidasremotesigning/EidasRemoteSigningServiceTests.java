package com.wpanther.eidasremotesigning;

import com.wpanther.eidasremotesigning.controller.ClientRegistrationController;
import com.wpanther.eidasremotesigning.controller.RemoteSigningController;
import com.wpanther.eidasremotesigning.controller.SigningCertificateController;
import com.wpanther.eidasremotesigning.dto.*;
import com.wpanther.eidasremotesigning.exception.CertificateException;
import com.wpanther.eidasremotesigning.exception.ClientRegistrationException;
import com.wpanther.eidasremotesigning.exception.SigningException;
import com.wpanther.eidasremotesigning.repository.OAuth2ClientRepository;
import com.wpanther.eidasremotesigning.repository.SigningCertificateRepository;
import com.wpanther.eidasremotesigning.service.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.web.servlet.MockMvc;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@SpringBootTest
@AutoConfigureMockMvc
public class EidasRemoteSigningServiceTests {

    @Mock
    private MockMvc mockMvc;

    @Mock
    private ClientRegistrationService clientRegistrationService;

    @Mock
    private SigningCertificateService signingCertificateService;
    
    @Mock
    private PKCS11Service pkcs11Service;

    @Mock
    private RemoteSigningService remoteSigningService;

    @Mock
    private OAuth2ClientRepository oauth2ClientRepository;

    @Mock
    private SigningCertificateRepository certificateRepository;

    @InjectMocks
    private ClientRegistrationController clientRegistrationController;

    @InjectMocks
    private SigningCertificateController certificateController;

    @InjectMocks
    private RemoteSigningController signingController;

    @BeforeEach
    public void setup() {
        // Clear security context before each test
        SecurityContextHolder.clearContext();
    }

    //----------------------------------------------------------------------
    // Client Registration Tests
    //----------------------------------------------------------------------

    @Test
    public void testRegisterClient_Success() {
        // Arrange
        ClientRegistrationRequest request = new ClientRegistrationRequest();
        request.setClientName("Test Client");
        request.setScopes(Set.of("signing"));
        request.setGrantTypes(Set.of("client_credentials"));

        ClientRegistrationResponse expectedResponse = new ClientRegistrationResponse();
        expectedResponse.setClientId("test-client-id");
        expectedResponse.setClientSecret("test-client-secret");
        expectedResponse.setClientName("Test Client");
        expectedResponse.setScopes(Set.of("signing"));
        expectedResponse.setGrantTypes(Set.of("client_credentials"));
        expectedResponse.setCreatedAt(Instant.now());

        when(clientRegistrationService.registerClient(any(ClientRegistrationRequest.class)))
                .thenReturn(expectedResponse);

        // Act
        ResponseEntity<ClientRegistrationResponse> response = clientRegistrationController.registerClient(request);

        // Assert
        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("test-client-id", response.getBody().getClientId());
        assertEquals("test-client-secret", response.getBody().getClientSecret());
    }

    @Test
    public void testRegisterClient_InvalidRequest() {
        // Arrange
        ClientRegistrationRequest request = new ClientRegistrationRequest();
        // Missing required fields
        
        // Mock service to throw exception for invalid request
        when(clientRegistrationService.registerClient(any(ClientRegistrationRequest.class)))
                .thenThrow(new ClientRegistrationException("Client name is required"));
        
        // Act & Assert
        assertThrows(ClientRegistrationException.class, () -> {
            clientRegistrationController.registerClient(request);
        });
    }

    @Test
    public void testRegisterClient_UnsupportedGrantType() {
        // Arrange
        ClientRegistrationRequest request = new ClientRegistrationRequest();
        request.setClientName("Test Client");
        request.setScopes(Set.of("signing"));
        request.setGrantTypes(Set.of("authorization_code")); // Unsupported

        when(clientRegistrationService.registerClient(any(ClientRegistrationRequest.class)))
                .thenThrow(new ClientRegistrationException("Only client_credentials grant type is supported"));

        // Act & Assert
        try {
            clientRegistrationController.registerClient(request);
            fail("Should have thrown exception");
        } catch (ClientRegistrationException e) {
            assertEquals("Only client_credentials grant type is supported", e.getMessage());
        }
    }

    //----------------------------------------------------------------------
    // Certificate Management Tests
    //----------------------------------------------------------------------
    
    @Test
    public void testAssociatePkcs11Certificate_Success() {
        // Arrange
        Pkcs11CertificateAssociateRequest request = Pkcs11CertificateAssociateRequest.builder()
                .certificateAlias("test-certificate")
                .description("Test PKCS#11 certificate")
                .build();

        CertificateDetailResponse expectedResponse = CertificateDetailResponse.builder()
                .id("test-cert-id")
                .subjectDN("CN=Test User, O=Test Organization, C=US")
                .issuerDN("CN=Test User, O=Test Organization, C=US")
                .serialNumber("123456789")
                .keyAlgorithm("RSA")
                .keySize(2048)
                .notBefore(Instant.now())
                .notAfter(Instant.now().plusSeconds(365 * 24 * 60 * 60))
                .active(true)
                .selfSigned(true)
                .storageType("PKCS11")
                .createdAt(Instant.now())
                .build();

        // Mock authentication
        mockClientAuthentication("test-client");

        // Mock service
        when(signingCertificateService.associatePkcs11Certificate(any(Pkcs11CertificateAssociateRequest.class)))
                .thenReturn(expectedResponse);

        // Act
        ResponseEntity<CertificateDetailResponse> response = certificateController.associatePkcs11Certificate(request);

        // Assert
        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("test-cert-id", response.getBody().getId());
        assertEquals("PKCS11", response.getBody().getStorageType());
    }

    @Test
    public void testListPkcs11Certificates_Success() {
        // Arrange
        List<Pkcs11CertificateInfo> expectedCertificates = new ArrayList<>();
        expectedCertificates.add(Pkcs11CertificateInfo.builder()
                .alias("cert-1")
                .subjectDN("CN=Test User 1")
                .issuerDN("CN=Test CA")
                .serialNumber("123")
                .hasPrivateKey(true)
                .build());

        // Mock authentication
        mockClientAuthentication("test-client");

        // Mock service
        when(signingCertificateService.listPkcs11Certificates()).thenReturn(expectedCertificates);

        // Act
        ResponseEntity<List<Pkcs11CertificateInfo>> response = certificateController.listPkcs11Certificates();

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(1, response.getBody().size());
        assertEquals("cert-1", response.getBody().get(0).getAlias());
    }

    @Test
    public void testListCertificates_Success() {
        // Arrange
        List<CertificateSummary> certificates = new ArrayList<>();
        certificates.add(CertificateSummary.builder()
                .id("cert-1")
                .subjectDN("CN=Test User 1")
                .serialNumber("123")
                .active(true)
                .storageType("PKCS11")
                .build());
        certificates.add(CertificateSummary.builder()
                .id("cert-2")
                .subjectDN("CN=Test User 2")
                .serialNumber("456")
                .active(true)
                .storageType("PKCS11")
                .build());

        CertificateListResponse expectedResponse = CertificateListResponse.builder()
                .certificates(certificates)
                .total(2)
                .build();

        // Mock authentication
        mockClientAuthentication("test-client");

        // Mock service
        when(signingCertificateService.listCertificates()).thenReturn(expectedResponse);

        // Act
        ResponseEntity<CertificateListResponse> response = certificateController.listCertificates();

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals(2, response.getBody().getTotal());
    }

    @Test
    public void testGetCertificate_Success() {
        // Arrange
        CertificateDetailResponse expectedResponse = CertificateDetailResponse.builder()
                .id("test-cert-id")
                .subjectDN("CN=Test User")
                .issuerDN("CN=Test User")
                .serialNumber("123456789")
                .active(true)
                .storageType("PKCS11")
                .build();

        // Mock authentication
        mockClientAuthentication("test-client");

        // Mock service
        when(signingCertificateService.getCertificate("test-cert-id")).thenReturn(expectedResponse);

        // Act
        ResponseEntity<CertificateDetailResponse> response = certificateController.getCertificate("test-cert-id");

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("test-cert-id", response.getBody().getId());
    }

    @Test
    public void testGetCertificate_NotFound() {
        // Arrange
        // Mock authentication
        mockClientAuthentication("test-client");

        // Mock service to throw exception
        when(signingCertificateService.getCertificate("non-existent-id"))
                .thenThrow(new CertificateException("Certificate not found"));

        // Act & Assert
        assertThrows(CertificateException.class, () -> {
            certificateController.getCertificate("non-existent-id");
        });
    }

    @Test
    public void testUpdateCertificate_Success() {
        // Arrange
        CertificateUpdateRequest request = CertificateUpdateRequest.builder()
                .description("Updated description")
                .active(false)
                .build();

        CertificateDetailResponse expectedResponse = CertificateDetailResponse.builder()
                .id("test-cert-id")
                .subjectDN("CN=Test User")
                .description("Updated description")
                .active(false)
                .storageType("PKCS11")
                .build();

        // Mock authentication
        mockClientAuthentication("test-client");

        // Mock service
        when(signingCertificateService.updateCertificate(eq("test-cert-id"), any(CertificateUpdateRequest.class)))
                .thenReturn(expectedResponse);

        // Act
        ResponseEntity<CertificateDetailResponse> response = certificateController.updateCertificate("test-cert-id", request);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("Updated description", response.getBody().getDescription());
        assertFalse(response.getBody().isActive());
    }

    @Test
    public void testDeleteCertificate_Success() {
        // Arrange
        // Mock authentication
        mockClientAuthentication("test-client");

        // Mock service - void method, so we need to use doNothing
        doNothing().when(signingCertificateService).deleteCertificate("test-cert-id");

        // Act
        ResponseEntity<Void> response = certificateController.deleteCertificate("test-cert-id");

        // Assert
        assertEquals(HttpStatus.NO_CONTENT, response.getStatusCode());
        verify(signingCertificateService).deleteCertificate("test-cert-id");
    }

    //----------------------------------------------------------------------
    // Signing Operations Tests
    //----------------------------------------------------------------------

    @Test
    public void testSignDigest_Success() {
        // Arrange
        DigestSigningRequest request = DigestSigningRequest.builder()
                .certificateId("test-cert-id")
                .digestValue(Base64.getEncoder().encodeToString("test-digest".getBytes()))
                .digestAlgorithm("SHA-256")
                .signatureType(DigestSigningRequest.SignatureType.XADES)
                .build();

        DigestSigningResponse expectedResponse = DigestSigningResponse.builder()
                .signatureValue("test-signature-value")
                .signatureAlgorithm("SHA256withRSA")
                .certificateId("test-cert-id")
                .certificateBase64("test-certificate-base64")
                .build();

        // Mock authentication
        mockClientAuthentication("test-client");

        // Mock service
        when(remoteSigningService.signDigest(any(DigestSigningRequest.class))).thenReturn(expectedResponse);

        // Act
        ResponseEntity<DigestSigningResponse> response = signingController.signDigest(request);

        // Assert
        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("test-signature-value", response.getBody().getSignatureValue());
    }

    @Test
    public void testSignDigest_InvalidBase64Digest() {
        // Arrange
        DigestSigningRequest request = DigestSigningRequest.builder()
                .certificateId("test-cert-id")
                .digestValue("not-valid-base64!")
                .digestAlgorithm("SHA-256")
                .signatureType(DigestSigningRequest.SignatureType.XADES)
                .build();

        // Mock authentication
        mockClientAuthentication("test-client");

        // Mock service to throw exception
        when(remoteSigningService.signDigest(any(DigestSigningRequest.class)))
                .thenThrow(new SigningException("Digest value must be Base64 encoded"));

        // Act & Assert
        assertThrows(SigningException.class, () -> {
            signingController.signDigest(request);
        });
    }

    @Test
    public void testSignDigest_UnsupportedDigestAlgorithm() {
        // Arrange
        DigestSigningRequest request = DigestSigningRequest.builder()
                .certificateId("test-cert-id")
                .digestValue(Base64.getEncoder().encodeToString("test-digest".getBytes()))
                .digestAlgorithm("SHA-1") // eIDAS doesn't allow SHA-1
                .signatureType(DigestSigningRequest.SignatureType.XADES)
                .build();

        // Mock authentication
        mockClientAuthentication("test-client");

        // Mock service to throw exception
        when(remoteSigningService.signDigest(any(DigestSigningRequest.class)))
                .thenThrow(new SigningException("Unsupported digest algorithm: SHA-1"));

        // Act & Assert
        assertThrows(SigningException.class, () -> {
            signingController.signDigest(request);
        });
    }

    @Test
    public void testSignDigest_CertificateNotActive() {
        // Arrange
        DigestSigningRequest request = DigestSigningRequest.builder()
                .certificateId("inactive-cert-id")
                .digestValue(Base64.getEncoder().encodeToString("test-digest".getBytes()))
                .digestAlgorithm("SHA-256")
                .signatureType(DigestSigningRequest.SignatureType.XADES)
                .build();

        // Mock authentication
        mockClientAuthentication("test-client");

        // Mock service to throw exception
        when(remoteSigningService.signDigest(any(DigestSigningRequest.class)))
                .thenThrow(new SigningException("Certificate is not active"));

        // Act & Assert
        assertThrows(SigningException.class, () -> {
            signingController.signDigest(request);
        });
    }

    @Test
    public void testSignDigest_CertificateExpired() {
        // Arrange
        DigestSigningRequest request = DigestSigningRequest.builder()
                .certificateId("expired-cert-id")
                .digestValue(Base64.getEncoder().encodeToString("test-digest".getBytes()))
                .digestAlgorithm("SHA-256")
                .signatureType(DigestSigningRequest.SignatureType.XADES)
                .build();

        // Mock authentication
        mockClientAuthentication("test-client");

        // Mock service to throw exception
        when(remoteSigningService.signDigest(any(DigestSigningRequest.class)))
                .thenThrow(new SigningException("Certificate has expired"));

        // Act & Assert
        assertThrows(SigningException.class, () -> {
            signingController.signDigest(request);
        });
    }

    //----------------------------------------------------------------------
    // Helper Methods for Tests
    //----------------------------------------------------------------------

    private void mockClientAuthentication(String clientId) {
        // Create a mock Authentication object
        Authentication authentication = mock(JwtAuthenticationToken.class);
        when(authentication.getName()).thenReturn(clientId);
        
        // Create a mock SecurityContext
        SecurityContext securityContext = mock(SecurityContext.class);
        when(securityContext.getAuthentication()).thenReturn(authentication);
        
        // Set the SecurityContext
        SecurityContextHolder.setContext(securityContext);
    }

}