package com.wpanther.eidasremotesigning;

import com.wpanther.eidasremotesigning.controller.ClientRegistrationController;
import com.wpanther.eidasremotesigning.controller.SigningCertificateController;
import com.wpanther.eidasremotesigning.dto.*;
import com.wpanther.eidasremotesigning.exception.ClientRegistrationException;
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
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
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
    private OAuth2ClientRepository oauth2ClientRepository;

    @Mock
    private SigningCertificateRepository certificateRepository;

    @InjectMocks
    private ClientRegistrationController clientRegistrationController;

    @InjectMocks
    private SigningCertificateController certificateController;


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



}