package com.wpanther.eidasremotesigning.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wpanther.eidasremotesigning.dto.*;
import com.wpanther.eidasremotesigning.repository.OAuth2ClientRepository;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.util.Base64;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for eIDAS Remote Signing Service
 * These tests cover the complete flow from client registration to signing
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class EidasRemoteSigningIT {

        @Autowired
        private MockMvc mockMvc;

        @Autowired
        private ObjectMapper objectMapper;

        @Autowired
        private OAuth2ClientRepository oauth2ClientRepository;


        // Test variables
        private static String clientId;
        private static String clientSecret;
        private static String accessToken;

        /**
         * Cleanup before running tests
         */
        @BeforeAll
        public static void setup() {
                // This will be executed before all test methods
        }

        /**
         * Test client registration
         */
        @Test
        @Order(1)
        public void testClientRegistration() throws Exception {
                // Create client registration request
                ClientRegistrationRequest request = new ClientRegistrationRequest();
                request.setClientName("Integration Test Client");
                request.setScopes(Set.of("signing"));
                request.setGrantTypes(Set.of("client_credentials"));

                // Call the registration endpoint
                MvcResult result = mockMvc.perform(MockMvcRequestBuilders
                                .post("/client-registration")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isCreated())
                                .andReturn();

                // Parse response
                String responseContent = result.getResponse().getContentAsString();
                JsonNode responseJson = objectMapper.readTree(responseContent);

                // Save client credentials for subsequent tests
                clientId = responseJson.get("clientId").asText();
                clientSecret = responseJson.get("clientSecret").asText();

                // Verify registration data
                assertNotNull(clientId);
                assertNotNull(clientSecret);
                assertEquals("Integration Test Client", responseJson.get("clientName").asText());
                assertTrue(responseJson.get("scopes").isArray());
                assertTrue(responseJson.get("grantTypes").isArray());

                // Verify client exists in database
                assertTrue(oauth2ClientRepository.existsByClientId(clientId));

                System.out.println("Registered client with ID: " + clientId);
        }

        /**
         * Test OAuth2 token generation
         */
        @Test
        @Order(2)
        public void testOAuthTokenGeneration() throws Exception {
                // Prepare Basic authentication header
                String auth = clientId + ":" + clientSecret;
                String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());

                // Request an OAuth access token
                MvcResult result = mockMvc.perform(MockMvcRequestBuilders
                                .post("/oauth2/token")
                                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                                .header("Authorization", "Basic " + encodedAuth)
                                .content("grant_type=client_credentials&scope=signing"))
                                .andExpect(status().isOk())
                                .andReturn();

                // Parse response
                String responseContent = result.getResponse().getContentAsString();
                JsonNode responseJson = objectMapper.readTree(responseContent);

                // Save access token for subsequent tests
                accessToken = responseJson.get("access_token").asText();

                // Verify token data
                assertNotNull(accessToken);
                assertTrue(responseJson.has("expires_in"));
                assertTrue(responseJson.has("token_type"));

                System.out.println("Generated OAuth token successfully");
        }

}
