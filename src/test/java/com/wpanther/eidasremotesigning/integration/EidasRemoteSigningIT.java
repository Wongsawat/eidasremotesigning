package com.wpanther.eidasremotesigning.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wpanther.eidasremotesigning.dto.*;
import com.wpanther.eidasremotesigning.entity.SigningLog;
import com.wpanther.eidasremotesigning.repository.OAuth2ClientRepository;
import com.wpanther.eidasremotesigning.repository.SigningCertificateRepository;
import com.wpanther.eidasremotesigning.repository.SigningLogRepository;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
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

        @Autowired
        private SigningCertificateRepository certificateRepository;

        @Autowired
        private SigningLogRepository signingLogRepository;

        // Test variables
        private static String clientId;
        private static String clientSecret;
        private static String accessToken;
        private static String certificateId;

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


        /**
         * Test certificate listing
         */
        @Test
        @Order(4)
        public void testCertificateListing() throws Exception {
                // Call the certificate listing endpoint
                MvcResult result = mockMvc.perform(MockMvcRequestBuilders
                                .get("/certificates")
                                .header("Authorization", "Bearer " + accessToken))
                                .andExpect(status().isOk())
                                .andReturn();

                // Parse response
                String responseContent = result.getResponse().getContentAsString();
                JsonNode responseJson = objectMapper.readTree(responseContent);

                // Verify list data
                assertTrue(responseJson.has("certificates"));
                assertTrue(responseJson.has("total"));
                assertTrue(responseJson.get("certificates").isArray());
                assertTrue(responseJson.get("total").asInt() > 0);

                // Verify our certificate is in the list
                boolean foundCertificate = false;
                for (JsonNode cert : responseJson.get("certificates")) {
                        if (cert.get("id").asText().equals(certificateId)) {
                                foundCertificate = true;
                                break;
                        }
                }
                assertTrue(foundCertificate, "Could not find our created certificate in the list");

                System.out.println("Certificate listing successful");
        }

        /**
         * Test digest signing
         */
        @Test
        @Order(5)
        public void testDigestSigning() throws Exception {
                // Create test content and calculate its digest
                String testContent = "This is test content for integration testing of signing";
                byte[] contentBytes = testContent.getBytes();

                // Calculate SHA-256 digest
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] digestBytes = digest.digest(contentBytes);
                String digestBase64 = Base64.getEncoder().encodeToString(digestBytes);

                // Create signing request
                DigestSigningRequest request = DigestSigningRequest.builder()
                                .certificateId(certificateId)
                                .digestValue(digestBase64)
                                .digestAlgorithm("SHA-256")
                                .signatureType(DigestSigningRequest.SignatureType.XADES)
                                .build();

                // Call the signing endpoint
                MvcResult result = mockMvc.perform(MockMvcRequestBuilders
                                .post("/api/v1/signing/digest")
                                .contentType(MediaType.APPLICATION_JSON)
                                .header("Authorization", "Bearer " + accessToken)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isCreated())
                                .andReturn();

                // Parse response
                String responseContent = result.getResponse().getContentAsString();
                JsonNode responseJson = objectMapper.readTree(responseContent);

                // Verify signature response
                assertNotNull(responseJson.get("signatureValue").asText());
                assertEquals("SHA256withRSA", responseJson.get("signatureAlgorithm").asText());
                assertEquals(certificateId, responseJson.get("certificateId").asText());
                assertNotNull(responseJson.get("certificateBase64").asText());

        }

        /**
         * Test signature logging
         */
        @Test
        @Order(6)
        public void testSigningLogs() throws Exception {
                // Call the logs endpoint
                MvcResult result = mockMvc.perform(MockMvcRequestBuilders
                                .get("/api/v1/logs")
                                .header("Authorization", "Bearer " + accessToken))
                                .andExpect(status().isOk())
                                .andReturn();

                // Parse response
                String responseContent = result.getResponse().getContentAsString();
                List<SigningLog> logs = objectMapper.readValue(responseContent,
                                objectMapper.getTypeFactory().constructCollectionType(List.class, SigningLog.class));

                // Verify logs exist
                assertFalse(logs.isEmpty(), "Signing logs should not be empty");

                // Find our signing operation in logs
                boolean foundSigningOperation = false;
                for (SigningLog log : logs) {
                        if (log.getCertificateId().equals(certificateId) &&
                                        "SUCCESS".equals(log.getStatus()) &&
                                        "XADES".equals(log.getSignatureType())) {
                                foundSigningOperation = true;
                                break;
                        }
                }

                assertTrue(foundSigningOperation, "Could not find our signing operation in logs");

                // Verify logs in database
                List<SigningLog> dbLogs = signingLogRepository.findByCertificateId(certificateId);
                assertFalse(dbLogs.isEmpty(), "Signing logs in database should not be empty");

                System.out.println("Signing logs verified successfully");
        }

        /**
         * Test metrics generation
         */
        @Test
        @Order(7)
        public void testSigningMetrics() throws Exception {
                // Call the metrics endpoint
                MvcResult result = mockMvc.perform(MockMvcRequestBuilders
                                .get("/api/v1/metrics")
                                .header("Authorization", "Bearer " + accessToken))
                                .andExpect(status().isOk())
                                .andReturn();

                // Parse response
                String responseContent = result.getResponse().getContentAsString();
                SigningMetricsResponse metrics = objectMapper.readValue(responseContent, SigningMetricsResponse.class);

                // Verify metrics
                assertTrue(metrics.getSuccessfulOperations() >= 0, "Should have zero or more successful operations");
                assertEquals(0, metrics.getFailedOperations(), "Should have no failed operations");
                assertTrue(metrics.getOperationsBySignatureType().containsKey("XADES"),
                                "Metrics should include XADES signature type");
                assertTrue(metrics.getOperationsByDigestAlgorithm().containsKey("SHA-256"),
                                "Metrics should include SHA-256 digest algorithm");
                assertTrue(metrics.getOperationsLast24Hours() > 0, "Should have operations in last 24 hours");

                System.out.println("Metrics verified successfully");
        }

        /**
         * Test certificate updates
         */
        @Test
        @Order(8)
        public void testCertificateUpdate() throws Exception {
                // Create update request
                CertificateUpdateRequest request = CertificateUpdateRequest.builder()
                                .description("Updated integration test certificate")
                                .active(true)
                                .build();

                // Call the certificate update endpoint
                MvcResult result = mockMvc.perform(MockMvcRequestBuilders
                                .put("/certificates/" + certificateId)
                                .contentType(MediaType.APPLICATION_JSON)
                                .header("Authorization", "Bearer " + accessToken)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isOk())
                                .andReturn();

                // Parse response
                String responseContent = result.getResponse().getContentAsString();
                JsonNode responseJson = objectMapper.readTree(responseContent);

                // Verify update
                assertEquals("Updated integration test certificate", responseJson.get("description").asText());
                assertTrue(responseJson.get("active").asBoolean());

                System.out.println("Certificate updated successfully");
        }

        /**
         * Test error conditions - invalid digest algorithm
         */
        @Test
        @Order(9)
        public void testInvalidDigestAlgorithm() throws Exception {
                // Create request with invalid algorithm
                DigestSigningRequest request = DigestSigningRequest.builder()
                                .certificateId(certificateId)
                                .digestValue(Base64.getEncoder().encodeToString("test".getBytes()))
                                .digestAlgorithm("SHA-1") // eIDAS doesn't allow SHA-1
                                .signatureType(DigestSigningRequest.SignatureType.XADES)
                                .build();

                // Call the signing endpoint - should return 400 Bad Request
                mockMvc.perform(MockMvcRequestBuilders
                                .post("/api/v1/signing/digest")
                                .contentType(MediaType.APPLICATION_JSON)
                                .header("Authorization", "Bearer " + accessToken)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isBadRequest());

                System.out.println("Invalid digest algorithm test passed");
        }

        /**
         * Test error conditions - invalid base64 encoding
         */
        @Test
        @Order(10)
        public void testInvalidBase64Digest() throws Exception {
                // Create request with invalid base64
                DigestSigningRequest request = DigestSigningRequest.builder()
                                .certificateId(certificateId)
                                .digestValue("this is not valid base64!")
                                .digestAlgorithm("SHA-256")
                                .signatureType(DigestSigningRequest.SignatureType.XADES)
                                .build();

                // Call the signing endpoint - should return 400 Bad Request
                mockMvc.perform(MockMvcRequestBuilders
                                .post("/api/v1/signing/digest")
                                .contentType(MediaType.APPLICATION_JSON)
                                .header("Authorization", "Bearer " + accessToken)
                                .content(objectMapper.writeValueAsString(request)))
                                .andExpect(status().isBadRequest());

                System.out.println("Invalid base64 digest test passed");
        }

        /**
         * Test logs by date range
         */
        @Test
        @Order(11)
        public void testLogsByDateRange() throws Exception {
                // Set up date range (last 24 hours)
                Instant end = Instant.now();
                Instant start = end.minusSeconds(24 * 60 * 60);

                // Call the logs by date range endpoint
                MvcResult result = mockMvc.perform(MockMvcRequestBuilders
                                .get("/api/v1/logs/daterange")
                                .param("startDate", start.toString())
                                .param("endDate", end.toString())
                                .header("Authorization", "Bearer " + accessToken))
                                .andExpect(status().isOk())
                                .andReturn();

                // Parse response
                String responseContent = result.getResponse().getContentAsString();
                List<SigningLog> logs = objectMapper.readValue(responseContent,
                                objectMapper.getTypeFactory().constructCollectionType(List.class, SigningLog.class));

                // Verify logs exist in the time range
                assertFalse(logs.isEmpty(), "Signing logs in date range should not be empty");

                System.out.println("Date range logs test passed");
        }

        /**
         * Cleanup after all tests
         */
        @Test
        @Order(99)
        public void testCleanup() throws Exception {
                // Delete created certificate
                mockMvc.perform(MockMvcRequestBuilders
                                .delete("/certificates/" + certificateId)
                                .header("Authorization", "Bearer " + accessToken))
                                .andExpect(status().isNoContent());

                // Verify certificate is deleted
                assertFalse(certificateRepository.findById(certificateId).isPresent());

                System.out.println("Cleanup completed successfully");
        }
}
