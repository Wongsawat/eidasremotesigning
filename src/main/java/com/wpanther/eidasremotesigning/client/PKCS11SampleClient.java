package com.wpanther.eidasremotesigning.client;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Sample client demonstrating the use of PKCS#11 remote signing
 */
public class PKCS11SampleClient {

    private static final String SERVER_URL = "http://localhost:9000";
    private static final String CLIENT_ID = "test-client";
    private static final String CLIENT_SECRET = "test-secret";
    private static final String HSM_PIN = "1234"; // SoftHSM default pin
    
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    
    private String accessToken;
    
    public PKCS11SampleClient() {
        this.httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .build();
        this.objectMapper = new ObjectMapper();
    }
    
    /**
     * Main method to run the sample client
     */
    public static void main(String[] args) {
        try {
            PKCS11SampleClient client = new PKCS11SampleClient();
            
            // Step 1: Get OAuth2 access token
            client.getAccessToken();
            System.out.println("Successfully obtained access token");
            
            // Step 2: List available certificates in the HSM
            JsonNode certificates = client.listPkcs11Certificates();
            System.out.println("Available certificates in HSM:");
            for (JsonNode cert : certificates) {
                System.out.println("  - " + cert.get("alias").asText() + ": " + 
                                    cert.get("subjectDN").asText());
            }
            
            if (certificates.size() == 0) {
                System.err.println("No certificates found in HSM. Please create at least one certificate.");
                return;
            }
            
            // Step 3: Choose the first certificate
            String certificateAlias = certificates.get(0).get("alias").asText();
            System.out.println("\nUsing certificate: " + certificateAlias);
            
            // Step 4: Associate the certificate with our client
            JsonNode certAssociation = client.associateCertificate(certificateAlias);
            String certificateId = certAssociation.get("id").asText();
            System.out.println("Associated certificate with ID: " + certificateId);
            
            // Step 5: Sign a test document digest
            String documentContent = "This is a test document that will be signed remotely with PKCS#11";
            byte[] digest = client.calculateDigest(documentContent.getBytes(StandardCharsets.UTF_8), "SHA-256");
            String base64Digest = Base64.getEncoder().encodeToString(digest);
            
            System.out.println("Document digest (Base64): " + base64Digest);
            
            // Sign the digest with XADES
            JsonNode signatureResponse = client.signDigest(certificateId, base64Digest, "SHA-256", "XADES");
            
            System.out.println("Signature created successfully!");
            System.out.println("Signature Algorithm: " + signatureResponse.get("signatureAlgorithm").asText());
            System.out.println("Signature Value: " + signatureResponse.get("signatureValue").asText());
            
        } catch (Exception e) {
            System.err.println("Error in sample client: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Obtains an OAuth2 access token using the client credentials flow
     */
    public void getAccessToken() throws Exception {
        // Create the request body
        String requestBody = "grant_type=client_credentials&scope=signing";
        
        // Create the authorization header
        String auth = CLIENT_ID + ":" + CLIENT_SECRET;
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.UTF_8));
        
        // Build the request
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(SERVER_URL + "/oauth2/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Authorization", "Basic " + encodedAuth)
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();
        
        // Send the request
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        
        // Check if the request was successful
        if (response.statusCode() != 200) {
            throw new RuntimeException("Failed to obtain access token. Status code: " + response.statusCode());
        }
        
        // Parse the response
        JsonNode jsonResponse = objectMapper.readTree(response.body());
        this.accessToken = jsonResponse.get("access_token").asText();
    }
    
    /**
     * Lists all certificates available in the PKCS#11 token
     */
    public JsonNode listPkcs11Certificates() throws Exception {
        // Build the request
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(SERVER_URL + "/certificates/pkcs11"))
                .header("Authorization", "Bearer " + accessToken)
                .header("X-HSM-PIN", HSM_PIN)
                .GET()
                .build();
        
        // Send the request
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        
        // Check if the request was successful
        if (response.statusCode() != 200) {
            throw new RuntimeException("Failed to list PKCS#11 certificates. Status code: " + 
                                      response.statusCode() + ", Response: " + response.body());
        }
        
        // Parse and return the response
        return objectMapper.readTree(response.body());
    }
    
    /**
     * Associates a certificate from the PKCS#11 token with the client
     */
    public JsonNode associateCertificate(String certificateAlias) throws Exception {
        // Create the request body
        ObjectNode requestBody = objectMapper.createObjectNode();
        requestBody.put("certificateAlias", certificateAlias);
        requestBody.put("description", "Certificate associated via sample client");
        
        // Build the request
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(SERVER_URL + "/certificates/pkcs11/associate"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + accessToken)
                .header("X-HSM-PIN", HSM_PIN)
                .POST(HttpRequest.BodyPublishers.ofString(requestBody.toString()))
                .build();
        
        // Send the request
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        
        // Check if the request was successful
        if (response.statusCode() != 201) {
            throw new RuntimeException("Failed to associate certificate. Status code: " + 
                                      response.statusCode() + ", Response: " + response.body());
        }
        
        // Parse and return the response
        return objectMapper.readTree(response.body());
    }
    
    /**
     * Signs a document digest using the remote signing API
     */
    public JsonNode signDigest(String certificateId, String digestBase64, String digestAlgorithm, 
                             String signatureType) throws Exception {
        // Create the request body
        ObjectNode requestBody = objectMapper.createObjectNode();
        requestBody.put("certificateId", certificateId);
        requestBody.put("digestValue", digestBase64);
        requestBody.put("digestAlgorithm", digestAlgorithm);
        requestBody.put("signatureType", signatureType);
        
        // Build the request
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(SERVER_URL + "/api/v1/signing/digest"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + accessToken)
                .header("X-HSM-PIN", HSM_PIN)
                .POST(HttpRequest.BodyPublishers.ofString(requestBody.toString()))
                .build();
        
        // Send the request
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        
        // Check if the request was successful
        if (response.statusCode() != 201) {
            throw new RuntimeException("Failed to sign digest. Status code: " + 
                                      response.statusCode() + ", Response: " + response.body());
        }
        
        // Parse and return the response
        return objectMapper.readTree(response.body());
    }
    
    /**
     * Calculates a digest of the input data using the specified algorithm
     */
    public byte[] calculateDigest(byte[] data, String algorithm) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        return md.digest(data);
    }
}
