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
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Sample client demonstrating the use of CSC API v2.0 with PKCS#11 remote signing
 */
public class CSCSampleClient {

    private static final String SERVER_URL = "http://localhost:9000";
    private static final String CLIENT_ID = "test-client";
    private static final String CLIENT_SECRET = "test-secret";
    private static final String HSM_PIN = "1234"; // SoftHSM default pin
    
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    
    private String accessToken;
    
    public CSCSampleClient() {
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
            CSCSampleClient client = new CSCSampleClient();
            
            // Step 1: Get OAuth2 access token
            client.getAccessToken();
            System.out.println("Successfully obtained access token");
            
            // Step 2: Get CSC API service info
            JsonNode serviceInfo = client.getServiceInfo();
            System.out.println("CSC API Service Info:");
            System.out.println("  - Name: " + serviceInfo.get("name").asText());
            System.out.println("  - Description: " + serviceInfo.get("description").asText());
            System.out.println("  - Supported methods: " + serviceInfo.get("methods"));
            
            // Step 3: List credentials (certificates)
            JsonNode credentials = client.listCredentials();
            System.out.println("\nAvailable credentials:");
            
            if (credentials.get("certificates").size() == 0) {
                System.out.println("  No credentials found. Please create at least one certificate.");
                
                // Step 3a: If no certificates exist, list available PKCS#11 certificates for association
                JsonNode pkcs11Certs = client.listPkcs11Certificates();
                System.out.println("\nAvailable PKCS#11 certificates for association:");
                
                if (pkcs11Certs.size() == 0) {
                    System.err.println("  No certificates found in HSM. Please create at least one certificate.");
                    return;
                }
                
                // Step 3b: Associate the first available certificate
                String certAlias = pkcs11Certs.get(0).get("alias").asText();
                System.out.println("  Associating certificate: " + certAlias);
                
                JsonNode association = client.associatePkcs11Certificate(certAlias);
                System.out.println("  Certificate association successful with ID: " + association.get("id").asText());
                
                // Refresh credential list
                credentials = client.listCredentials();
            }
            
            // Step 4: Choose the first credential
            JsonNode credential = credentials.get("certificates").get(0);
            String credentialId = credential.get("id").asText();
            System.out.println("\nSelected credential ID: " + credentialId);
            System.out.println("  Subject: " + credential.get("cert").get("subject").asText());
            
            // Step 5: Get detailed credential info
            JsonNode credentialInfo = client.getCredentialInfo(credentialId);
            System.out.println("\nCredential details:");
            System.out.println("  Status: " + credentialInfo.get("status").asText());
            System.out.println("  Key algorithm: " + credentialInfo.get("key").get("algo").asText());
            System.out.println("  Key length: " + credentialInfo.get("key").get("length").asText());
            
            // Step 6: Sign a test document hash
            String documentContent = "This is a test document that will be signed using CSC API v2.0";
            byte[] digest = client.calculateDigest(documentContent.getBytes(StandardCharsets.UTF_8), "SHA-256");
            String base64Digest = Base64.getEncoder().encodeToString(digest);
            
            System.out.println("\nDocument digest (Base64): " + base64Digest);
            
            // Sign the hash with XAdES
            JsonNode signatureResponse = client.signHash(credentialId, base64Digest, "SHA-256", "XAdES");
            
            System.out.println("Signature created successfully!");
            System.out.println("  Signature Algorithm: " + signatureResponse.get("signatureAlgorithm").asText());
            System.out.println("  Signature Value: " + signatureResponse.get("signatures").get(0).asText());
            
        } catch (Exception e) {
            System.err.println("Error in CSC sample client: " + e.getMessage());
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
     * Gets CSC API service information
     */
    public JsonNode getServiceInfo() throws Exception {
        // Build the request
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(SERVER_URL + "/csc/v2/info"))
                .header("Authorization", "Bearer " + accessToken)
                .GET()
                .build();
        
        // Send the request
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        
        // Check if the request was successful
        if (response.statusCode() != 200) {
            throw new RuntimeException("Failed to get service info. Status code: " + 
                                      response.statusCode() + ", Response: " + response.body());
        }
        
        // Parse and return the response
        return objectMapper.readTree(response.body());
    }
    
    /**
     * Lists all user credentials (certificates)
     */
    public JsonNode listCredentials() throws Exception {
        // Create the request body
        ObjectNode requestBody = objectMapper.createObjectNode();
        requestBody.put("clientId", CLIENT_ID);
        
        // Add credentials with PIN
        ObjectNode credentials = objectMapper.createObjectNode();
        ObjectNode pin = objectMapper.createObjectNode();
        pin.put("value", HSM_PIN);
        credentials.set("pin", pin);
        requestBody.set("credentials", credentials);
        
        // Build the request
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(SERVER_URL + "/csc/v2/credentials/list"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + accessToken)
                .POST(HttpRequest.BodyPublishers.ofString(requestBody.toString()))
                .build();
        
        // Send the request
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        
        // Check if the request was successful
        if (response.statusCode() != 200) {
            throw new RuntimeException("Failed to list credentials. Status code: " + 
                                      response.statusCode() + ", Response: " + response.body());
        }
        
        // Parse and return the response
        return objectMapper.readTree(response.body());
    }
    
    /**
     * Gets detailed information about a specific credential
     */
    public JsonNode getCredentialInfo(String credentialId) throws Exception {
        // Create the request body
        ObjectNode requestBody = objectMapper.createObjectNode();
        requestBody.put("clientId", CLIENT_ID);
        
        // Add credentials with PIN
        ObjectNode credentials = objectMapper.createObjectNode();
        ObjectNode pin = objectMapper.createObjectNode();
        pin.put("value", HSM_PIN);
        credentials.set("pin", pin);
        requestBody.set("credentials", credentials);
        
        // Build the request
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(SERVER_URL + "/csc/v2/credentials/info?credentialID=" + credentialId))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + accessToken)
                .POST(HttpRequest.BodyPublishers.ofString(requestBody.toString()))
                .build();
        
        // Send the request
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        
        // Check if the request was successful
        if (response.statusCode() != 200) {
            throw new RuntimeException("Failed to get credential info. Status code: " + 
                                      response.statusCode() + ", Response: " + response.body());
        }
        
        // Parse and return the response
        return objectMapper.readTree(response.body());
    }
    
    /**
     * Signs a hash using the remote signing API
     */
    public JsonNode signHash(String credentialId, String hashBase64, String hashAlgo, String signatureType) throws Exception {
        // Create the request body
        ObjectNode requestBody = objectMapper.createObjectNode();
        requestBody.put("clientId", CLIENT_ID);
        requestBody.put("credentialID", credentialId);
        requestBody.put("hashAlgo", hashAlgo);
        
        // Add credentials with PIN
        ObjectNode credentials = objectMapper.createObjectNode();
        ObjectNode pin = objectMapper.createObjectNode();
        pin.put("value", HSM_PIN);
        credentials.set("pin", pin);
        requestBody.set("credentials", credentials);
        
        // Add hash to sign
        ObjectNode signatureData = objectMapper.createObjectNode();
        ArrayNode hashesToSign = objectMapper.createArrayNode();
        hashesToSign.add(hashBase64);
        signatureData.set("hashToSign", hashesToSign);
        
        // Add signature attributes
        ObjectNode signatureAttributes = objectMapper.createObjectNode();
        signatureAttributes.put("signatureType", signatureType);
        signatureData.set("signatureAttributes", signatureAttributes);
        
        requestBody.set("signatureData", signatureData);
        
        // Build the request
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(SERVER_URL + "/csc/v2/signatures/signHash"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + accessToken)
                .POST(HttpRequest.BodyPublishers.ofString(requestBody.toString()))
                .build();
        
        // Send the request
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        
        // Check if the request was successful
        if (response.statusCode() != 200) {
            throw new RuntimeException("Failed to sign hash. Status code: " + 
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
    
    /**
     * Lists all certificates available in the PKCS#11 token (legacy endpoint)
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
     * Associates a PKCS#11 certificate with the client (legacy endpoint)
     */
    public JsonNode associatePkcs11Certificate(String certificateAlias) throws Exception {
        // Create the request body
        ObjectNode requestBody = objectMapper.createObjectNode();
        requestBody.put("certificateAlias", certificateAlias);
        requestBody.put("description", "Certificate associated via CSC sample client");
        
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
}
