package com.wpanther.eidasremotesigning.client;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.security.Security;

/**
 * Sample client to demonstrate the usage of the Remote Signing API
 * This is a demonstration class and should NOT be used in production as-is.
 */
public class SampleClient {

    private static final String SERVER_URL = "http://localhost:9000";
    private static final String CLIENT_ID = "test-client";
    private static final String CLIENT_SECRET = "test-secret";
    
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    
    private String accessToken;
    
    public SampleClient() {
        // Add Bouncy Castle provider for crypto operations
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        
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
            SampleClient client = new SampleClient();
            
            // Step 1: Get OAuth2 access token
            client.getAccessToken();
            System.out.println("Successfully obtained access token");
            
            // Step 2: Create a test certificate
            String certificateId = client.createCertificate();
            System.out.println("Created certificate with ID: " + certificateId);
            
            // Step 3: Sign a test document digest (simulated)
            String documentContent = "This is a test document that will be signed remotely";
            byte[] digest = client.calculateDigest(documentContent.getBytes(StandardCharsets.UTF_8), "SHA-256");
            String base64Digest = Base64.getEncoder().encodeToString(digest);
            
            System.out.println("Document digest (Base64): " + base64Digest);
            
            // Sign the digest with XADES
            JsonNode signatureResponse = client.signDigest(certificateId, base64Digest, "SHA-256", "XADES");
            
            System.out.println("Signature created successfully!");
            System.out.println("Signature Algorithm: " + signatureResponse.get("signatureAlgorithm").asText());
            System.out.println("Signature Value: " + signatureResponse.get("signatureValue").asText());
            
            // Convert and display the certificate
            String certificatePem = convertToPEM(
                    Base64.getDecoder().decode(signatureResponse.get("certificateBase64").asText())
            );
            System.out.println("\nSigner Certificate:");
            System.out.println(certificatePem);
            
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
     * Creates a new certificate for testing
     */
    public String createCertificate() throws Exception {
        // Create the request body
        Map<String, Object> requestBody = new HashMap<>();
        requestBody.put("subjectDN", "CN=Test User, O=Test Organization, C=US");
        requestBody.put("keyAlgorithm", "RSA");
        requestBody.put("keySize", 2048);
        requestBody.put("validityMonths", 12);
        requestBody.put("description", "Test certificate created by sample client");
        requestBody.put("selfSigned", true);
        
        // Build the request
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(SERVER_URL + "/certificates"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + accessToken)
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(requestBody)))
                .build();
        
        // Send the request
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        
        // Check if the request was successful
        if (response.statusCode() != 201) {
            throw new RuntimeException("Failed to create certificate. Status code: " + response.statusCode() + 
                    ", Response: " + response.body());
        }
        
        // Parse the response to get the certificate ID
        JsonNode jsonResponse = objectMapper.readTree(response.body());
        return jsonResponse.get("id").asText();
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
                .POST(HttpRequest.BodyPublishers.ofString(requestBody.toString()))
                .build();
        
        // Send the request
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        
        // Check if the request was successful
        if (response.statusCode() != 200) {
            throw new RuntimeException("Failed to sign digest. Status code: " + response.statusCode() + 
                    ", Response: " + response.body());
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
     * Convert a binary certificate to PEM format
     */
    public static String convertToPEM(byte[] certificateBytes) throws Exception {
        // Create a certificate from the bytes
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(
                new ByteArrayInputStream(certificateBytes));
        
        // Convert to PEM format
        StringWriter writer = new StringWriter();
        try (PemWriter pemWriter = new PemWriter(writer)) {
            pemWriter.writeObject(new PemObject("CERTIFICATE", cert.getEncoded()));
        }
        
        return writer.toString();
    }
    
    /**
     * Helper method to save a file (for debugging)
     */
    private void saveFile(byte[] content, String filePath) throws Exception {
        Files.write(Path.of(filePath), content);
    }
}