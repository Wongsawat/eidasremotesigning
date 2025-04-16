package com.wpanther.eidasremotesigning.controller;

import com.wpanther.eidasremotesigning.dto.csc.*;
import com.wpanther.eidasremotesigning.service.CSCOAuth2Service;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.UUID;

/**
 * Controller implementing the Cloud Signature Consortium API v2.0 OAuth2 endpoints
 * Handles the OAuth2 authorization flow for credential access
 */
@RestController
@RequestMapping("/csc/v2/oauth2")
@RequiredArgsConstructor
@Slf4j
public class CSCOAuth2Controller {

    private final CSCOAuth2Service oAuth2Service;

    /**
     * OAuth2 authorization endpoint
     * Initiates the OAuth2 authorization flow
     */
    @GetMapping("/authorize")
    public void authorize(
            @RequestParam String response_type,
            @RequestParam String client_id,
            @RequestParam String redirect_uri,
            @RequestParam(required = false) String scope,
            @RequestParam(required = false) String state,
            HttpServletRequest request,
            HttpServletResponse response) throws Exception {
        
        log.debug("CSC OAuth2 authorize request from client: {}", client_id);
        
        // Validate request parameters
        if (!"code".equals(response_type)) {
            sendErrorRedirect(redirect_uri, "unsupported_response_type", 
                    "Only code response type is supported", state, response);
            return;
        }
        
        // Generate an authorization code
        String authCode = UUID.randomUUID().toString();
        
        // Store the authorization request
        oAuth2Service.storeAuthorizationRequest(authCode, client_id, redirect_uri, scope, state);
        
        // Redirect to consent page or directly to callback based on configuration
        String callbackUrl = UriComponentsBuilder.fromUriString(redirect_uri)
                .queryParam("code", authCode)
                .queryParam("state", state)
                .build().toUriString();
        
        // For now, we'll just redirect back with the code (auto-approve)
        response.sendRedirect(callbackUrl);
    }
    
    /**
     * OAuth2 token endpoint
     * Exchange authorization code for access token
     */
    @PostMapping("/token")
    public ResponseEntity<CSCOAuth2TokenResponse> token(
            @RequestParam String grant_type,
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String redirect_uri,
            @RequestParam(required = false) String client_id,
            @RequestParam(required = false) String client_secret,
            @RequestParam(required = false) String refresh_token,
            HttpServletRequest request) {
        
        log.debug("CSC OAuth2 token request with grant type: {}", grant_type);
        
        CSCOAuth2TokenResponse response;
        
        // Handle different grant types
        switch (grant_type) {
            case "authorization_code":
                if (code == null || redirect_uri == null) {
                    throw new CSCOAuth2Exception("invalid_request", "Missing required parameters");
                }
                response = oAuth2Service.exchangeAuthorizationCode(code, redirect_uri, client_id, client_secret);
                break;
                
            case "refresh_token":
                if (refresh_token == null) {
                    throw new CSCOAuth2Exception("invalid_request", "Missing refresh token");
                }
                response = oAuth2Service.refreshAccessToken(refresh_token, client_id, client_secret);
                break;
                
            case "client_credentials":
                response = oAuth2Service.clientCredentialsGrant(client_id, client_secret);
                break;
                
            default:
                throw new CSCOAuth2Exception("unsupported_grant_type", "Unsupported grant type");
        }
        
        return ResponseEntity.ok(response);
    }
    
    /**
     * Helper method to send an error redirect for OAuth2 flow
     */
    private void sendErrorRedirect(String redirectUri, String error, String errorDescription, 
                                 String state, HttpServletResponse response) throws Exception {
        String redirectUrl = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("error", error)
                .queryParam("error_description", errorDescription)
                .queryParam("state", state)
                .build().toUriString();
        
        response.sendRedirect(redirectUrl);
    }
    
    /**
     * Exception class for OAuth2 errors
     */
    public static class CSCOAuth2Exception extends RuntimeException {
        private final String error;
        
        public CSCOAuth2Exception(String error, String message) {
            super(message);
            this.error = error;
        }
        
        public String getError() {
            return error;
        }
    }
}