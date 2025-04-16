package com.wpanther.eidasremotesigning.dto.csc;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * CSC API OAuth2 token response
 * Based on OAuth2 standards and CSC API v2.0 specifications
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CSCOAuth2TokenResponse {
    
    @JsonProperty("access_token")
    private String access_token;
    
    @JsonProperty("token_type")
    private String token_type;
    
    @JsonProperty("expires_in")
    private Integer expires_in;
    
    @JsonProperty("refresh_token")
    private String refresh_token;
    
    @JsonProperty("scope")
    private String scope;
}