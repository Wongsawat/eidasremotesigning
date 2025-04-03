package com.wpanther.eidasremotesigning.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ClientRegistrationResponse {
    private String clientId;
    private String clientSecret;
    private String clientName;
    private Set<String> scopes;
    private Set<String> grantTypes;
    private Instant createdAt;
}
