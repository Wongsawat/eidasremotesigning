package com.wpanther.eidasremotesigning.service;

import com.wpanther.eidasremotesigning.entity.OAuth2Client;
import com.wpanther.eidasremotesigning.repository.OAuth2ClientRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class OAuth2RegisteredClientRepository implements RegisteredClientRepository {

    private final OAuth2ClientRepository oauth2ClientRepository;

    @Override
    public void save(RegisteredClient registeredClient) {
        // This method would typically be called by the framework when registering clients via admin tools
        // For our dynamic registration, we use our own process and service
        throw new UnsupportedOperationException("Direct client saving not supported - use ClientRegistrationService");
    }

    @Override
    public RegisteredClient findById(String id) {
        return oauth2ClientRepository.findById(id)
                .map(this::mapToRegisteredClient)
                .orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return oauth2ClientRepository.findByClientId(clientId)
                .map(this::mapToRegisteredClient)
                .orElse(null);
    }

    private RegisteredClient mapToRegisteredClient(OAuth2Client client) {
        if (!client.isActive()) {
            return null;
        }

        RegisteredClient.Builder builder = RegisteredClient.withId(client.getId())
                .clientId(client.getClientId())
                .clientSecret(client.getClientSecret())
                .clientName(client.getClientName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);

        // Map grant types
        for (String grantType : client.getGrantTypes()) {
            builder.authorizationGrantType(new AuthorizationGrantType(grantType));
        }

        // Map scopes
        for (String scope : client.getScopes()) {
            builder.scope(scope);
        }

        // Client settings
        builder.clientSettings(ClientSettings.builder()
                .requireAuthorizationConsent(false)  // No consent needed for m2m
                .requireProofKey(false)
                .build());

        // Token settings
        builder.tokenSettings(TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofHours(1))
                .build());

        return builder.build();
    }
}