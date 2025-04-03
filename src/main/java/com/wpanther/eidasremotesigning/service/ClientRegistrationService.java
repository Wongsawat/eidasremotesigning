package com.wpanther.eidasremotesigning.service;

import com.wpanther.eidasremotesigning.dto.ClientRegistrationRequest;
import com.wpanther.eidasremotesigning.dto.ClientRegistrationResponse;
import com.wpanther.eidasremotesigning.entity.OAuth2Client;
import com.wpanther.eidasremotesigning.exception.ClientRegistrationException;
import com.wpanther.eidasremotesigning.repository.OAuth2ClientRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ClientRegistrationService {

    private final OAuth2ClientRepository oauth2ClientRepository;
    private final ClientSecretService clientSecretService;

    @Transactional
    public ClientRegistrationResponse registerClient(ClientRegistrationRequest request) {
        // Validate the registration request
        validateRegistrationRequest(request);

        // Generate client credentials
        String clientId = UUID.randomUUID().toString();
        String rawClientSecret = clientSecretService.generateClientSecret();
        String hashedClientSecret = clientSecretService.hashClientSecret(rawClientSecret);

        // Create and save the client entity
        OAuth2Client client = OAuth2Client.builder()
                .id(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret(hashedClientSecret)
                .clientName(request.getClientName())
                .scopes(request.getScopes())
                .grantTypes(request.getGrantTypes())
                .active(true)
                .createdAt(Instant.now())
                .build();

        oauth2ClientRepository.save(client);

        // Build and return the response
        return ClientRegistrationResponse.builder()
                .clientId(clientId)
                .clientSecret(rawClientSecret) // Only returned once during registration
                .clientName(client.getClientName())
                .scopes(client.getScopes())
                .grantTypes(client.getGrantTypes())
                .createdAt(client.getCreatedAt())
                .build();
    }

    private void validateRegistrationRequest(ClientRegistrationRequest request) {
        // Validate grant types (only client_credentials allowed for now)
        if (!request.getGrantTypes().contains("client_credentials")) {
            throw new ClientRegistrationException("Only client_credentials grant type is supported");
        }

        // Additional validation logic can be added here
    }
}
