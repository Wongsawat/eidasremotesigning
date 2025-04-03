package com.wpanther.eidasremotesigning.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ClientRegistrationRequest {

    @NotBlank(message = "Client name is required")
    private String clientName;

    @NotEmpty(message = "At least one scope is required")
    private Set<String> scopes;

    @NotEmpty(message = "At least one grant type is required")
    private Set<String> grantTypes;
}