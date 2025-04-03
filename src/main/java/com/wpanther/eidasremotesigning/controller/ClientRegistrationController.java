package com.wpanther.eidasremotesigning.controller;

import com.wpanther.eidasremotesigning.dto.ClientRegistrationRequest;
import com.wpanther.eidasremotesigning.dto.ClientRegistrationResponse;
import com.wpanther.eidasremotesigning.service.ClientRegistrationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/client-registration")
@RequiredArgsConstructor
public class ClientRegistrationController {

    private final ClientRegistrationService clientRegistrationService;

    @PostMapping
    public ResponseEntity<ClientRegistrationResponse> registerClient(@Valid @RequestBody ClientRegistrationRequest request) {
        ClientRegistrationResponse response = clientRegistrationService.registerClient(request);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }
}
