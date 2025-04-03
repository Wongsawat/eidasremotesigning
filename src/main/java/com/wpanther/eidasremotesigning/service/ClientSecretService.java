package com.wpanther.eidasremotesigning.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Base64;

@Service
public class ClientSecretService {

    private final PasswordEncoder passwordEncoder;
    private final SecureRandom secureRandom;

    public ClientSecretService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
        this.secureRandom = new SecureRandom();
    }

    public String generateClientSecret() {
        byte[] randomBytes = new byte[32]; // 256 bits
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    public String hashClientSecret(String clientSecret) {
        return passwordEncoder.encode(clientSecret);
    }

    public boolean verifyClientSecret(String rawClientSecret, String hashedClientSecret) {
        return passwordEncoder.matches(rawClientSecret, hashedClientSecret);
    }
}
