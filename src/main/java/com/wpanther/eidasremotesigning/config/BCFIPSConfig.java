package com.wpanther.eidasremotesigning.config;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.Security;

@Slf4j
@Configuration
public class BCFIPSConfig {

    @Bean
    public BouncyCastleFipsProvider bouncyCastleFipsProvider() {
        if (Security.getProvider("BCFIPS") == null) {
            Security.insertProviderAt(new BouncyCastleFipsProvider(), 2);
            log.info("Registered BCFIPS provider at position 2");
        } else {
            log.info("BCFIPS provider already registered");
        }
        return (BouncyCastleFipsProvider) Security.getProvider("BCFIPS");
    }
}
