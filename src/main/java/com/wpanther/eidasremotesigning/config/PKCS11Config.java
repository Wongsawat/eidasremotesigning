package com.wpanther.eidasremotesigning.config;

import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Configuration for PKCS#11 HSM integration
 */
@Configuration
@ConditionalOnProperty(name = "app.pkcs11.enabled", havingValue = "true", matchIfMissing = true)
@RequiredArgsConstructor
@Slf4j
public class PKCS11Config {


    @Value("${app.pkcs11.provider:SunPKCS11}")
    private String pkcs11Provider;
    
    @Value("${app.pkcs11.config-file:/app/eidasremotesigning/pkcs11.cfg}")
    private String pkcs11ConfigFile;
    
    @Value("${app.pkcs11.library-path:/usr/lib/softhsm/libsofthsm2.so}")
    private String pkcs11LibraryPath;
    
    @Value("${app.pkcs11.slot-list-index:0}")
    private Integer slotListIndex;
    
    @Value("${app.pkcs11.name:SoftHSM}")
    private String pkcs11Name;
    

    /**
     * Initializes the PKCS#11 provider
     */
    @Bean
    public Provider pkcs11Provider() {
        try {
            // Register the PKCS#11 provider
            if ("SunPKCS11".equals(pkcs11Provider)) {
                log.info("Initializing SunPKCS11 provider");
                
                Provider provider;
    
                log.info("Using PKCS#11 config file: {}", pkcs11ConfigFile);
                
                // Create the provider using the config file
                provider = Security.getProvider("SunPKCS11");
                provider = provider.configure(pkcs11ConfigFile);
                
                Security.addProvider(provider);
                log.info("PKCS#11 provider added successfully: {}", provider.getName());
                return provider;
            } else {
                // Custom provider or third-party provider
                log.info("Using custom PKCS#11 provider: {}", pkcs11Provider);
                Class<?> providerClass = Class.forName(pkcs11Provider);
                Provider provider = (Provider) providerClass.getDeclaredConstructor().newInstance();
                Security.addProvider(provider);
                return provider;
            }
        } catch (Exception e) {
            log.error("Failed to initialize PKCS#11 provider", e);
            throw new RuntimeException("Could not initialize PKCS#11 provider: " + e.getMessage(), e);
        }
    }
    
    /**
     * Creates a KeyStore instance for PKCS#11
     */
    @Bean
    public KeyStore pkcs11KeyStore() throws Exception {
        try {
            // Make sure provider is initialized
            Provider provider = pkcs11Provider();
            
            // Create the PKCS#11 keystore
            KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
            
            // Note: The keystore is not initialized here.
            // It will be initialized with the PIN when needed
            
            log.info("PKCS#11 KeyStore created successfully");
            return keyStore;
        } catch (Exception e) {
            log.error("Failed to create PKCS#11 KeyStore", e);
            throw new RuntimeException("Could not create PKCS#11 KeyStore: " + e.getMessage(), e);
        }
    }
}
