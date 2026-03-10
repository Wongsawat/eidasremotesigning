package com.wpanther.eidasremotesigning.config;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.security.Security;

import static org.assertj.core.api.Assertions.assertThat;

class BCFIPSConfigTest {

    @AfterEach
    void cleanup() {
        Security.removeProvider("BCFIPS");
    }

    @Test
    void bouncyCastleFipsProvider_registersProviderWithCorrectName() {
        BCFIPSConfig config = new BCFIPSConfig();
        config.bouncyCastleFipsProvider();

        assertThat(Security.getProvider("BCFIPS")).isNotNull();
        assertThat(Security.getProvider("BCFIPS").getName()).isEqualTo("BCFIPS");
    }

    @Test
    void bouncyCastleFipsProvider_isIdempotent_whenCalledTwice() {
        BCFIPSConfig config = new BCFIPSConfig();
        config.bouncyCastleFipsProvider();
        int countAfterFirst = Security.getProviders().length;

        config.bouncyCastleFipsProvider();

        assertThat(Security.getProviders().length).isEqualTo(countAfterFirst);
    }

    @Test
    void bouncyCastleFipsProvider_doesNotDisplaceExistingProviders() {
        String firstProviderBefore = Security.getProviders()[0].getName();

        BCFIPSConfig config = new BCFIPSConfig();
        config.bouncyCastleFipsProvider();

        assertThat(Security.getProviders()[0].getName()).isEqualTo(firstProviderBefore);
    }
}
