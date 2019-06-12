package no.nav.security.token.support.core.test.support.spring;

import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever;
import no.nav.security.token.support.core.test.support.FileResourceRetriever;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;

import no.nav.security.token.support.core.test.support.JwkGenerator;

@Configuration
@Import(TokenGeneratorController.class)
public class TokenGeneratorConfiguration {

    /**
     * To be able to ovverride the oidc validation properties in
     * EnableOIDCTokenValidationConfiguration in oidc-spring-support
     */
    @Bean
    @Primary
    ProxyAwareResourceRetriever overrideOidcResourceRetriever() {
        return new FileResourceRetriever("/metadata.json", "/jwkset.json");
    }

    @Bean
    JwkGenerator jwkGenerator() {
        return new JwkGenerator();
    }
}
