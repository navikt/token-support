package no.nav.security.token.support.test.spring;

import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever;
import no.nav.security.token.support.test.FileResourceRetriever;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;

import no.nav.security.token.support.test.JwkGenerator;

/**
 * @deprecated use @EnableMockAuth2Server from the token-validation-spring-test module instead
 */
@Deprecated(since = "1.3.0")
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
