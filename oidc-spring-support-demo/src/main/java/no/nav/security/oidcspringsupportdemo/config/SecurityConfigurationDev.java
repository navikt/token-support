package no.nav.security.oidcspringsupportdemo.config;

import no.nav.security.oidc.test.support.spring.TokenGeneratorConfiguration;
import no.nav.security.spring.oidc.api.EnableOIDCTokenValidation;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Profile;

@Configuration
@Profile("dev")
@Import(TokenGeneratorConfiguration.class)
public class SecurityConfigurationDev {
}
