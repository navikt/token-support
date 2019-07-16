package no.nav.security.oidcspringsupportdemo.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Profile;

import no.nav.security.oidc.test.support.spring.TokenGeneratorConfiguration;

@Configuration
@Profile("dev")
@Import(TokenGeneratorConfiguration.class)
public class SecurityConfigurationDev {
}
