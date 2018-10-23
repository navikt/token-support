package no.nav.security.oidcspringsupportdemo.config;

import no.nav.security.oidc.test.support.spring.TokenGeneratorController;
import no.nav.security.spring.oidc.api.EnableOIDCTokenValidation;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@EnableOIDCTokenValidation
@Configuration
public class SecurityConfiguration {
}
