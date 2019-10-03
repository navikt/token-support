package no.nav.security.token.support.demo.spring.config;

import no.nav.security.token.support.test.spring.TokenGeneratorConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Profile;

@Configuration
@Profile("dev")
@Import(TokenGeneratorConfiguration.class)
public class ApplicationConfigurationDev {
}
