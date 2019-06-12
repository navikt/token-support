package no.nav.security.token.support.spring.integrationtest;

import no.nav.security.token.support.spring.api.EnableJwtTokenValidation;
import no.nav.security.token.support.core.test.support.spring.TokenGeneratorConfiguration;
import no.nav.security.token.support.spring.MultiIssuerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@EnableJwtTokenValidation
@Import({TokenGeneratorConfiguration.class})
@EnableConfigurationProperties(MultiIssuerProperties.class)
@Configuration
public class ProtectedApplicationConfig {

}
