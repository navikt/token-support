package no.nav.security.spring.oidc.integrationtest;

import no.nav.security.token.support.core.test.support.spring.TokenGeneratorConfiguration;
import no.nav.security.spring.oidc.MultiIssuerProperties;
import no.nav.security.spring.oidc.api.EnableOIDCTokenValidation;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@EnableOIDCTokenValidation
@Import({TokenGeneratorConfiguration.class})
@EnableConfigurationProperties(MultiIssuerProperties.class)
@Configuration
public class ProtectedApplicationConfig {

}
