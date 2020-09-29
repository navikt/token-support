package no.nav.security.token.support.demo.spring;

import no.nav.security.token.support.spring.test.EnableMockOAuth2Server;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration
@Profile("local")
@EnableMockOAuth2Server
public class LocalSecurityConfiguration {

}
