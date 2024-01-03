package no.nav.security.token.support.demo.spring

import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Profile
import no.nav.security.token.support.spring.test.EnableMockOAuth2Server

@Configuration
@Profile("local")
@EnableMockOAuth2Server
class LocalSecurityConfiguration