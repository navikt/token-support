package no.nav.security.token.support.spring.integrationtest

import java.io.IOException
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.DependsOn
import org.springframework.context.annotation.Primary
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever
import no.nav.security.token.support.spring.MultiIssuerProperties
import no.nav.security.token.support.spring.api.EnableJwtTokenValidation

@EnableJwtTokenValidation
@EnableConfigurationProperties(MultiIssuerProperties::class)
@Configuration
class ProtectedApplicationConfig {
    @Bean
    @Primary
    @DependsOn("mockOAuth2Server")
    fun oidcResourceRetriever() = ProxyAwareResourceRetriever()


    @Bean
    @Throws(IOException::class)
    fun mockOAuth2Server() =
        MockOAuth2Server().apply {
            start(1111)
        }
}