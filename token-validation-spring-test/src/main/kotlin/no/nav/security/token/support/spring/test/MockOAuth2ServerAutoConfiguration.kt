package no.nav.security.token.support.spring.test

import jakarta.annotation.PostConstruct
import jakarta.annotation.PreDestroy
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.DependsOn
import org.springframework.context.annotation.Primary
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.mock.oauth2.OAuth2Config
import no.nav.security.mock.oauth2.token.DefaultOAuth2TokenCallback
import no.nav.security.mock.oauth2.token.OAuth2TokenProvider
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever

@Configuration
@EnableConfigurationProperties(MockOAuth2ServerProperties::class)
class MockOAuth2ServerAutoConfiguration(private val properties : MockOAuth2ServerProperties) {

    private val log : Logger = LoggerFactory.getLogger(MockOAuth2ServerAutoConfiguration::class.java)
    private val mockOAuth2Server = MockOAuth2Server(OAuth2Config(properties.isInteractiveLogin, null, null,false,OAuth2TokenProvider(), setOf(DefaultOAuth2TokenCallback())))

    @Bean
    @Primary
    @DependsOn("mockOAuth2Server")
    fun overrideOidcResourceRetriever() = ProxyAwareResourceRetriever()

    @Bean
    fun mockOAuth2Server() = mockOAuth2Server

    @PostConstruct
    fun start() {
        log.debug("starting the mock oauth2 server on {}.port", properties)
        mockOAuth2Server.start(properties.port)
    }

    @PreDestroy
    fun shutdown() {
        log.debug("shutting down the mock oauth2 server.")
        mockOAuth2Server.shutdown()
    }
}

@ConfigurationProperties(MockOAuth2ServerProperties.PREFIX)
class MockOAuth2ServerProperties(val port : Int, val isInteractiveLogin : Boolean = false) {

    init {
        require(port > 0) { "port must be set" }
    }

    companion object {

        const val PREFIX : String = "mock-oauth2-server"
    }
}