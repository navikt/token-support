package no.nav.security.token.support.spring.test;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import no.nav.security.mock.oauth2.MockOAuth2Server;
import no.nav.security.mock.oauth2.OAuth2Config;
import no.nav.security.mock.oauth2.token.DefaultOAuth2TokenCallback;
import no.nav.security.mock.oauth2.token.OAuth2TokenCallback;
import no.nav.security.mock.oauth2.token.OAuth2TokenProvider;
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Primary;

import java.util.Set;

@Configuration
@EnableConfigurationProperties(MockOAuth2ServerProperties.class)
public class MockOAuth2ServerAutoConfiguration {

    private final Logger log = LoggerFactory.getLogger(MockOAuth2ServerAutoConfiguration.class);
    private final MockOAuth2Server mockOAuth2Server;
    private final MockOAuth2ServerProperties properties;

    public MockOAuth2ServerAutoConfiguration(MockOAuth2ServerProperties properties) {
        this.properties = properties;
        this.mockOAuth2Server = new MockOAuth2Server(
            new OAuth2Config(
                properties.isInteractiveLogin(),
                null,
                null,
                new OAuth2TokenProvider(),
                    Set.of(new DefaultOAuth2TokenCallback())
            )
        );
    }

    @Bean
    @Primary
    @DependsOn("mockOAuth2Server")
    ProxyAwareResourceRetriever overrideOidcResourceRetriever() {
        return new ProxyAwareResourceRetriever();
    }

    @Bean
    MockOAuth2Server mockOAuth2Server() {
        return mockOAuth2Server;
    }

    @PostConstruct
    void start() {
        int port = properties.getPort();
        if (port > 0) {
            log.debug("starting mock oauth2 server on port {}",port);
            mockOAuth2Server.start(port);
        } else {
            throw new RuntimeException("could not find mock-oauth2-server.port in environment. cannot start server.");
        }
    }

    @PreDestroy
    void shutdown()  {
        log.debug("shutting down the mock oauth2 server.");
        mockOAuth2Server.shutdown();
    }
}

@ConfigurationProperties(MockOAuth2ServerProperties.PREFIX)
class MockOAuth2ServerProperties {

    static final String PREFIX = "mock-oauth2-server";
    private final int port;
    private final boolean interactiveLogin;

    MockOAuth2ServerProperties(int port, boolean interactiveLogin) {
        this.port = port;
        this.interactiveLogin = interactiveLogin;
    }

    public int getPort() {
        return this.port;
    }

    public boolean isInteractiveLogin() {
        return this.interactiveLogin;
    }

    @Override
    public String toString() {
        return "MockOAuth2ServerProperties(port=" + this.getPort() + ", interactiveLogin=" + this.isInteractiveLogin() + ")";
    }
}