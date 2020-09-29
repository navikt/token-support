package no.nav.security.token.support.spring.test;

import lombok.Getter;
import lombok.ToString;
import no.nav.security.mock.oauth2.MockOAuth2Server;
import no.nav.security.mock.oauth2.OAuth2Config;
import no.nav.security.mock.oauth2.token.DefaultOAuth2TokenCallback;
import no.nav.security.mock.oauth2.token.OAuth2TokenProvider;
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Primary;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.io.IOException;
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
        try {
            int port = properties.getPort();
            if (port > 0) {
                log.debug("starting mock oauth2 server on port " + port);
                mockOAuth2Server.start(port);
            } else {
                throw new RuntimeException("could not find " + "mock-oauth2-server.port" + " in environment. cannot " +
                    "start server.");
            }
        } catch (IOException e) {
            log.error("could not register and start MockOAuth2Server");
            throw new RuntimeException(e);
        }
    }

    @PreDestroy
    void shutdown() throws IOException {
        log.debug("shutting down the mock oauth2 server.");
        mockOAuth2Server.shutdown();
    }
}

@ToString
@Getter
@ConstructorBinding
@ConfigurationProperties(MockOAuth2ServerProperties.PREFIX)
class MockOAuth2ServerProperties {

    static final String PREFIX = "mock-oauth2-server";
    private final int port;
    private final boolean interactiveLogin;

    MockOAuth2ServerProperties(int port, boolean interactiveLogin) {
        this.port = port;
        this.interactiveLogin = interactiveLogin;
    }
}
