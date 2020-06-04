package no.nav.security.token.support.spring.test;

import lombok.Getter;
import lombok.ToString;
import no.nav.security.mock.oauth2.MockOAuth2Server;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.io.IOException;

@Configuration
@EnableConfigurationProperties(MockOAuth2ServerProperties.class)
public class MockOAuth2ServerAutoConfiguration {

    private final Logger log = LoggerFactory.getLogger(MockOAuth2ServerAutoConfiguration.class);
    private final MockOAuth2ServerProperties mockOAuth2ServerProperties;
    private final MockOAuth2Server mockOAuth2Server;

    public MockOAuth2ServerAutoConfiguration(MockOAuth2ServerProperties mockOAuth2ServerProperties,
                                             MockOAuth2Server mockOAuth2Server) {
        this.mockOAuth2ServerProperties = mockOAuth2ServerProperties;
        this.mockOAuth2Server = mockOAuth2Server;
    }

    @Bean
    MockOAuth2ServerApplicationListener mockOAuth2ApplicationListener(){
        return new MockOAuth2ServerApplicationListener();
    }

    @PostConstruct
    void init() throws IOException {
        log.debug("starting mock oauth2 server on port " + mockOAuth2ServerProperties.getPort());
        mockOAuth2Server.start(mockOAuth2ServerProperties.getPort());
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

    MockOAuth2ServerProperties(int port) {
        this.port = port;
    }
}
