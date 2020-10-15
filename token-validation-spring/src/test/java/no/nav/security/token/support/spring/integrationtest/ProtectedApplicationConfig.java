package no.nav.security.token.support.spring.integrationtest;

import no.nav.security.mock.oauth2.MockOAuth2Server;
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever;
import no.nav.security.token.support.spring.api.EnableJwtTokenValidation;
import no.nav.security.token.support.test.spring.TokenGeneratorConfiguration;
import no.nav.security.token.support.spring.MultiIssuerProperties;
import org.mockito.Mock;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.*;

import java.io.IOException;
import java.net.InetAddress;

@EnableJwtTokenValidation
@EnableConfigurationProperties(MultiIssuerProperties.class)
@Configuration
public class ProtectedApplicationConfig {

    @Bean
    @Primary
    @DependsOn("mockOAuth2Server")
    public ProxyAwareResourceRetriever oidcResourceRetriever() {
        return new ProxyAwareResourceRetriever();
    }

    @Bean
    public MockOAuth2Server mockOAuth2Server() throws IOException {
        MockOAuth2Server mockOAuth2Server = new MockOAuth2Server();
        mockOAuth2Server.start(InetAddress.getLocalHost(), 1111);
        return mockOAuth2Server;
    }
}
