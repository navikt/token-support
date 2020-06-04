package no.nav.security.token.support.spring.test;

import no.nav.security.mock.oauth2.MockOAuth2Server;
import no.nav.security.mock.oauth2.OAuth2Config;
import no.nav.security.mock.oauth2.token.DefaultOAuth2TokenCallback;
import no.nav.security.mock.oauth2.token.OAuth2TokenProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Set;

@Configuration
class MockOAuth2ServerConfiguration {

    @Bean
    @ConditionalOnMissingBean
    OAuth2Config oAuth2Config() {
        return new OAuth2Config(
            false,
            new OAuth2TokenProvider(),
            Set.of(new DefaultOAuth2TokenCallback())
        );
    }

    @Bean
    MockOAuth2Server mockOAuth2Server(OAuth2Config oAuth2Config) {
        return new MockOAuth2Server(oAuth2Config);
    }
}
