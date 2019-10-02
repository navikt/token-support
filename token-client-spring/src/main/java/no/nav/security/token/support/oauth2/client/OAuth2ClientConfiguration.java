package no.nav.security.token.support.oauth2.client;

import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import no.nav.security.token.support.oauth2.client.ClientCredentialsTokenResponseClient;
import no.nav.security.token.support.oauth2.client.OAuth2AccessTokenService;
import no.nav.security.token.support.oauth2.client.OnBehalfOfTokenResponseClient;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OAuth2ClientConfiguration {

    @Bean
    OAuth2AccessTokenService oAuth2AccessTokenService(RestTemplateBuilder restTemplateBuilder,
                                                      TokenValidationContextHolder contextHolder) {
        return new OAuth2AccessTokenService(contextHolder,
            new OnBehalfOfTokenResponseClient(restTemplateBuilder.build()),
            new ClientCredentialsTokenResponseClient(restTemplateBuilder.build()));
    }
}
