package no.nav.security.token.support.demo.spring.client;

import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService;
import no.nav.security.token.support.client.spring.ClientConfigurationProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.stereotype.Service;

@Service
public class OnBehalfOfExampleClient extends BaseExampleClient {

    private static final String OAUTH2_CLIENT_CONFIG_KEY = "exampleapi-onbehalfof";

    public OnBehalfOfExampleClient(RestTemplateBuilder restTemplateBuilder,
                                   ClientConfigurationProperties clientConfigurationProperties,
                                   OAuth2AccessTokenService oAuth2AccessTokenService) {

        super(OAUTH2_CLIENT_CONFIG_KEY, restTemplateBuilder, clientConfigurationProperties, oAuth2AccessTokenService);
    }

    public String ping() {
        return restTemplate.getForObject("/ping", String.class);
    }
}
