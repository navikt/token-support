package no.nav.security.token.support.demo.spring.client;

import no.nav.security.token.support.oauth2.ClientConfigurationProperties;
import no.nav.security.token.support.oauth2.client.OAuth2AccessTokenService;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.stereotype.Service;

@Service
public class ClientCredentialsExampleClient extends BaseExampleClient {

    private static final String OAUTH2_CLIENT_CONFIG_KEY = "exampleapi-clientcredentials";

    public ClientCredentialsExampleClient(RestTemplateBuilder restTemplateBuilder,
                                          ClientConfigurationProperties clientConfigurationProperties,
                                          OAuth2AccessTokenService oAuth2AccessTokenService) {
        super(OAUTH2_CLIENT_CONFIG_KEY, restTemplateBuilder, clientConfigurationProperties, oAuth2AccessTokenService);
    }

    public String ping() {
        return restTemplate.getForObject("/ping", String.class);
    }
}
