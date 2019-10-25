package no.nav.security.token.support.demo.spring.client;

import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse;
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService;
import no.nav.security.token.support.client.spring.ClientConfigurationProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.web.client.RestTemplate;

import java.util.Optional;

public class BaseExampleClient {

    protected final RestTemplate restTemplate;
    private final ClientProperties clientProperties;
    private final OAuth2AccessTokenService oAuth2AccessTokenService;

    public BaseExampleClient(String clientConfigKey, RestTemplateBuilder restTemplateBuilder,
                                   ClientConfigurationProperties clientConfigurationProperties,
                                   OAuth2AccessTokenService oAuth2AccessTokenService) {

        this.clientProperties = Optional.ofNullable(
            clientConfigurationProperties.getRegistration().get(clientConfigKey))
            .orElseThrow(() -> new RuntimeException("could not find oauth2 client config for key="+ clientConfigKey));
        this.restTemplate = restTemplateBuilder
            .rootUri(clientProperties.getResourceUrl().toString())
            .interceptors(bearerTokenInterceptor())
            .build();
        this.oAuth2AccessTokenService = oAuth2AccessTokenService;

    }

    private ClientHttpRequestInterceptor bearerTokenInterceptor(){
        return (request, body, execution) -> {
            OAuth2AccessTokenResponse response =
                oAuth2AccessTokenService.getAccessToken(clientProperties);
            request.getHeaders().setBearerAuth(response.getAccessToken());
            return execution.execute(request, body);
        };
    }
}
