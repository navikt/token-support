package no.nav.security.token.support.client.spring.oauth2;

import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService;
import no.nav.security.token.support.client.spring.ClientConfigurationProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import reactor.core.publisher.Mono;

import static com.nimbusds.oauth2.sdk.token.AccessTokenType.BEARER;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

public class OAuth2ClientExchangeFilterFunction implements ExchangeFilterFunction {

    private static final Logger LOG = LoggerFactory.getLogger(OAuth2ClientExchangeFilterFunction.class);

    private final OAuth2AccessTokenService service;
    private final ClientConfigurationPropertiesMatcher matcher;
    private final ClientConfigurationProperties configs;

    public OAuth2ClientExchangeFilterFunction(ClientConfigurationProperties configs, OAuth2AccessTokenService service, ClientConfigurationPropertiesMatcher matcher) {
        this.service = service;
        this.matcher = matcher;
        this.configs = configs;
    }

    @Override
    public Mono<ClientResponse> filter(ClientRequest req, ExchangeFunction next) {
        var url = req.url();
        var config = matcher.findProperties(configs, url);
        if (config.isPresent()) {
            return next.exchange(ClientRequest.from(req).header(AUTHORIZATION, BEARER + " " + service.getAccessToken(config.get()).getAccessToken()).build());
        }
        return next.exchange(ClientRequest.from(req).build());
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + " [service=" + service + ", matcher=" + matcher + ", configs=" + configs + "]";
    }
}
