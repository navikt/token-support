package no.nav.security.token.support.client.spring.oauth2;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService;
import no.nav.security.token.support.client.spring.ClientConfigurationProperties;

/**
 *
 * Interceptor som setter Authorization header til et innvekslet token, gyldig
 * kun for target app. Gjeldende klient konfigurasjon for denne kan slås opp via
 * en konfigurerbar matcher
 *
 */
public class Oauth2ClientRequestInterceptor implements ClientHttpRequestInterceptor {

    private static final Logger LOG = LoggerFactory.getLogger(Oauth2ClientRequestInterceptor.class);
    private final ClientConfigurationProperties properties;
    private final OAuth2AccessTokenService service;
    private final ClientConfigurationPropertiesMatcher matcher;

    public Oauth2ClientRequestInterceptor(ClientConfigurationProperties properties,
            OAuth2AccessTokenService service, ClientConfigurationPropertiesMatcher matcher) {
        this.properties = properties;
        this.service = service;
        this.matcher = matcher;
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest req, byte[] body, ClientHttpRequestExecution execution) throws IOException {
        matcher.findProperties(properties, req)
                .ifPresentOrElse(config -> req.getHeaders().setBearerAuth(service.getAccessToken(config).getAccessToken()),
                        () -> LOG.info("Ingen konfig for {}", req.getURI()));

        return execution.execute(req, body);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + " [properties=" + properties + ", service=" + service + ", matcher=" + matcher + "]";
    }

}
