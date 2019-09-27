package no.nav.security.token.support.oauth2.client;

import no.nav.security.token.support.oauth2.OAuth2ClientException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Collections;

import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;

abstract class AbstractOAuth2TokenResponseClient<T extends AbstractOAuth2GrantRequest> {

    private final RestTemplate restTemplate;

    AbstractOAuth2TokenResponseClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public OAuth2AccessTokenResponse getTokenResponse(T grantRequest) {
        Assert.notNull(grantRequest, "oAuth2OnBehalfOfGrantRequest cannot be null");
        RequestEntity<?> request = convert(grantRequest);
        try {
            return restTemplate.exchange(request, OAuth2AccessTokenResponse.class).getBody();
        } catch (HttpStatusCodeException e) {
            throw new OAuth2ClientException(String.format("received %s from tokenendpoint=%s with responsebody=%s",
                e.getStatusCode(), grantRequest.getClientProperties().getTokenEndpointUrl(), e.getResponseBodyAsString()), e);
        }
    }

    private RequestEntity<?> convert(T grantRequest) {
        HttpHeaders headers = tokenRequestHeaders(grantRequest.getClientProperties());
        MultiValueMap<String, String> formParameters = this.buildFormParameters(grantRequest);
        URI uri = UriComponentsBuilder.fromUri(grantRequest.getClientProperties().getTokenEndpointUrl())
            .build()
            .toUri();
        return new RequestEntity<>(formParameters, headers, HttpMethod.POST, uri);
    }

    private HttpHeaders tokenRequestHeaders(OAuth2ClientConfig.OAuth2Client clientProperties) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON_UTF8));
        final MediaType contentType = MediaType.valueOf(APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8");
        headers.setContentType(contentType);
        if ("client_secret_basic".equals(clientProperties.getClientAuthMethod())) {
            headers.setBasicAuth(clientProperties.getClientId(), clientProperties.getClientSecret());
        }
        return headers;
    }

    protected abstract MultiValueMap<String, String> buildFormParameters(T grantRequest);

}
