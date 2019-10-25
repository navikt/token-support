package no.nav.security.token.support.client.spring.oauth2;

import no.nav.security.token.support.client.core.OAuth2ClientException;
import no.nav.security.token.support.client.core.http.OAuth2HttpClient;
import no.nav.security.token.support.client.core.http.OAuth2HttpRequest;
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

public class DefaultOAuth2HttpClient implements OAuth2HttpClient {

    private final RestTemplate restTemplate;

    public DefaultOAuth2HttpClient(RestTemplateBuilder restTemplateBuilder) {
        this.restTemplate = restTemplateBuilder.build();
    }

    @Override
    public OAuth2AccessTokenResponse post(OAuth2HttpRequest oAuth2HttpRequest) {
        Assert.notNull(oAuth2HttpRequest, "OAuth2HttpRequest cannot be null");
        RequestEntity<?> request = convert(oAuth2HttpRequest);
        try {
            return restTemplate.exchange(request, OAuth2AccessTokenResponse.class).getBody();
        } catch (HttpStatusCodeException e) {
            throw new OAuth2ClientException(String.format("received %s from tokenendpoint=%s with responsebody=%s",
                e.getStatusCode(), oAuth2HttpRequest.getTokenEndpointUrl(), e.getResponseBodyAsString()), e);
        }
    }

    private RequestEntity<?> convert(OAuth2HttpRequest oAuth2HttpRequest) {
        HttpHeaders headers = headers(oAuth2HttpRequest);
        MultiValueMap<String, String> formParameters = new LinkedMultiValueMap<>();
        formParameters.setAll(oAuth2HttpRequest.getFormParameters());
        return new RequestEntity<>(formParameters, headers, HttpMethod.POST, oAuth2HttpRequest.getTokenEndpointUrl());
    }

    private HttpHeaders headers(OAuth2HttpRequest oAuth2HttpRequest) {
        HttpHeaders headers = new HttpHeaders();
        headers.putAll(oAuth2HttpRequest.getOAuth2HttpHeaders().headers());
        return headers;
    }
}
