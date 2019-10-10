package no.nav.security.token.support.oauth2.client;

import no.nav.security.token.support.oauth2.ClientConfigurationProperties;
import no.nav.security.token.support.oauth2.OAuth2ClientException;
import no.nav.security.token.support.oauth2.OAuth2ParameterNames;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Collections;

import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;

abstract class AbstractOAuth2TokenClient<T extends AbstractOAuth2GrantRequest> {

    private final RestTemplate restTemplate;

    AbstractOAuth2TokenClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    OAuth2AccessTokenResponse getTokenResponse(T grantRequest) {
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

    private HttpHeaders tokenRequestHeaders(ClientConfigurationProperties.ClientProperties clientProperties) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON_UTF8));
        final MediaType contentType = MediaType.valueOf(APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8");
        headers.setContentType(contentType);
        if ("client_secret_basic".equals(clientProperties.getClientAuthMethod())) {
            headers.setBasicAuth(clientProperties.getClientId(), clientProperties.getClientSecret());
        }
        return headers;
    }

    MultiValueMap<String, String> createDefaultFormParameters(T grantRequest) {
        MultiValueMap<String, String> formParameters = new LinkedMultiValueMap<>();
        ClientConfigurationProperties.ClientProperties clientProperties = grantRequest.getClientProperties();
        if ("client_secret_post".equals(clientProperties.getClientAuthMethod())) {
            formParameters.add(OAuth2ParameterNames.CLIENT_ID, clientProperties.getClientId());
            formParameters.add(OAuth2ParameterNames.CLIENT_SECRET, clientProperties.getClientSecret());
        }
        formParameters.add(OAuth2ParameterNames.GRANT_TYPE, grantRequest.getGrantType().getValue());
        formParameters.add(OAuth2ParameterNames.SCOPE, String.join(" ", clientProperties.getScope()));
        return formParameters;
    }

    protected abstract MultiValueMap<String, String> buildFormParameters(T grantRequest);
}
