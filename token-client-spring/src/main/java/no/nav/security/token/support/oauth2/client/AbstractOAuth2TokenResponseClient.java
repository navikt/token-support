package no.nav.security.token.support.oauth2.client;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Collections;
import java.util.Map;

import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;

public abstract class AbstractOAuth2TokenResponseClient<T extends AbstractOAuth2GrantRequest> {

    private final RestTemplate restTemplate;

    protected AbstractOAuth2TokenResponseClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public Map<String, String> getTokenResponse(T grantRequest) {
        Assert.notNull(grantRequest, "oAuth2OnBehalfOfGrantRequest cannot be null");
        RequestEntity<?> request = convert(grantRequest);
        ParameterizedTypeReference<Map<String, String>> responseType = new ParameterizedTypeReference<Map<String, String>>() {};
        return restTemplate.exchange(request, responseType).getBody();
    }

    protected RequestEntity<?> convert(T grantRequest) {
        HttpHeaders headers = tokenRequestHeaders(grantRequest.getClientProperties());
        MultiValueMap<String, String> formParameters = this.buildFormParameters(grantRequest);
        URI uri = UriComponentsBuilder.fromUriString(grantRequest.getClientProperties().getTokenEndpointUrl())
            .build()
            .toUri();
        return new RequestEntity<>(formParameters, headers, HttpMethod.POST, uri);
    }

    protected HttpHeaders tokenRequestHeaders(OAuth2ClientConfig.OAuth2ClientProperties clientProperties) {
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
