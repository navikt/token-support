package no.nav.security.token.support.client.core.http;

import lombok.Builder;
import lombok.Getter;
import lombok.Singular;

import java.net.URI;
import java.util.Map;

@Getter
@Builder
public class OAuth2HttpRequest {

    private URI tokenEndpointUrl;
    private OAuth2HttpHeaders oAuth2HttpHeaders;
    @Singular
    private Map<String, String> formParameters;
}
