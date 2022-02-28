package no.nav.security.token.support.client.core.http;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static java.util.Collections.unmodifiableMap;

public class OAuth2HttpRequest {

    private final URI tokenEndpointUrl;
    private final OAuth2HttpHeaders oAuth2HttpHeaders;
    private final Map<String, String> formParameters;

    OAuth2HttpRequest(URI tokenEndpointUrl, OAuth2HttpHeaders oAuth2HttpHeaders, Map<String, String> formParameters) {
        this.tokenEndpointUrl = tokenEndpointUrl;
        this.oAuth2HttpHeaders = oAuth2HttpHeaders;
        this.formParameters = formParameters;
    }

    public static OAuth2HttpRequestBuilder builder() {
        return new OAuth2HttpRequestBuilder();
    }

    public URI getTokenEndpointUrl() {
        return tokenEndpointUrl;
    }

    public OAuth2HttpHeaders getOAuth2HttpHeaders() {
        return oAuth2HttpHeaders;
    }

    public Map<String, String> getFormParameters() {
        return formParameters;
    }

    public static class OAuth2HttpRequestBuilder {
        private URI tokenEndpointUrl;
        private OAuth2HttpHeaders oAuth2HttpHeaders;
        private List<String> keys;
        private List<String> values;

        OAuth2HttpRequestBuilder() {
        }

        public OAuth2HttpRequestBuilder tokenEndpointUrl(URI tokenEndpointUrl) {
            this.tokenEndpointUrl = tokenEndpointUrl;
            return this;
        }

        public OAuth2HttpRequestBuilder oAuth2HttpHeaders(OAuth2HttpHeaders oAuth2HttpHeaders) {
            this.oAuth2HttpHeaders = oAuth2HttpHeaders;
            return this;
        }

        public OAuth2HttpRequestBuilder formParameter(String formParameterKey, String formParameterValue) {
            if (keys == null) {
                keys = new ArrayList<>();
                values = new ArrayList<>();
            }
            keys.add(formParameterKey);
            values.add(formParameterValue);
            return this;
        }

        public OAuth2HttpRequestBuilder formParameters(Map<? extends String, ? extends String> formParameters) {
            if (keys == null) {
                keys = new ArrayList<>();
                values = new ArrayList<>();
            }
            formParameters.forEach((key, value) -> {
                keys.add(key);
                values.add(value);
            });
            return this;
        }

        public OAuth2HttpRequestBuilder clearFormParameters() {
            if (keys != null) {
                keys.clear();
                values.clear();
            }
            return this;
        }

        public OAuth2HttpRequest build() {
            switch (keys == null ? 0 : keys.size()) {
                case 0:
                    return new OAuth2HttpRequest(tokenEndpointUrl, oAuth2HttpHeaders, Map.of());
                case 1:
                    return new OAuth2HttpRequest(tokenEndpointUrl, oAuth2HttpHeaders, Map.of(this.keys.get(0), this.values.get(0)));
                default:
                    var formParameters = new LinkedHashMap<String,String>(keys.size());
                    for (int i = 0; i < this.keys.size(); i++) {
                        formParameters.put(this.keys.get(i), this.values.get(i));
                    }
                    return new OAuth2HttpRequest(tokenEndpointUrl, oAuth2HttpHeaders, unmodifiableMap(formParameters));
            }
        }

        @Override
        public String toString() {
            return "OAuth2HttpRequest.OAuth2HttpRequestBuilder(tokenEndpointUrl=" + tokenEndpointUrl + ", oAuth2HttpHeaders=" + oAuth2HttpHeaders + ", keys=" + keys + ", values=" + values + ")";
        }
    }
}
