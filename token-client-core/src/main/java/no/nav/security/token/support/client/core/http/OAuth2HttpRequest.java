package no.nav.security.token.support.client.core.http;

import java.net.URI;
import java.util.ArrayList;
import java.util.Map;

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
        return this.tokenEndpointUrl;
    }

    public OAuth2HttpHeaders getOAuth2HttpHeaders() {
        return this.oAuth2HttpHeaders;
    }

    public Map<String, String> getFormParameters() {
        return this.formParameters;
    }

    public static class OAuth2HttpRequestBuilder {
        private URI tokenEndpointUrl;
        private OAuth2HttpHeaders oAuth2HttpHeaders;
        private ArrayList<String> formParameters$key;
        private ArrayList<String> formParameters$value;

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
            if (this.formParameters$key == null) {
                this.formParameters$key = new ArrayList<String>();
                this.formParameters$value = new ArrayList<String>();
            }
            this.formParameters$key.add(formParameterKey);
            this.formParameters$value.add(formParameterValue);
            return this;
        }

        public OAuth2HttpRequestBuilder formParameters(Map<? extends String, ? extends String> formParameters) {
            if (this.formParameters$key == null) {
                this.formParameters$key = new ArrayList<String>();
                this.formParameters$value = new ArrayList<String>();
            }
            for (final Map.Entry<? extends String, ? extends String> $lombokEntry : formParameters.entrySet()) {
                this.formParameters$key.add($lombokEntry.getKey());
                this.formParameters$value.add($lombokEntry.getValue());
            }
            return this;
        }

        public OAuth2HttpRequestBuilder clearFormParameters() {
            if (this.formParameters$key != null) {
                this.formParameters$key.clear();
                this.formParameters$value.clear();
            }
            return this;
        }

        public OAuth2HttpRequest build() {
            Map<String, String> formParameters;
            switch (this.formParameters$key == null ? 0 : this.formParameters$key.size()) {
                case 0:
                    formParameters = java.util.Collections.emptyMap();
                    break;
                case 1:
                    formParameters = java.util.Collections.singletonMap(this.formParameters$key.get(0), this.formParameters$value.get(0));
                    break;
                default:
                    formParameters = new java.util.LinkedHashMap<String, String>(this.formParameters$key.size() < 1073741824 ? 1 + this.formParameters$key.size() + (this.formParameters$key.size() - 3) / 3 : Integer.MAX_VALUE);
                    for (int $i = 0; $i < this.formParameters$key.size(); $i++)
                        formParameters.put(this.formParameters$key.get($i), this.formParameters$value.get($i));
                    formParameters = java.util.Collections.unmodifiableMap(formParameters);
            }

            return new OAuth2HttpRequest(tokenEndpointUrl, oAuth2HttpHeaders, formParameters);
        }

        @Override
        public String toString() {
            return "OAuth2HttpRequest.OAuth2HttpRequestBuilder(tokenEndpointUrl=" + this.tokenEndpointUrl + ", oAuth2HttpHeaders=" + this.oAuth2HttpHeaders + ", formParameters$key=" + this.formParameters$key + ", formParameters$value=" + this.formParameters$value + ")";
        }
    }
}
