package no.nav.security.token.support.client.core.http;

import lombok.EqualsAndHashCode;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

@ToString
@EqualsAndHashCode
public class OAuth2HttpHeaders {

    private final Map<String, List<String>> headers;

    private OAuth2HttpHeaders(final Map<String, List<String>> headers) {
        this.headers = Optional.ofNullable(headers).orElse(Map.of());
    }

    public static OAuth2HttpHeaders of(Map<String, List<String>> headers) {
        return new OAuth2HttpHeaders(headers);
    }

    @SuppressWarnings("WeakerAccess")
    public static Builder builder() {
        return new Builder();
    }

    @SuppressWarnings("WeakerAccess")
    public Map<String, List<String>> headers() {
        return headers;
    }

    @SuppressWarnings("WeakerAccess")
    public static class Builder {
        private final TreeMap<String, List<String>> headersMap;

        public Builder() {
            headersMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        }

        public Builder header(String name, String value) {
            headersMap.computeIfAbsent(name, k -> new ArrayList<>(1))
                .add(value);
            return this;
        }

        public OAuth2HttpHeaders build() {
            return OAuth2HttpHeaders.of(headersMap);
        }
    }

}
