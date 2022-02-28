package no.nav.security.token.support.client.core.http;

import java.util.*;

import static java.lang.String.CASE_INSENSITIVE_ORDER;

public class OAuth2HttpHeaders {

    private final Map<String, List<String>> headers;

    private OAuth2HttpHeaders(final Map<String, List<String>> headers) {
        this.headers = Optional.ofNullable(headers).orElse(Map.of());
    }

    public static OAuth2HttpHeaders of(Map<String, List<String>> headers) {
        return new OAuth2HttpHeaders(headers);
    }

    public static Builder builder() {
        return new Builder();
    }

    public Map<String, List<String>> headers() {
        return headers;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        var that = (OAuth2HttpHeaders) o;
        return Objects.equals(headers, that.headers);
    }

    @Override
    public int hashCode() {
        return Objects.hash(headers);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + " [headers=" + headers + "]";
    }

    public static class Builder {
        private final TreeMap<String, List<String>> headersMap;

        public Builder() {
            headersMap = new TreeMap<>(CASE_INSENSITIVE_ORDER);
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
