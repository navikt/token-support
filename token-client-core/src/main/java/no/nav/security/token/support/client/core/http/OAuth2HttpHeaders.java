package no.nav.security.token.support.client.core.http;

import java.util.*;

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

    public boolean equals(final Object o) {
        if (o == this) return true;
        if (!(o instanceof OAuth2HttpHeaders)) return false;
        final OAuth2HttpHeaders other = (OAuth2HttpHeaders) o;
        if (!other.canEqual((Object) this)) return false;
        final Object this$headers = this.headers;
        final Object other$headers = other.headers;
        if (this$headers == null ? other$headers != null : !this$headers.equals(other$headers)) return false;
        return true;
    }

    protected boolean canEqual(final Object other) {
        return other instanceof OAuth2HttpHeaders;
    }

    public int hashCode() {
        final int PRIME = 59;
        int result = 1;
        final Object $headers = this.headers;
        result = result * PRIME + ($headers == null ? 43 : $headers.hashCode());
        return result;
    }

    public String toString() {
        return "OAuth2HttpHeaders(headers=" + this.headers + ")";
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
