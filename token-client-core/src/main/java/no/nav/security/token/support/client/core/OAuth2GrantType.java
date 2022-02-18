package no.nav.security.token.support.client.core;

import java.util.Objects;
import java.util.Optional;

public class OAuth2GrantType {
    public static final OAuth2GrantType JWT_BEARER = new OAuth2GrantType("urn:ietf:params:oauth:grant-type:jwt-bearer");
    public static final OAuth2GrantType CLIENT_CREDENTIALS = new OAuth2GrantType("client_credentials");
    public static final OAuth2GrantType TOKEN_EXCHANGE = new OAuth2GrantType("urn:ietf:params:oauth:grant-type:token-exchange");
    private final String value;

    public OAuth2GrantType(String value) {
        this.value = Optional.ofNullable(value)
        .orElseThrow(() -> new OAuth2ClientException("value for OAuth2GrantType cannot be null"));
    }

    public String getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        OAuth2GrantType that = (OAuth2GrantType) o;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return value;
    }
}
