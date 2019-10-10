package no.nav.security.token.support.oauth2;

import java.util.Optional;

public class OAuth2GrantType {
    public static final OAuth2GrantType JWT_BEARER = new OAuth2GrantType("urn:ietf:params:oauth:grant-type:jwt-bearer");
    public static final OAuth2GrantType CLIENT_CREDENTIALS = new OAuth2GrantType("client_credentials");
    private final String value;

    public OAuth2GrantType(String value) {
        this.value = Optional.ofNullable(value)
        .orElseThrow(() -> new OAuth2ClientException("value for OAuth2GrantType cannot be null"));
    }

    public String getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o){
        return Optional.ofNullable(o)
            .filter(OAuth2GrantType.class::isInstance)
            .map(OAuth2GrantType.class::cast)
            .filter(grantType -> value.equals(grantType.getValue()))
            .isPresent();
    }

    @Override
    public String toString() {
        return value;
    }
}
