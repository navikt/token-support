package no.nav.security.token.support.client.core;

import java.util.Optional;

public record OAuth2GrantType(String value) {
    public static final OAuth2GrantType JWT_BEARER = new OAuth2GrantType("urn:ietf:params:oauth:grant-type:jwt-bearer");
    public static final OAuth2GrantType CLIENT_CREDENTIALS = new OAuth2GrantType("client_credentials");
    public static final OAuth2GrantType TOKEN_EXCHANGE = new OAuth2GrantType("urn:ietf:params:oauth:grant-type:token-exchange");

    public OAuth2GrantType(String value) {
        this.value = Optional.ofNullable(value)
            .orElseThrow(() -> new OAuth2ClientException("value for OAuth2GrantType cannot be null"));
    }
}
