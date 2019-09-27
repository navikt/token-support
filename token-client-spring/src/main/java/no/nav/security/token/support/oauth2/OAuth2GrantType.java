package no.nav.security.token.support.oauth2;

public class OAuth2GrantType {
    public static final OAuth2GrantType JWT_BEARER = new OAuth2GrantType("urn:ietf:params:oauth:grant-type:jwt-bearer");
    public static final OAuth2GrantType CLIENT_CREDENTIALS = new OAuth2GrantType("client_credentials");
    private final String value;

    public OAuth2GrantType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    @Override
    public String toString() {
        return value;
    }
}
