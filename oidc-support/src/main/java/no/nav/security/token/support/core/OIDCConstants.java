package no.nav.security.token.support.core;

public class OIDCConstants {

    // TODO make private?
    public static final String COOKIE_NAME = "%s-idtoken";
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String OIDC_VALIDATION_CONTEXT = "no.nav.security.oidc.validation.context";

    public static String getDefaultCookieName(String issuer) {
        return String.format(COOKIE_NAME, issuer);
    }

}
