package no.nav.security.token.support.core;

public class JwtTokenConstants {

    // TODO make private?
    public static final String COOKIE_NAME = "%s-idtoken";
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String EXPIRY_THRESHOLD_ENV_PROPERTY = "no.nav.security.jwt.expirythreshold";
    public static final String TOKEN_VALIDATION_FILTER_ORDER_PROPERTY = "no.nav.security.jwt.tokenvalidationfilter.order";
    public static final String TOKEN_EXPIRES_SOON_HEADER = "x-token-expires-soon";

    public static String getDefaultCookieName(String issuer) {
        return String.format(COOKIE_NAME, issuer);
    }

}
