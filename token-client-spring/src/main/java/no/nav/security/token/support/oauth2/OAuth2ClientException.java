package no.nav.security.token.support.oauth2;

public class OAuth2ClientException extends RuntimeException {

    public OAuth2ClientException(String message) {
        super(message);
    }

    public OAuth2ClientException(String message, Throwable cause) {
        super(message, cause);
    }
}
