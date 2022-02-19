package no.nav.security.token.support.client.core;

public class OAuth2ClientException extends RuntimeException {

    public OAuth2ClientException(String message) {
        this(message,null);
    }

    public OAuth2ClientException(String message, Throwable cause) {
        super(message, cause);
    }
}
