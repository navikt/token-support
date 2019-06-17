package no.nav.security.token.support.core.exceptions;

public class JwtTokenMissingException extends RuntimeException {
    public JwtTokenMissingException(String message) {
        super(message);
    }
}
