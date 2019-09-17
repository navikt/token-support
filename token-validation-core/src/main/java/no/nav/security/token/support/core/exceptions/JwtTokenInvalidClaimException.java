package no.nav.security.token.support.core.exceptions;

public class JwtTokenInvalidClaimException extends RuntimeException {

    public JwtTokenInvalidClaimException(String message) {
        super(message);
    }
}
