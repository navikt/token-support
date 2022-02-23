package no.nav.security.token.support.core.exceptions;

public class IssuerConfigurationException extends RuntimeException {
    public IssuerConfigurationException(String message) {
        this(message,null);
    }
    public IssuerConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}
