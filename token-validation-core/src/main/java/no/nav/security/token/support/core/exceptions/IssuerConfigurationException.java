package no.nav.security.token.support.core.exceptions;

public class IssuerConfigurationException extends RuntimeException {

    public IssuerConfigurationException(String message) {
        super(message);
    }

    public IssuerConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }

    public IssuerConfigurationException(Throwable cause) {
        super(cause);
    }
}
