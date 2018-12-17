package no.nav.security.oidc.exceptions;

public class MissingPropertyException extends RuntimeException {

    public MissingPropertyException(String msg) {
        this(msg, null);
    }

    public MissingPropertyException(Throwable cause) {
        this(null, cause);
    }

    public MissingPropertyException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
