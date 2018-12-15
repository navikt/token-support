package no.nav.security.oidc.exceptions;

public class MetaDataNotAvailableException extends RuntimeException {

    public MetaDataNotAvailableException(String msg) {
        this(msg, null);
    }

    public MetaDataNotAvailableException(Throwable cause) {
        this(null, cause);
    }

    public MetaDataNotAvailableException(String msg, Throwable cause) {
        super(msg, cause);
    }

}
