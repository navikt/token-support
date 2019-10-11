package no.nav.security.token.support.core.exceptions;

import java.net.URL;

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

    public MetaDataNotAvailableException(URL url, Exception e) {
        this(String.format("could not retrieve metadata from url: %s. received exception %s", url, e), e);
    }

}
