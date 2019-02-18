package no.nav.security.oidc.exceptions;

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
        this("Kunne ikke hente metadata fra " + url, e);
    }

}
