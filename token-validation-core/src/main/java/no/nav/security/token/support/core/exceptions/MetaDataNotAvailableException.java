package no.nav.security.token.support.core.exceptions;

import java.net.URL;

public class MetaDataNotAvailableException extends RuntimeException {
    public MetaDataNotAvailableException(Exception e) {
        super(e);
    }
    public MetaDataNotAvailableException(String msg, URL url, Exception e) {
        super(String.format("Could not retrieve metadata from url: %s. %s", url,msg), e);
    }

}
