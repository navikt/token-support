package no.nav.security.oidc.exceptions;

import java.util.Date;

public class OIDCTokenValidatorException extends RuntimeException {

    private final Date expiryDate;

    public OIDCTokenValidatorException(String msg) {
        this(msg, null, null);
    }

    public OIDCTokenValidatorException(String msg, Date expiryDate) {
        this(msg, expiryDate, null);
    }

    public OIDCTokenValidatorException(String msg, Date expiryDate, Throwable cause) {
        super(msg, cause);
        this.expiryDate = expiryDate;
    }

    public Date getExpiryDate() {
        return expiryDate;
    }
}
