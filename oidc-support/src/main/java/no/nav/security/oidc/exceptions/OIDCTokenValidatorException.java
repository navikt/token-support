package no.nav.security.oidc.exceptions;

import java.util.Date;

@SuppressWarnings("serial")
public class OIDCTokenValidatorException extends Exception {

    private final Date expiryDate;

    public OIDCTokenValidatorException(String message) {
        this(message, null, null);
    }

    public OIDCTokenValidatorException(String message, Date expiryDate) {
        this(message, expiryDate, null);
    }

    public OIDCTokenValidatorException(String message, Date expiryDate, Throwable cause) {
        super(message, cause);
        this.expiryDate = expiryDate;
    }

    public Date getExpiryDate() {
        return expiryDate;
    }
}
