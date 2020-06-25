package no.nav.security.token.support.core.exceptions;

import java.util.Date;

public class JwtTokenValidatorException extends RuntimeException {

    private final Date expiryDate;

    public JwtTokenValidatorException(String msg) {
        this(msg, null, null);
    }

    public JwtTokenValidatorException(String msg, Throwable cause) {
        this(msg, null, cause);
    }

    public JwtTokenValidatorException(String msg, Date expiryDate, Throwable cause) {
        super(msg, cause);
        this.expiryDate = expiryDate;
    }

    public Date getExpiryDate() {
        return expiryDate;
    }
}
