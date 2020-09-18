package no.nav.security.token.support.core.validation;

import no.nav.security.token.support.core.exceptions.JwtTokenValidatorException;

public interface JwtTokenValidator {

    void assertValidToken(String tokenString) throws JwtTokenValidatorException;
}
