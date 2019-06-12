package no.nav.security.token.support.core.jaxrs.servlet;

import no.nav.security.token.support.core.configuration.MultiIssuerConfiguration;
import no.nav.security.token.support.core.filter.OIDCTokenValidationFilter;
import no.nav.security.token.support.core.jaxrs.JaxrsJwtTokenContextHolder;
import no.nav.security.token.support.core.validation.JwtTokenValidationHandler;

public class JaxrsOIDCTokenValidationFilter extends OIDCTokenValidationFilter {

    public JaxrsOIDCTokenValidationFilter(MultiIssuerConfiguration oidcConfig) {
        super(new JwtTokenValidationHandler(oidcConfig), JaxrsJwtTokenContextHolder.getHolder());
    }
}
