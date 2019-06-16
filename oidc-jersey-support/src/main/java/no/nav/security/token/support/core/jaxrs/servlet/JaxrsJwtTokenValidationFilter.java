package no.nav.security.token.support.core.jaxrs.servlet;

import no.nav.security.token.support.core.configuration.MultiIssuerConfiguration;
import no.nav.security.token.support.core.filter.JwtTokenValidationFilter;
import no.nav.security.token.support.core.jaxrs.JaxrsTokenContextHolder;
import no.nav.security.token.support.core.validation.JwtTokenValidationHandler;

public class JaxrsJwtTokenValidationFilter extends JwtTokenValidationFilter {

    public JaxrsJwtTokenValidationFilter(MultiIssuerConfiguration oidcConfig) {
        super(new JwtTokenValidationHandler(oidcConfig), JaxrsTokenContextHolder.getHolder());
    }
}
