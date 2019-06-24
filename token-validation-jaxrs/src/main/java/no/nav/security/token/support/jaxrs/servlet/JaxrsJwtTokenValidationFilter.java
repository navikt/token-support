package no.nav.security.token.support.jaxrs.servlet;

import no.nav.security.token.support.core.configuration.MultiIssuerConfiguration;
import no.nav.security.token.support.filter.JwtTokenValidationFilter;
import no.nav.security.token.support.jaxrs.JaxrsTokenValidationContextHolder;
import no.nav.security.token.support.core.validation.JwtTokenValidationHandler;

public class JaxrsJwtTokenValidationFilter extends JwtTokenValidationFilter {

    public JaxrsJwtTokenValidationFilter(MultiIssuerConfiguration oidcConfig) {
        super(new JwtTokenValidationHandler(oidcConfig), JaxrsTokenValidationContextHolder.getHolder());
    }
}
