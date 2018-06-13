package no.nav.security.oidc.jaxrs.servlet;

import no.nav.security.oidc.configuration.MultiIssuerConfiguraton;
import no.nav.security.oidc.filter.OIDCTokenValidationFilter;
import no.nav.security.oidc.jaxrs.OidcRequestContext;

public class JaxrsOIDCTokenValidationFilter extends OIDCTokenValidationFilter {

    public JaxrsOIDCTokenValidationFilter(MultiIssuerConfiguraton oidcConfig) {
        super(oidcConfig, OidcRequestContext.getHolder());
    }
}
