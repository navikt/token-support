package no.nav.security.oidc.jaxrs.servlet;

import no.nav.security.oidc.configuration.MultiIssuerConfiguration;
import no.nav.security.oidc.filter.OIDCTokenValidationFilter;
import no.nav.security.oidc.jaxrs.OidcRequestContext;

public class JaxrsOIDCTokenValidationFilter extends OIDCTokenValidationFilter {

    public JaxrsOIDCTokenValidationFilter(MultiIssuerConfiguration oidcConfig) {
        super(oidcConfig, OidcRequestContext.getHolder());
    }
}
