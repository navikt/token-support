package no.nav.security.oidc.jaxrs;

import no.nav.security.oidc.context.OIDCRequestContextHolder;
import no.nav.security.oidc.context.OIDCValidationContext;

public class OidcRequestContext implements OIDCRequestContextHolder {

    private static final OIDCRequestContextHolder oidcRequestContextHolder = new OidcRequestContext();

    private OidcRequestContext() {}

    public static OIDCRequestContextHolder getHolder() {
        return oidcRequestContextHolder;
    }

    private static final ThreadLocal<OIDCValidationContext> validationContextHolder = new ThreadLocal<>();

    @Override
    public Object getRequestAttribute(String name) {
        throw new UnsupportedOperationException("Unnecessary method");
    }

    @Override
    public void setRequestAttribute(String name, Object value) {
        throw new UnsupportedOperationException("Unnecessary method");
    }

    @Override
    public OIDCValidationContext getOIDCValidationContext() {
        return validationContextHolder.get();
    }

    @Override
    public void setOIDCValidationContext(OIDCValidationContext oidcValidationContext) {
        if(validationContextHolder.get() != null && oidcValidationContext != null) {
            throw new IllegalStateException("Should not overwrite the OidcValidationContext");
        }
        validationContextHolder.set(oidcValidationContext);
    }
}
