package no.nav.security.oidc.context;

public interface OIDCRequestContextHolder {

    Object getRequestAttribute(String name);

    void setRequestAttribute(String name, Object value);

    OIDCValidationContext getOIDCValidationContext();

    void setOIDCValidationContext(OIDCValidationContext oidcValidationContext);
}
