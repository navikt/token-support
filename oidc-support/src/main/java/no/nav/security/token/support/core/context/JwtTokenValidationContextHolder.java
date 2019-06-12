package no.nav.security.token.support.core.context;

public interface JwtTokenValidationContextHolder {

    Object getRequestAttribute(String name);

    void setRequestAttribute(String name, Object value);

    JwtTokenValidationContext getOIDCValidationContext();

    void setOIDCValidationContext(JwtTokenValidationContext jwtTokenValidationContext);
}
