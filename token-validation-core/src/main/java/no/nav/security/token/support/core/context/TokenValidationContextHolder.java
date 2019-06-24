package no.nav.security.token.support.core.context;

public interface TokenValidationContextHolder {

    TokenValidationContext getTokenValidationContext();

    void setTokenValidationContext(TokenValidationContext tokenValidationContext);
}
