package no.nav.security.token.support.core.context;

public interface TokenContextHolder {

    TokenValidationContext getTokenValidationContext();

    void setTokenValidationContext(TokenValidationContext tokenValidationContext);
}
