package no.nav.security.token.support.core.jaxrs;

import no.nav.security.token.support.core.context.JwtTokenValidationContextHolder;

public class JaxrsJwtTokenContextHolder implements JwtTokenValidationContextHolder {

    private static final JwtTokenValidationContextHolder JWT_BEARER_TOKEN_CONTEXT_HOLDER = new JaxrsJwtTokenContextHolder();

    private JaxrsJwtTokenContextHolder() {}

    public static JwtTokenValidationContextHolder getHolder() {
        return JWT_BEARER_TOKEN_CONTEXT_HOLDER;
    }

    private static final ThreadLocal<no.nav.security.token.support.core.context.JwtTokenValidationContext> validationContextHolder = new ThreadLocal<>();

    @Override
    public Object getRequestAttribute(String name) {
        throw new UnsupportedOperationException("Unnecessary method");
    }

    @Override
    public void setRequestAttribute(String name, Object value) {
        throw new UnsupportedOperationException("Unnecessary method");
    }

    @Override
    public no.nav.security.token.support.core.context.JwtTokenValidationContext getOIDCValidationContext() {
        return validationContextHolder.get();
    }

    @Override
    public void setOIDCValidationContext(no.nav.security.token.support.core.context.JwtTokenValidationContext jwtTokenValidationContext) {
        if(validationContextHolder.get() != null && jwtTokenValidationContext != null) {
            throw new IllegalStateException("Should not overwrite the OidcValidationContext");
        }
        validationContextHolder.set(jwtTokenValidationContext);
    }
}
