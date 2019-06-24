package no.nav.security.token.support.jaxrs;

import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import no.nav.security.token.support.core.context.TokenValidationContext;

public class JaxrsTokenValidationContextHolder implements TokenValidationContextHolder {

    private static final TokenValidationContextHolder JWT_BEARER_TOKEN_CONTEXT_HOLDER = new JaxrsTokenValidationContextHolder();

    private JaxrsTokenValidationContextHolder() {}

    public static TokenValidationContextHolder getHolder() {
        return JWT_BEARER_TOKEN_CONTEXT_HOLDER;
    }

    private static final ThreadLocal<TokenValidationContext> validationContextHolder = new ThreadLocal<>();

    @Override
    public TokenValidationContext getTokenValidationContext() {
        return validationContextHolder.get();
    }

    @Override
    public void setTokenValidationContext(TokenValidationContext tokenValidationContext) {
        if(validationContextHolder.get() != null && tokenValidationContext != null) {
            throw new IllegalStateException("Should not overwrite the TokenValidationContext");
        }
        validationContextHolder.set(tokenValidationContext);
    }
}
