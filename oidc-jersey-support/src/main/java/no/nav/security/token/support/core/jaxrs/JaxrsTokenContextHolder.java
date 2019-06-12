package no.nav.security.token.support.core.jaxrs;

import no.nav.security.token.support.core.context.TokenContextHolder;
import no.nav.security.token.support.core.context.TokenValidationContext;

public class JaxrsTokenContextHolder implements TokenContextHolder {

    private static final TokenContextHolder JWT_BEARER_TOKEN_CONTEXT_HOLDER = new JaxrsTokenContextHolder();

    private JaxrsTokenContextHolder() {}

    public static TokenContextHolder getHolder() {
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
