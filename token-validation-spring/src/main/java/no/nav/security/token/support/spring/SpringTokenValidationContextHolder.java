package no.nav.security.token.support.spring;

import no.nav.security.token.support.core.context.TokenValidationContext;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import no.nav.security.token.support.core.context.TokenValidationContextHolder;

import java.util.Collections;

public class SpringTokenValidationContextHolder implements TokenValidationContextHolder {

    private static final String TOKEN_VALIDATION_CONTEXT_ATTRIBUTE = SpringTokenValidationContextHolder.class.getName();

	@Override
	public TokenValidationContext getTokenValidationContext() {
		TokenValidationContext tokenValidationContext = (TokenValidationContext)getRequestAttribute(TOKEN_VALIDATION_CONTEXT_ATTRIBUTE);
		return tokenValidationContext != null ? tokenValidationContext : new TokenValidationContext(Collections.emptyMap());
	}

	@Override
	public void setTokenValidationContext(TokenValidationContext tokenValidationContext) {
		setRequestAttribute(TOKEN_VALIDATION_CONTEXT_ATTRIBUTE, tokenValidationContext);
	}

    private Object getRequestAttribute(String name) {
        return RequestContextHolder.currentRequestAttributes().getAttribute(name, RequestAttributes.SCOPE_REQUEST);
    }

    private void setRequestAttribute(String name, Object value) {
        RequestContextHolder.currentRequestAttributes().setAttribute(name, value, RequestAttributes.SCOPE_REQUEST);
    }
}
