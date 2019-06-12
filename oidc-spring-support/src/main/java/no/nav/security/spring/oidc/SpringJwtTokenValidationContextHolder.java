package no.nav.security.spring.oidc;
/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */
import no.nav.security.token.support.core.context.JwtTokenValidationContext;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import no.nav.security.token.support.core.OIDCConstants;
import no.nav.security.token.support.core.context.JwtTokenValidationContextHolder;

import java.util.Collections;

public class SpringJwtTokenValidationContextHolder implements JwtTokenValidationContextHolder {

	@Override
	public Object getRequestAttribute(String name) {
		return RequestContextHolder.currentRequestAttributes().getAttribute(name, RequestAttributes.SCOPE_REQUEST);
	}

	@Override
	public void setRequestAttribute(String name, Object value) {
		RequestContextHolder.currentRequestAttributes().setAttribute(name, value, RequestAttributes.SCOPE_REQUEST);
	}

	@Override
	public JwtTokenValidationContext getOIDCValidationContext() {
		JwtTokenValidationContext jwtTokenValidationContext = (JwtTokenValidationContext)getRequestAttribute(OIDCConstants.OIDC_VALIDATION_CONTEXT);
		return jwtTokenValidationContext != null ? jwtTokenValidationContext : new JwtTokenValidationContext(Collections.emptyMap());
	}

	@Override
	public void setOIDCValidationContext(JwtTokenValidationContext jwtTokenValidationContext) {
		setRequestAttribute(OIDCConstants.OIDC_VALIDATION_CONTEXT, jwtTokenValidationContext);
	}
}
