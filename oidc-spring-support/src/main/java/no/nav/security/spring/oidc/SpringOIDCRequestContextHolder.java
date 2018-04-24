package no.nav.security.spring.oidc;
/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import no.nav.security.oidc.OIDCConstants;
import no.nav.security.oidc.context.OIDCRequestContextHolder;
import no.nav.security.oidc.context.OIDCValidationContext;

public class SpringOIDCRequestContextHolder implements OIDCRequestContextHolder {

	@Override
	public Object getRequestAttribute(String name) {
		return RequestContextHolder.currentRequestAttributes().getAttribute(name, RequestAttributes.SCOPE_REQUEST);
	}

	@Override
	public void setRequestAttribute(String name, Object value) {
		RequestContextHolder.currentRequestAttributes().setAttribute(name, value, RequestAttributes.SCOPE_REQUEST);
	}

	@Override
	public OIDCValidationContext getOIDCValidationContext() {
		return (OIDCValidationContext)getRequestAttribute(OIDCConstants.OIDC_VALIDATION_CONTEXT);
	}

	@Override
	public void setOIDCValidationContext(OIDCValidationContext oidcValidationContext) {
		setRequestAttribute(OIDCConstants.OIDC_VALIDATION_CONTEXT, oidcValidationContext);
	}
}
