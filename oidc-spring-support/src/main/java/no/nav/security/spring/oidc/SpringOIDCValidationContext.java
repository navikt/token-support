package no.nav.security.spring.oidc;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import no.nav.security.oidc.OIDCConstants;
import no.nav.security.oidc.context.OIDCValidationContext;
import no.nav.security.oidc.filter.OIDCRequestContextHolder;
import no.nav.security.oidc.validation.OIDCClaims;

@Component
public class SpringOIDCValidationContext {
	
	@Autowired
	OIDCRequestContextHolder requestContext;

	
	@Deprecated // use context() or getClaims(String issuer)
	public OIDCValidationContext get(String issuer) {
		return (OIDCValidationContext)requestContext.getRequestAttribute(OIDCConstants.OIDC_VALIDATION_CONTEXT);
	}
	
	public OIDCValidationContext context() {
		return (OIDCValidationContext)requestContext.getRequestAttribute(OIDCConstants.OIDC_VALIDATION_CONTEXT);
	}
	
	public OIDCClaims getClaims(String issuer) {
		return context().getClaims(issuer);
	}

}
