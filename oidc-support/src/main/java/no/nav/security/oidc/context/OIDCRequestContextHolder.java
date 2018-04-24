package no.nav.security.oidc.context;
/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */

public interface OIDCRequestContextHolder {
	
	Object getRequestAttribute(String name);
	void setRequestAttribute(String name, Object value);
	OIDCValidationContext getOIDCValidationContext();
	void setOIDCValidationContext(OIDCValidationContext oidcValidationContext);
}
