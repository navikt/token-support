package no.nav.security.oidc;
/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */
public class OIDCConstants {

	public static final String COOKIE_NAME = "%s-idtoken";
	public static final String AUTHORIZATION_HEADER = "Authorization";
	public static final String OIDC_VALIDATION_CONTEXT = "no.nav.security.oidc.validation.context";
	public static final String PROPAGATED_HEADERS = "no.nav.security.oidc.http.propagated_headers";
	
	
	public static String getDefaultCookieName(String issuer) {
		return String.format(COOKIE_NAME, issuer);
	}
	
}
