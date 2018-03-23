package no.nav.security.oidc.configuration;
/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */
public interface OIDCProperties {

	public static final String ISSUERS = "no.nav.security.oidc.issuers";
	public static final String URI = "no.nav.security.oidc.issuer.%s.uri";
	public static final String ACCEPTEDAUDIENCE = "no.nav.security.oidc.issuer.%s.acceptedaudience";
	public static final String COOKIE_NAME = "no.nav.security.oidc.issuer.%s.cookie_name";
	
	String get(String key);
	
}
