package no.nav.security.oidc.validation;

/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */

@SuppressWarnings("serial")
public class OIDCTokenValidatorException extends Exception {
	
	public OIDCTokenValidatorException(String message, Throwable cause){
		super(message,  cause);
	}
}
