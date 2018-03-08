package no.nav.security.oidc.validation;
/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */
import java.text.ParseException;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;

public class OIDCClaims {
	
	private JWT claims;
	public OIDCClaims(JWT jwt) {
		this.claims = jwt;
	}
	
	public JWTClaimsSet getClaimSet() {
		try {
			return this.claims.getJWTClaimsSet();
		} catch (ParseException e) {
			throw new RuntimeException(e);
		}
	}

}
