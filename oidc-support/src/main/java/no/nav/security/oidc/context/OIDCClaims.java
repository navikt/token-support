package no.nav.security.oidc.context;
/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */
import java.text.ParseException;
import java.util.List;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;

public class OIDCClaims {
	
	private JWT claims;
	public OIDCClaims(JWT jwt) {
		this.claims = jwt;
	}
	
	public String get(String name){
		try {
			return getClaimSet().getStringClaim(name);
		} catch (ParseException e) {
			throw new RuntimeException(e);
		}
	}
	
	public JWTClaimsSet getClaimSet() {
		try {
			return this.claims.getJWTClaimsSet();
		} catch (ParseException e) {
			throw new RuntimeException(e);
		}
	}
	
	public String getSubject(){
		return getClaimSet().getSubject();
	}
	
	public List<String> getAsList(String name){
		try {
			return getClaimSet().getStringListClaim(name);
		} catch (ParseException e) {
			throw new RuntimeException(e);
		}
	}
	
	public boolean containsClaim(String name, String value){
		String claimValue = get(name); 
		return claimValue != null && claimValue.equals(value); 
	}

}
