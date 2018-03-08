package no.nav.security.oidc.context;
/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import no.nav.security.oidc.validation.OIDCClaims;

public class OIDCValidationContext {
	
	private Map<String, TokenContext> validatedTokens;
	private Map<String, OIDCClaims> validatedClaims;
	private List<String> issuers;
	
	public OIDCValidationContext() {
		this.validatedTokens = new ConcurrentHashMap<>();
		this.validatedClaims = new ConcurrentHashMap<>();
		this.issuers = new ArrayList<>();
	}

	public void addValidatedToken(String issuer, TokenContext tokenContext, OIDCClaims claims) {
		this.validatedTokens.put(issuer, tokenContext);
		this.validatedClaims.put(issuer, claims);
		this.issuers.add(issuer);
	}
	
	public boolean hasValidTokenFor(String issuer){
		return this.validatedTokens.containsKey(issuer);
	}
	
	public boolean hasTokenFor(String issuer) {
		return this.validatedTokens.containsKey(issuer);
	}
	
	public TokenContext getToken(String issuer) {
		return this.validatedTokens.get(issuer);
	}
	
	public OIDCClaims getClaims(String issuer) {
		return this.validatedClaims.get(issuer);
	}
	
	public boolean hasValidToken() {
		return this.validatedTokens.size() > 0;
	}
	
	public List<String> getIssuers(){
		return issuers;
	}
	
}
