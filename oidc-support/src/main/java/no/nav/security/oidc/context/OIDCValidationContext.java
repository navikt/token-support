package no.nav.security.oidc.context;
/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */
import javax.swing.text.html.Option;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

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
	
	public boolean hasValidTokenFor(String issuerName){
		return this.validatedTokens.containsKey(issuerName);
	}
	
	public boolean hasTokenFor(String issuerName) {
		return this.validatedTokens.containsKey(issuerName);
	}
	
	public TokenContext getToken(String issuerName) {
		return this.validatedTokens.get(issuerName);
	}
	
	public OIDCClaims getClaims(String issuerName) {
		return this.validatedClaims.get(issuerName);
	}
	
	public boolean hasValidToken() {
		return this.validatedTokens.size() > 0;
	}
	
	public List<String> getIssuers(){
		return issuers;
	}

	public Optional<TokenContext> getFirstValidToken(){
		Optional<String> issuer = getIssuers().stream().findFirst();
		return issuer.isPresent()
				? Optional.of(getToken(issuer.get())) : Optional.empty();
	}
	
}
