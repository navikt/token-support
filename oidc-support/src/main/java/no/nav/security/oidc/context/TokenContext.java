package no.nav.security.oidc.context;
/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */
public class TokenContext {
	
	private String idToken;
	private String issuer;

	public TokenContext(String issuer, String idToken) {
		super();
		this.issuer = issuer;
		this.idToken = idToken;
	}
	
	public String getIssuer() {
		return issuer;
	}

	public String getIdToken() {
		return idToken;
	}

	@Override
	public String toString() {
		return "TokenContext [issuer=" + issuer + ",idToken=" + idToken + "]";
	}
	
	

	

}
