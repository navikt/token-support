package no.nav.security.oidc.validation;

/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */

import java.net.URL;
import com.nimbusds.jose.*;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.*;
import com.nimbusds.oauth2.sdk.id.*;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.validators.*;

import no.nav.security.oidc.http.HttpClient;
import no.nav.security.oidc.http.HttpClientJsonResourceRetriever;

public class OIDCTokenValidator {

	public static int DEFAULT_HTTP_CONNECT_TIMEOUT = 21050;
	public static int DEFAULT_HTTP_READ_TIMEOUT = 30000;
	public static int DEFAULT_HTTP_SIZE_LIMIT = 50 * 1024;
	
	// The required parameters
	private final Issuer iss;
	private final ClientID clientID;
	private final JWSAlgorithm jwsAlg = JWSAlgorithm.RS256;
	private final URL jwkSetURL;
	IDTokenValidator validator;

	public OIDCTokenValidator(String issuer, String clientId, URL jwkSetUrl, HttpClient httpClient) {
		super();
		this.iss = new Issuer(issuer);
		this.clientID = new ClientID(clientId);
		this.jwkSetURL = jwkSetUrl;
		validator = new IDTokenValidator(iss, clientID, jwsAlg, jwkSetURL, httpClient == null ? 
				new DefaultResourceRetriever(
				DEFAULT_HTTP_CONNECT_TIMEOUT, DEFAULT_HTTP_READ_TIMEOUT, DEFAULT_HTTP_SIZE_LIMIT) : 
				new HttpClientJsonResourceRetriever(httpClient));
		
	}

	public void assertValidToken(String tokenString) throws OIDCTokenValidatorException {
		assertValidToken(tokenString, null);
	}

	public void assertValidToken(String tokenString, String expectedNonce) throws OIDCTokenValidatorException {
		try {
			JWT token = JWTParser.parse(tokenString);
			validator.validate(token, expectedNonce != null ? new Nonce(expectedNonce) : null);
		} catch (Throwable t) {
			throw new OIDCTokenValidatorException("token validation failed: " + t, t);
		}
	}
}
