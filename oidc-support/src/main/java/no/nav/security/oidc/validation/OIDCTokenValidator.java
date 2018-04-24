package no.nav.security.oidc.validation;

/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */

import java.net.URL;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

import no.nav.security.oidc.exceptions.OIDCTokenValidatorException;


public class OIDCTokenValidator {
	
	// The required parameters
	private final Issuer iss;
	private final ClientID clientID;
	private final JWSAlgorithm jwsAlg = JWSAlgorithm.RS256;
	private final URL jwkSetURL;
	IDTokenValidator validator;

	public OIDCTokenValidator(String issuer, String clientId, URL jwkSetUrl, ResourceRetriever jwksResourceRetriever) {
		super();
		this.iss = new Issuer(issuer);
		this.clientID = new ClientID(clientId);
		this.jwkSetURL = jwkSetUrl;
		validator = new IDTokenValidator(iss, clientID, jwsAlg, jwkSetURL, jwksResourceRetriever);
		
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
