package no.nav.security.oidc.validation;

/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */

import java.net.URL;
import java.text.ParseException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
	private static Logger log = LoggerFactory.getLogger(OIDCTokenValidator.class);
	private final JWSAlgorithm jwsAlg = JWSAlgorithm.RS256;
	private final Map<String, IDTokenValidator> audienceValidatorMap;

	public OIDCTokenValidator(String issuer, String clientId, URL jwkSetUrl, ResourceRetriever jwksResourceRetriever) {		
		this(issuer, Collections.singletonList(clientId), jwkSetUrl, jwksResourceRetriever);
	}
	
	public OIDCTokenValidator(String issuer, List<String> acceptedAudience, URL jwkSetUrl, ResourceRetriever jwksResourceRetriever) {
		this.audienceValidatorMap = initializeMap(issuer, acceptedAudience, jwkSetUrl, jwksResourceRetriever);
	}

	public void assertValidToken(String tokenString) throws OIDCTokenValidatorException {
		assertValidToken(tokenString, null);
	}

	public void assertValidToken(String tokenString, String expectedNonce) throws OIDCTokenValidatorException {
		try {
			JWT token = JWTParser.parse(tokenString);	
			get(token).validate(token, expectedNonce != null ? new Nonce(expectedNonce) : null);
		} catch (Throwable t) {
			throw new OIDCTokenValidatorException("token validation failed: " + t, t);
		}
	}
	
	protected IDTokenValidator get(JWT jwt) throws ParseException, OIDCTokenValidatorException {
		List<String> tokenAud = jwt.getJWTClaimsSet().getAudience();
		for (String aud : tokenAud) {
			if(audienceValidatorMap.containsKey(aud)){
				return audienceValidatorMap.get(aud);
			}
		}
		log.warn("could not find validator for token audience:" + tokenAud);
		throw new OIDCTokenValidatorException("could not find appropriate validator to validate token. check your config.");
	}
	
	protected IDTokenValidator createValidator(String issuer, String clientId, URL jwkSetUrl, ResourceRetriever jwksResourceRetriever){
		Issuer iss = new Issuer(issuer);
		ClientID clientID = new ClientID(clientId);
		IDTokenValidator validator = new IDTokenValidator(iss, clientID, jwsAlg, jwkSetUrl, jwksResourceRetriever);
		return validator;
	}
	
	private Map<String, IDTokenValidator> initializeMap(String issuer, List<String> acceptedAudience, URL jwkSetUrl, ResourceRetriever jwksResourceRetriever){
		if(acceptedAudience == null || acceptedAudience.isEmpty()){
			throw new IllegalArgumentException("accepted audience cannot be null or empty in validator config.");
		}
		Map<String, IDTokenValidator> map = new HashMap<>();
		for (String aud : acceptedAudience) {
			map.put(aud, createValidator(issuer, aud, jwkSetUrl, jwksResourceRetriever));
		}
		return map;
	}	
}
