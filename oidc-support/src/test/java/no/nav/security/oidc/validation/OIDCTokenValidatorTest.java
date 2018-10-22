package no.nav.security.oidc.validation;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSHeader.Builder;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import no.nav.security.oidc.configuration.OIDCResourceRetriever;
import no.nav.security.oidc.exceptions.OIDCTokenValidatorException;

public class OIDCTokenValidatorTest {
	
	@Rule
	public ExpectedException thrown = ExpectedException.none();
	
	private static final String ISSUER = "https://issuer";	
	private static final String KEYID = "myKeyId";
	private RSAKey rsaJwk;

	@Before
	public void setupKeys() throws NoSuchAlgorithmException {

		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(2048); // just for testing so 1024 is ok
		KeyPair keyPair = gen.generateKeyPair();
		rsaJwk = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
				.privateKey((RSAPrivateKey) keyPair.getPrivate())
				.keyID(KEYID).build();
	}

	@Test 
	public void testAssertValidToken() throws IOException, OIDCTokenValidatorException {
		OIDCTokenValidator validator = createOIDCTokenValidator(ISSUER, Collections.singletonList("aud1"));
		JWT token = createSignedJWT("aud1");
		validator.assertValidToken(token.serialize());
	}
	
	@Test 
	public void testAssertUnexpectedIssuer() throws IOException, OIDCTokenValidatorException {
		OIDCTokenValidator validator = createOIDCTokenValidator("https://differentfromtoken", Collections.singletonList("aud1"));
		JWT token = createSignedJWT("aud1");
		thrown.expect(OIDCTokenValidatorException.class);
		validator.assertValidToken(token.serialize());
	}
	
	@Test 
	public void testAssertUnknownAudience() throws IOException, OIDCTokenValidatorException {
		OIDCTokenValidator validator = createOIDCTokenValidator(ISSUER, Collections.singletonList("aud1"));
		JWT token = createSignedJWT("unknown");
		thrown.expect(OIDCTokenValidatorException.class);
		validator.assertValidToken(token.serialize());
	}
	
	@Test
	public void testGetValidator() throws MalformedURLException, ParseException, OIDCTokenValidatorException {
		List<String> aud = new ArrayList<>();
		aud.add("aud1");
		aud.add("aud2");
		OIDCTokenValidator validator = createOIDCTokenValidator(ISSUER, aud);
		
		JWT tokenAud1 = createSignedJWT("aud1");
		assertEquals("aud1", validator.get(tokenAud1).getClientID().getValue());
		
		JWT tokenAud2 = createSignedJWT("aud2");
		assertEquals("aud2", validator.get(tokenAud2).getClientID().getValue());
		
		JWT tokenUnknownAud = createSignedJWT("unknown");
		thrown.expect(OIDCTokenValidatorException.class);
		validator.get(tokenUnknownAud);	
	}
	
	private OIDCTokenValidator createOIDCTokenValidator(String issuer, List<String> expectedAudience){
		try {
			return new OIDCTokenValidator(issuer, expectedAudience, URI.create("https://someurl").toURL(), new MockResourceRetriever());
		} catch (MalformedURLException e) {
			throw new RuntimeException(e);
		}
	}
	
	private SignedJWT createSignedJWT(String audience) {
		try {
			Date now = new Date();
			JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
					.subject("foobar").issuer(ISSUER).audience(audience)
					.jwtID(UUID.randomUUID().toString()).notBeforeTime(now).issueTime(now)
					.expirationTime(new Date(now.getTime() + 3600)).build();
			
			JWSHeader.Builder header = new Builder(JWSAlgorithm.RS256)
	                .keyID(rsaJwk.getKeyID())
	                .type(JOSEObjectType.JWT);

	        SignedJWT signedJWT = new SignedJWT(header.build(), claimsSet);
	        JWSSigner signer = new RSASSASigner(rsaJwk.toPrivateKey());
	        signedJWT.sign(signer);
	        return signedJWT;
		} catch(JOSEException e){
			throw new RuntimeException(e);
		}	
	}
	
	class MockResourceRetriever extends OIDCResourceRetriever {
		@Override
		public Resource retrieveResource(URL url) throws IOException {
			JWKSet set = new JWKSet(rsaJwk);	
			String content = set.toString();
			return new Resource(content, "application/json");
		
		}	
	}	
}
