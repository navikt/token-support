package no.nav.security.token.support.core.validation;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import no.nav.security.token.support.core.exceptions.JwtTokenValidatorException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DefaultJwtTokenValidator implements JwtTokenValidator {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultJwtTokenValidator.class);
    private static final JWSAlgorithm JWS_ALG = JWSAlgorithm.RS256;
    private final Map<String, IDTokenValidator> audienceValidatorMap;
    private final RemoteJWKSet<SecurityContext> remoteJWKSet;

    public DefaultJwtTokenValidator(
        String issuer,
        List<String> acceptedAudience,
        RemoteJWKSet<SecurityContext> remoteJWKSet
    ) {
        this.remoteJWKSet = remoteJWKSet;
        this.audienceValidatorMap = initializeMap(issuer, acceptedAudience);
    }

    @Override
    public void assertValidToken(String tokenString) throws JwtTokenValidatorException {
        assertValidToken(tokenString, null);
    }

    public void assertValidToken(String tokenString, String expectedNonce) throws JwtTokenValidatorException {
        JWT token = null;
        try {
            token = JWTParser.parse(tokenString);
            get(token).validate(token, expectedNonce != null ? new Nonce(expectedNonce) : null);
        } catch (NoSuchMethodError e) {
            String msg = "Dependant method not found. Ensure that nimbus-jose-jwt and/or oauth2-oidc-sdk has versions >= 9.x (e.g. Spring Boot >= 2.5.0)";
            LOG.error(msg, e);
            throw new JwtTokenValidatorException(msg, e);
        } catch (Throwable t) {
            throw new JwtTokenValidatorException("Token validation failed", expiryDate(token), t);
        }
    }

    protected IDTokenValidator get(JWT jwt) throws ParseException, JwtTokenValidatorException {
        List<String> tokenAud = jwt.getJWTClaimsSet().getAudience();
        for (String aud : tokenAud) {
            if (audienceValidatorMap.containsKey(aud)) {
                return audienceValidatorMap.get(aud);
            }
        }
        LOG.warn("Could not find validator for token audience {}", tokenAud);
        throw new JwtTokenValidatorException(
            "Could not find appropriate validator to validate token. check your config.");
    }

    protected IDTokenValidator createValidator(String issuer, String clientId) {
        Issuer iss = new Issuer(issuer);
        ClientID clientID = new ClientID(clientId);
        JWSVerificationKeySelector<SecurityContext> jwsKeySelector = new JWSVerificationKeySelector<>(
            JWS_ALG,
            remoteJWKSet
        );
        return new IDTokenValidator(iss, clientID, jwsKeySelector, null);
    }

    private static Date expiryDate(JWT token) {
        try {
            return token != null ? token.getJWTClaimsSet().getExpirationTime() : null;
        } catch (ParseException e) {
            return null;
        }
    }

    private Map<String, IDTokenValidator> initializeMap(String issuer, List<String> acceptedAudience) {
        if (acceptedAudience == null || acceptedAudience.isEmpty()) {
            throw new IllegalArgumentException("Accepted audience cannot be null or empty in validator config.");
        }
        Map<String, IDTokenValidator> map = new HashMap<>();
        for (String aud : acceptedAudience) {
            map.put(aud, createValidator(issuer, aud));
        }
        return map;
    }

    protected RemoteJWKSet<SecurityContext> getRemoteJWKSet() {
        return this.remoteJWKSet;
    }
}
