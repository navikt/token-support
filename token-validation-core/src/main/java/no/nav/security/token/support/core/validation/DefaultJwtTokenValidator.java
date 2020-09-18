package no.nav.security.token.support.core.validation;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import no.nav.security.token.support.core.exceptions.JwtTokenValidatorException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DefaultJwtTokenValidator implements JwtTokenValidator {
    private static final Logger LOG = LoggerFactory.getLogger(DefaultJwtTokenValidator.class);
    private static final JWSAlgorithm JWSALG = JWSAlgorithm.RS256;
    private final Map<String, IDTokenValidator> audienceValidatorMap;

    public DefaultJwtTokenValidator(String issuer, List<String> acceptedAudience, URL jwkSetUrl,
                                    ResourceRetriever jwksResourceRetriever) {
        this.audienceValidatorMap = initializeMap(issuer, acceptedAudience, jwkSetUrl, jwksResourceRetriever);
    }

    public void assertValidToken(String tokenString) throws JwtTokenValidatorException {
        assertValidToken(tokenString, null);
    }

    public void assertValidToken(String tokenString, String expectedNonce) throws JwtTokenValidatorException {
        JWT token = null;
        try {
            token = JWTParser.parse(tokenString);
            get(token).validate(token, expectedNonce != null ? new Nonce(expectedNonce) : null);
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

    protected IDTokenValidator createValidator(String issuer, String clientId, URL jwkSetUrl,
                                               ResourceRetriever jwksResourceRetriever) {
        Issuer iss = new Issuer(issuer);
        ClientID clientID = new ClientID(clientId);
        return new IDTokenValidator(iss, clientID, JWSALG, jwkSetUrl, jwksResourceRetriever);
    }

    private static Date expiryDate(JWT token) {
        try {
            return token != null ? token.getJWTClaimsSet().getExpirationTime() : null;
        } catch (ParseException e) {
            return null;
        }
    }

    private Map<String, IDTokenValidator> initializeMap(String issuer, List<String> acceptedAudience, URL jwkSetUrl,
                                                        ResourceRetriever jwksResourceRetriever) {
        if (acceptedAudience == null || acceptedAudience.isEmpty()) {
            throw new IllegalArgumentException("Accepted audience cannot be null or empty in validator config.");
        }
        Map<String, IDTokenValidator> map = new HashMap<>();
        for (String aud : acceptedAudience) {
            map.put(aud, createValidator(issuer, aud, jwkSetUrl, jwksResourceRetriever));
        }
        return map;
    }
}
