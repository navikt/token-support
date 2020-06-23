package no.nav.security.token.support.core.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import no.nav.security.token.support.core.exceptions.JwtTokenValidatorException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.HashSet;
import java.util.List;

public class LightenJwtTokenValidator implements JwtTokenValidator {

    private static final Logger log = LoggerFactory.getLogger(LightenJwtTokenValidator.class);
    private final String issuer;
    private final List<String> requiredClaims = List.of("iss", "iat", "exp", "nbf");

    LightenJwtTokenValidator(String issuer) {
        this.issuer = issuer;
    }

    @Override
    public void assertValidToken(String tokenString) throws JwtTokenValidatorException {
        try {
            verify(issuer, tokenString,
                new JWSVerificationKeySelector<>(
                    JWSAlgorithm.RS256,
                    new ImmutableJWKSet<>(new JWKSet())
                )
            );
        } catch (ParseException | JOSEException | BadJOSEException e) {
            e.printStackTrace();
        }
    }

    private void verify(String issuer, String tokenString, JWSVerificationKeySelector<SecurityContext> keySelector) throws ParseException, JOSEException, BadJOSEException {
        verify(
            tokenString,
            new DefaultJWTClaimsVerifier<>(
                new JWTClaimsSet.Builder()
                    .issuer(issuer)
                    .build(),
                new HashSet<>(requiredClaims)
            ),
            keySelector
        );
    }

    private void verify(String tokenString, JWTClaimsSetVerifier<SecurityContext> jwtClaimsSetVerifier, JWSVerificationKeySelector<SecurityContext> keySelector) throws ParseException, JOSEException, BadJOSEException {
        JWT token;
        try {
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            jwtProcessor.setJWSKeySelector(keySelector);
            jwtProcessor.setJWTClaimsSetVerifier(jwtClaimsSetVerifier);
            token = parse(tokenString);
            jwtProcessor.process(token, null);
        } catch (Throwable t) {
            throw new JwtTokenValidatorException("Token validation failed: " + t.getMessage());
        }
    }

    private JWT parse(String tokenString) {
        try {
            return JWTParser.parse(tokenString);
        } catch (Throwable t) {
            throw new JwtTokenValidatorException("Token verification failed: " + t.getMessage());
        }
    }
}
