package no.nav.security.token.support.core.validation;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import no.nav.security.token.support.core.context.TokenValidationContext;
import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import no.nav.security.token.support.core.exceptions.JwtTokenInvalidClaimException;
import no.nav.security.token.support.core.jwt.JwtToken;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class JwtTokenAnnotationHandlerTest {

    private final JwtTokenAnnotationHandler annotationHandler;

    public JwtTokenAnnotationHandlerTest() {
        Map<String, JwtToken> validationContextMap = new HashMap<>();

        validationContextMap.put("issuer1", jwtToken("https://one", "acr=Level3"));
        validationContextMap.put("issuer2", jwtToken("https://two", "acr=Level4"));
        validationContextMap.put("issuer3", jwtToken("https://three", "acr=Level1"));
        validationContextMap.put("issuer4", jwtToken("https://four", "acr=Level3", "foo=bar"));

        TokenValidationContext tvc  = new TokenValidationContext(validationContextMap);
        TokenValidationContextHolder tokenValidationContextHolder = new TokenValidationContextHolder() {
            @Override
            public TokenValidationContext getTokenValidationContext() {
                return tvc;
            }
            @Override
            public void setTokenValidationContext(TokenValidationContext tokenValidationContext) {
            }
        };
        this.annotationHandler = new JwtTokenAnnotationHandler(tokenValidationContextHolder);
    }

    @Test
    public void checkThatAlternativeClaimsWithSameKeyWorks() {
        final String[] protectedWithAnyClaim = new String[] {"acr=Level3", "acr=Level4"}; // Require either acr=Level3 or acr=Level4

        assertTrue(annotationHandler.handleProtectedWithClaims("issuer1", protectedWithAnyClaim, true));

        assertTrue(annotationHandler.handleProtectedWithClaims("issuer2", protectedWithAnyClaim, true));

        assertThrows(JwtTokenInvalidClaimException.class, () ->
            annotationHandler.handleProtectedWithClaims("issuer3", protectedWithAnyClaim, true));

        assertTrue(annotationHandler.handleProtectedWithClaims("issuer4", protectedWithAnyClaim, true));
    }

    @Test
    public void checkThatMultipleRequiredClaimsWorks() {
        final String[] protectedWithAllClaims = new String[] {"acr=Level3", "foo=bar"}; // Require acr=Level3 and foo=bar

        assertThrows(JwtTokenInvalidClaimException.class, () ->
            annotationHandler.handleProtectedWithClaims("issuer1", protectedWithAllClaims, false));
        assertThrows(JwtTokenInvalidClaimException.class, () ->
            annotationHandler.handleProtectedWithClaims("issuer2", protectedWithAllClaims, false));
        assertThrows(JwtTokenInvalidClaimException.class, () ->
            annotationHandler.handleProtectedWithClaims("issuer3", protectedWithAllClaims, false));

        assertTrue(annotationHandler.handleProtectedWithClaims("issuer4", protectedWithAllClaims, false));
    }

    @Test
    public void checkThatClaimWithUnknownValueIsRejected() {
        final String[] protectedWithClaims = new String[] {"acr=Level3", "acr=Level4"};

        // Token from issuer3 only contains acr=Level1
        assertThrows(JwtTokenInvalidClaimException.class, () ->
            annotationHandler.handleProtectedWithClaims("issuer3", protectedWithClaims, true));
        assertThrows(JwtTokenInvalidClaimException.class, () ->
            annotationHandler.handleProtectedWithClaims("issuer3", protectedWithClaims, false));
    }

    @Test
    public void chechThatNoReqiredClaimsWorks() {
        final String[] protectedWithClaims = new String[0];

        assertTrue(annotationHandler.handleProtectedWithClaims("issuer1", protectedWithClaims, true));
        assertTrue(annotationHandler.handleProtectedWithClaims("issuer2", protectedWithClaims, true));
        assertTrue(annotationHandler.handleProtectedWithClaims("issuer3", protectedWithClaims, true));
        assertTrue(annotationHandler.handleProtectedWithClaims("issuer4", protectedWithClaims, true));

        assertTrue(annotationHandler.handleProtectedWithClaims("issuer1", protectedWithClaims, false));
        assertTrue(annotationHandler.handleProtectedWithClaims("issuer2", protectedWithClaims, false));
        assertTrue(annotationHandler.handleProtectedWithClaims("issuer3", protectedWithClaims, false));
        assertTrue(annotationHandler.handleProtectedWithClaims("issuer4", protectedWithClaims, false));
    }

    private JwtToken jwtToken(String issuer, String...claims) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject("subject");
        Arrays.stream(claims).map(c -> c.split("=")).forEach(pair -> {
            builder.claim(pair[0], pair[1]);
        });
        PlainJWT plainJWT = new PlainJWT(builder.build());
        return new JwtToken(plainJWT.serialize());
    }

}
