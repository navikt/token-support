package no.nav.security.spring.oidc.validation.interceptor;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.annotation.Annotation;
import java.util.AbstractMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.springframework.core.annotation.AnnotationAttributes;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

import net.minidev.json.JSONArray;
import no.nav.security.oidc.api.ProtectedWithClaims;
import no.nav.security.oidc.context.OIDCClaims;
import no.nav.security.oidc.context.OIDCRequestContextHolder;
import no.nav.security.oidc.context.OIDCValidationContext;
import no.nav.security.oidc.context.TokenContext;
import no.nav.security.spring.oidc.api.EnableOIDCTokenValidation;

public class OIDCTokenControllerHandlerInterceptorTest {

    private OIDCRequestContextHolder contextHolder = createContextHolder();
    private Map<String, Object> annotationAttributesMap = Stream
            .of(new AbstractMap.SimpleEntry<>("ignore", new String[] { "org.springframework" }))
            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    private AnnotationAttributes annotationAttrs = AnnotationAttributes.fromMap(annotationAttributesMap);
    private OIDCTokenControllerHandlerInterceptor interceptor = new OIDCTokenControllerHandlerInterceptor(
            annotationAttrs, contextHolder);

    @Test
    public void testHandleProtectedAnnotation() {
        assertThrows(OIDCUnauthorizedException.class,
                () -> interceptor.handleProtectedAnnotation(new OIDCValidationContext()));
        OIDCClaims claims = createOIDCClaims("customClaim", "socustom");
        OIDCValidationContext context = createOidcValidationContext(claims);
        assertTrue(interceptor.handleProtectedAnnotation(context));
    }

    @Test
    public void testHandleProtectedWithClaimsAnnotation() {
        ProtectedWithClaims annotation = createProtectedWithClaims("issuer1", "customClaim=shouldmatch");

        OIDCClaims claims = createOIDCClaims("customClaim", "shouldmatch");
        OIDCValidationContext context = createOidcValidationContext(claims);
        assertTrue(interceptor.handleProtectedWithClaimsAnnotation(context, annotation));
        assertThrows(OIDCUnauthorizedException.class,
                () -> interceptor.handleProtectedWithClaimsAnnotation(
                        createOidcValidationContext(createOIDCClaims("customClaim", "shouldNOTmatch")),
                        annotation));
    }

    @Test
    public void testHandleProtectedWithClaimsAnnotationCombineWithOr() {
        ProtectedWithClaims annotation = createProtectedWithClaims("issuer1", true, "customClaim=shouldmatch",
                "notintoken=foo");
        assertTrue(interceptor.handleProtectedWithClaimsAnnotation(
                createOidcValidationContext(createOIDCClaims("customClaim", "shouldmatch")), annotation));
        assertThrows(OIDCUnauthorizedException.class,
                () -> interceptor.handleProtectedWithClaimsAnnotation(
                        createOidcValidationContext(createOIDCClaims("customClaim", "shouldNOTmatch")),
                        annotation));
    }

    @Test
    public void testContainsRequiredClaimsDefaultBehaviour() {
        OIDCClaims claims = createOIDCClaims("customClaim", "shouldmatch");
        assertTrue(
                interceptor.containsRequiredClaims(claims, false, "customClaim=shouldmatch", "acr=Level4", ""));
        assertTrue(
                interceptor.containsRequiredClaims(claims, false, " customClaim = shouldmatch "));
        assertTrue(
                interceptor.containsRequiredClaims(claims, false, "groups=123", "groups=456"));
        assertFalse(interceptor.containsRequiredClaims(claims, false, "customClaim=shouldNOTmatch"));
        assertFalse(interceptor.containsRequiredClaims(claims, false, "notintoken=value"));
        assertFalse(interceptor.containsRequiredClaims(claims, false, "groups=notexist"));
    }

    @Test
    public void testContainsRequiredClaimsCombineWithOr() {
        OIDCClaims claims = createOIDCClaims("customClaim", "shouldmatch");

        assertTrue(
                interceptor.containsRequiredClaims(claims, true, "customClaim=shouldmatch", "notintoken=foo", ""));
        assertTrue(
                interceptor.containsRequiredClaims(claims, true, "customClaim=shouldmatch", "acr=Level4", ""));
        assertTrue(interceptor.containsRequiredClaims(claims, true));
        assertTrue(interceptor.containsRequiredClaims(claims, true, "customClaim=shouldNOTmatch",
                "customClaim=shouldmatch"));
        assertFalse(
                interceptor.containsRequiredClaims(claims, true, "customClaim=shouldNOTmatch", "anotherClaim=foo"));
        assertFalse(interceptor.containsRequiredClaims(claims, true, "notintoken=value"));

    }

    private OIDCValidationContext createOidcValidationContext(OIDCClaims claims1) {
        OIDCValidationContext context = new OIDCValidationContext();
        context.addValidatedToken("issuer1", new TokenContext("issuer1", "someidtoken"), claims1);
        return context;
    }

    private ProtectedWithClaims createProtectedWithClaims(String issuer, String... claimMap) {
        return createProtectedWithClaims(issuer, false, claimMap);
    }

    private ProtectedWithClaims createProtectedWithClaims(String issuer, boolean combineWithOr, String... claimMap) {
        return new ProtectedWithClaims() {
            public Class<? extends Annotation> annotationType() {
                return ProtectedWithClaims.class;
            }

            public String issuer() {
                return issuer;
            }

            public String[] claimMap() {
                return claimMap;
            }

            @Override
            public boolean combineWithOr() {
                return combineWithOr;
            }
        };
    }

    private OIDCClaims createOIDCClaims(String name, String value) {
        JWT jwt = new PlainJWT(new JWTClaimsSet.Builder()
                .subject("subject")
                .issuer("http//issuer1")
                .claim("acr", "Level4")
                .claim("groups", new JSONArray().appendElement("123").appendElement("456"))
                .claim(name, value).build());
        OIDCClaims claims = new OIDCClaims(jwt);
        return claims;
    }

    private OIDCRequestContextHolder createContextHolder() {
        return new OIDCRequestContextHolder() {
            OIDCValidationContext validationContext;

            @Override
            public void setRequestAttribute(String name, Object value) {
                validationContext = (OIDCValidationContext) value;
            }

            @Override
            public Object getRequestAttribute(String name) {
                return validationContext;
            }

            @Override
            public OIDCValidationContext getOIDCValidationContext() {
                return validationContext;
            }

            @Override
            public void setOIDCValidationContext(OIDCValidationContext oidcValidationContext) {
                this.validationContext = oidcValidationContext;
            }
        };
    }

    @EnableOIDCTokenValidation
    class TestMainClass {
    }

}
