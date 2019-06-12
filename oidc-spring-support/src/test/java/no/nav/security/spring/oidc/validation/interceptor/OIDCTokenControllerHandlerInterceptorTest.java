package no.nav.security.spring.oidc.validation.interceptor;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import net.minidev.json.JSONArray;
import no.nav.security.token.support.core.api.Protected;
import no.nav.security.token.support.core.api.ProtectedWithClaims;
import no.nav.security.token.support.core.api.Unprotected;
import no.nav.security.token.support.core.context.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.method.HandlerMethod;

import java.lang.annotation.Annotation;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.*;

class OIDCTokenControllerHandlerInterceptorTest {

    private JwtTokenValidationContextHolder contextHolder;

    private OIDCTokenControllerHandlerInterceptor interceptor;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setup() {
        contextHolder = createContextHolder();
        contextHolder.setOIDCValidationContext(new JwtTokenValidationContext(Collections.emptyMap()));
        Map<String, Object> annotationAttributesMap = new HashMap<>();
        annotationAttributesMap.put("ignore", new String[]{"org.springframework", IgnoreClass.class.getName()});
        AnnotationAttributes annotationAttrs = AnnotationAttributes.fromMap(annotationAttributesMap);
        interceptor = new OIDCTokenControllerHandlerInterceptor(annotationAttrs, contextHolder);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Test
    void classIsMarkedAsIgnore(){
        HandlerMethod handlerMethod = handlerMethod(new IgnoreClass(), "test");
        assertTrue(interceptor.preHandle(request,response, handlerMethod));
    }

    @Test
    void notAnnotatedShouldThrowException() {
        HandlerMethod handlerMethod = handlerMethod(new NotAnnotatedClass(), "test");
        assertThrows(OIDCUnauthorizedException.class,
                () -> interceptor.preHandle(request, response, handlerMethod));
    }

    @Test
    void methodIsUnprotectedAccessShouldBeAllowed() {
        HandlerMethod handlerMethod = handlerMethod(new UnprotectedClass(), "test");
        assertTrue(interceptor.preHandle(request, response, handlerMethod));
    }

    @Test
    void methodShouldBeProtected() {
        HandlerMethod handlerMethod = handlerMethod(new ProtectedClass(), "test");
        assertThrows(OIDCUnauthorizedException.class,
                () -> interceptor.preHandle(request, response, handlerMethod));
        setupValidOidcContext();
        assertTrue(interceptor.preHandle(request, response, handlerMethod));
    }

    @Test
    void methodShouldBeProtectedOnUnprotectedClass() {
        HandlerMethod handlerMethod = handlerMethod(new UnprotectedClassProtectedMethod(), "protectedMethod");
        assertThrows(OIDCUnauthorizedException.class,
                () -> interceptor.preHandle(request, response, handlerMethod));
        setupValidOidcContext();
        assertTrue(interceptor.preHandle(request, response, handlerMethod));
    }

    @Test
    void methodShouldBeUnprotectedOnProtectedClass() {
        HandlerMethod handlerMethod = handlerMethod(new ProtectedClassUnprotectedMethod(), "unprotectedMethod");
        assertTrue(interceptor.preHandle(request, response, handlerMethod));
    }

    @Test
    void methodShouldBeProtectedWithClaims() {
        HandlerMethod handlerMethod = handlerMethod(new ProtectedClassProtectedWithClaimsMethod(), "protectedMethod");
        assertThrows(OIDCUnauthorizedException.class,
                () -> interceptor.preHandle(request, response, handlerMethod));
        setupValidOidcContext();
        assertTrue(interceptor.preHandle(request, response, handlerMethod));
    }

    @Test
    void methodShouldBeProtectedOnClassProtectedWithClaims() {
        HandlerMethod handlerMethod = handlerMethod(new ProtectedWithClaimsClassProtectedMethod(), "protectedMethod");
        assertThrows(OIDCUnauthorizedException.class,
                () -> interceptor.preHandle(request, response, handlerMethod));
        setupValidOidcContext();
        assertTrue(interceptor.preHandle(request, response, handlerMethod));
    }

    @Test
    void testHandleProtectedAnnotation() {
        assertThrows(OIDCUnauthorizedException.class,
                () -> interceptor.handleProtectedAnnotation(new JwtTokenValidationContext(Collections.emptyMap())));
        JwtToken jwtToken = createJwtToken("customClaim", "socustom");
        JwtTokenValidationContext context = createOidcValidationContext("issuer1", jwtToken);
        assertTrue(interceptor.handleProtectedAnnotation(context));
    }

    @Test
    void testHandleProtectedWithClaimsAnnotation() {
        ProtectedWithClaims annotation = createProtectedWithClaims("customClaim=shouldmatch");

        JwtToken jwtToken = createJwtToken("customClaim", "shouldmatch");
        JwtTokenValidationContext context = createOidcValidationContext("issuer1", jwtToken);
        assertTrue(interceptor.handleProtectedWithClaimsAnnotation(context, annotation));
        assertThrows(OIDCUnauthorizedException.class,
                () -> interceptor.handleProtectedWithClaimsAnnotation(
                        createOidcValidationContext("issuer1", createJwtToken("customClaim", "shouldNOTmatch")),
                        annotation));
    }

    @Test
    void testHandleProtectedWithClaimsAnnotationCombineWithOr() {
        ProtectedWithClaims annotation = createProtectedWithClaims("issuer1", true, "customClaim=shouldmatch",
                "notintoken=foo");
        assertTrue(interceptor.handleProtectedWithClaimsAnnotation(
                createOidcValidationContext("issuer1", createJwtToken("customClaim", "shouldmatch")), annotation));
        assertThrows(OIDCUnauthorizedException.class,
                () -> interceptor.handleProtectedWithClaimsAnnotation(
                        createOidcValidationContext("issuer1", createJwtToken("customClaim", "shouldNOTmatch")),
                        annotation));
    }

    @Test
    void testContainsRequiredClaimsDefaultBehaviour() {
        JwtTokenClaims claims = createJwtToken("customClaim", "shouldmatch").getJwtTokenClaims();
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
    void testContainsRequiredClaimsCombineWithOr() {
        JwtTokenClaims claims = createJwtToken("customClaim", "shouldmatch").getJwtTokenClaims();

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

    private static JwtTokenValidationContext createOidcValidationContext(String issuerShortName, JwtToken jwtToken) {
        Map<String, JwtToken> map = new ConcurrentHashMap<>();
        map.put(issuerShortName, jwtToken);
        return new JwtTokenValidationContext(map);
    }

    private static ProtectedWithClaims createProtectedWithClaims(String... claimMap) {
        return createProtectedWithClaims("issuer1", false, claimMap);
    }

    private static ProtectedWithClaims createProtectedWithClaims(String issuer, boolean combineWithOr, String... claimMap) {
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

    private void setupValidOidcContext() {
        JwtToken claims = createJwtToken("aclaim", "value");
        JwtTokenValidationContext context = createOidcValidationContext("issuer1", claims);
        contextHolder.setOIDCValidationContext(context);
    }

    private static JwtToken createJwtToken(String claimName, String claimValue) {
        JWT jwt = new PlainJWT(new JWTClaimsSet.Builder()
                .subject("subject")
                .issuer("http//issuer1")
                .claim("acr", "Level4")
                .claim("groups", new JSONArray().appendElement("123").appendElement("456"))
                .claim(claimName, claimValue).build());
        return new JwtToken(jwt.serialize());
    }

    private static JwtTokenValidationContextHolder createContextHolder() {
        return new JwtTokenValidationContextHolder() {
            JwtTokenValidationContext validationContext;

            @Override
            public void setRequestAttribute(String name, Object value) {
                validationContext = (JwtTokenValidationContext) value;
            }

            @Override
            public Object getRequestAttribute(String name) {
                return validationContext;
            }

            @Override
            public JwtTokenValidationContext getOIDCValidationContext() {
                return validationContext;
            }

            @Override
            public void setOIDCValidationContext(JwtTokenValidationContext jwtTokenValidationContext) {
                this.validationContext = jwtTokenValidationContext;
            }
        };
    }

    private static HandlerMethod handlerMethod(Object object, String method) {
        try {
            return new HandlerMethod(object, method);
        } catch (NoSuchMethodException e) {
            throw new RuntimeException(e);
        }
    }

    private class IgnoreClass {
        public void test(){}
    }

    private class NotAnnotatedClass {
        public void test() {
        }
    }

    @Unprotected
    private class UnprotectedClass {
        public void test() {
        }
    }

    @Protected
    private class ProtectedClass {
        public void test() {
        }
    }

    @Protected
    private class ProtectedClassUnprotectedMethod {
        public void protectedMethod() {
        }

        @Unprotected
        public void unprotectedMethod() {
        }
    }

    @Unprotected
    private class UnprotectedClassProtectedMethod {
        @Protected
        public void protectedMethod() {
        }

        public void unprotectedMethod() {
        }
    }

    @Protected
    private class ProtectedClassProtectedWithClaimsMethod {
        @ProtectedWithClaims(issuer = "issuer1")
        public void protectedMethod() {
        }

        @Unprotected
        public void unprotectedMethod() {
        }

        public void unprotected() {
        }
    }

    @ProtectedWithClaims(issuer = "issuer1")
    private class ProtectedWithClaimsClassProtectedMethod {
        @Protected
        public void protectedMethod() {
        }

        @Unprotected
        public void unprotectedMethod() {
        }

        public void protectedWithClaimsMethod() {
        }
    }

}
