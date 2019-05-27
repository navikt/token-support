package no.nav.security.spring.oidc.validation.interceptor;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import net.minidev.json.JSONArray;
import no.nav.security.oidc.api.Protected;
import no.nav.security.oidc.api.ProtectedWithClaims;
import no.nav.security.oidc.api.Unprotected;
import no.nav.security.oidc.context.OIDCClaims;
import no.nav.security.oidc.context.OIDCRequestContextHolder;
import no.nav.security.oidc.context.OIDCValidationContext;
import no.nav.security.oidc.context.TokenContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.method.HandlerMethod;

import java.lang.annotation.Annotation;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class OIDCTokenControllerHandlerInterceptorTest {

    private OIDCRequestContextHolder contextHolder;

    private OIDCTokenControllerHandlerInterceptor interceptor;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setup() {
        contextHolder = createContextHolder();
        contextHolder.setOIDCValidationContext(new OIDCValidationContext());
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
                () -> interceptor.handleProtectedAnnotation(new OIDCValidationContext()));
        OIDCClaims claims = createOIDCClaims("customClaim", "socustom");
        OIDCValidationContext context = createOidcValidationContext(claims);
        assertTrue(interceptor.handleProtectedAnnotation(context));
    }

    @Test
    void testHandleProtectedWithClaimsAnnotation() {
        ProtectedWithClaims annotation = createProtectedWithClaims("customClaim=shouldmatch");

        OIDCClaims claims = createOIDCClaims("customClaim", "shouldmatch");
        OIDCValidationContext context = createOidcValidationContext(claims);
        assertTrue(interceptor.handleProtectedWithClaimsAnnotation(context, annotation));
        assertThrows(OIDCUnauthorizedException.class,
                () -> interceptor.handleProtectedWithClaimsAnnotation(
                        createOidcValidationContext(createOIDCClaims("customClaim", "shouldNOTmatch")),
                        annotation));
    }

    @Test
    void testHandleProtectedWithClaimsAnnotationCombineWithOr() {
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
    void testContainsRequiredClaimsDefaultBehaviour() {
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
    void testContainsRequiredClaimsCombineWithOr() {
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

    private static OIDCValidationContext createOidcValidationContext(OIDCClaims claims1) {
        OIDCValidationContext context = new OIDCValidationContext();
        context.addValidatedToken("issuer1", new TokenContext("issuer1", "someidtoken"), claims1);
        return context;
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
        OIDCClaims claims = createOIDCClaims("aclaim", "value");
        OIDCValidationContext context = createOidcValidationContext(claims);
        contextHolder.setOIDCValidationContext(context);
    }

    private static OIDCClaims createOIDCClaims(String name, String value) {
        JWT jwt = new PlainJWT(new JWTClaimsSet.Builder()
                .subject("subject")
                .issuer("http//issuer1")
                .claim("acr", "Level4")
                .claim("groups", new JSONArray().appendElement("123").appendElement("456"))
                .claim(name, value).build());
        return new OIDCClaims(jwt);
    }

    private static OIDCRequestContextHolder createContextHolder() {
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
