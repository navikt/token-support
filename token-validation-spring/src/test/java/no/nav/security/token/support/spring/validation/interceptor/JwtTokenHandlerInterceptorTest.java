package no.nav.security.token.support.spring.validation.interceptor;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import net.minidev.json.JSONArray;
import no.nav.security.token.support.core.api.Protected;
import no.nav.security.token.support.core.api.ProtectedWithClaims;
import no.nav.security.token.support.core.api.Unprotected;
import no.nav.security.token.support.core.context.TokenValidationContext;
import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import no.nav.security.token.support.core.jwt.JwtToken;
import no.nav.security.token.support.core.validation.JwtTokenAnnotationHandler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.method.HandlerMethod;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtTokenHandlerInterceptorTest {

    private TokenValidationContextHolder contextHolder;

    private JwtTokenHandlerInterceptor interceptor;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setup() {
        contextHolder = createContextHolder();
        contextHolder.setTokenValidationContext(new TokenValidationContext(Collections.emptyMap()));
        JwtTokenAnnotationHandler jwtTokenAnnotationHandler = new JwtTokenAnnotationHandler(contextHolder);
        Map<String, Object> annotationAttributesMap = new HashMap<>();
        annotationAttributesMap.put("ignore", new String[]{"org.springframework", IgnoreClass.class.getName()});
        AnnotationAttributes annotationAttrs = AnnotationAttributes.fromMap(annotationAttributesMap);
        interceptor = new JwtTokenHandlerInterceptor(annotationAttrs, jwtTokenAnnotationHandler);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Test
    void classIsMarkedAsIgnore() {
        HandlerMethod handlerMethod = handlerMethod(new IgnoreClass(), "test");
        assertTrue(interceptor.preHandle(request, response, handlerMethod));
    }

    @Test
    void notAnnotatedShouldThrowException() {
        HandlerMethod handlerMethod = handlerMethod(new NotAnnotatedClass(), "test");
        assertThrows(JwtTokenUnauthorizedException.class,
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
        assertThrows(JwtTokenUnauthorizedException.class,
            () -> interceptor.preHandle(request, response, handlerMethod));
        setupValidOidcContext();
        assertTrue(interceptor.preHandle(request, response, handlerMethod));
    }

    @Test
    void methodShouldBeProtectedOnUnprotectedClass() {
        HandlerMethod handlerMethod = handlerMethod(new UnprotectedClassProtectedMethod(), "protectedMethod");
        assertThrows(JwtTokenUnauthorizedException.class,
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
        assertThrows(JwtTokenUnauthorizedException.class,
            () -> interceptor.preHandle(request, response, handlerMethod));
        setupValidOidcContext();
        assertTrue(interceptor.preHandle(request, response, handlerMethod));
    }

    @Test
    void methodShouldBeProtectedOnClassProtectedWithClaims() {
        HandlerMethod handlerMethod = handlerMethod(new ProtectedWithClaimsClassProtectedMethod(), "protectedMethod");
        assertThrows(JwtTokenUnauthorizedException.class,
            () -> interceptor.preHandle(request, response, handlerMethod));
        setupValidOidcContext();
        assertTrue(interceptor.preHandle(request, response, handlerMethod));
    }

    private static TokenValidationContext createOidcValidationContext(String issuerShortName, JwtToken jwtToken) {
        Map<String, JwtToken> map = new ConcurrentHashMap<>();
        map.put(issuerShortName, jwtToken);
        return new TokenValidationContext(map);
    }

    private void setupValidOidcContext() {
        JwtToken claims = createJwtToken("aclaim", "value");
        TokenValidationContext context = createOidcValidationContext("issuer1", claims);
        contextHolder.setTokenValidationContext(context);
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

    private static TokenValidationContextHolder createContextHolder() {
        return new TokenValidationContextHolder() {
            TokenValidationContext validationContext;

            @Override
            public TokenValidationContext getTokenValidationContext() {
                return validationContext;
            }

            @Override
            public void setTokenValidationContext(TokenValidationContext tokenValidationContext) {
                this.validationContext = tokenValidationContext;
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
        public void test() {
        }
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
