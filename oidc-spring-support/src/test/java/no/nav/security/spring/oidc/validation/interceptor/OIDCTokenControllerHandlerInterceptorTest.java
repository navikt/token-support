package no.nav.security.spring.oidc.validation.interceptor;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.lang.annotation.Annotation;
import java.util.AbstractMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.core.annotation.AnnotationAttributes;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

import no.nav.security.oidc.context.OIDCClaims;
import no.nav.security.oidc.context.OIDCRequestContextHolder;
import no.nav.security.oidc.context.OIDCValidationContext;
import no.nav.security.oidc.context.TokenContext;
import no.nav.security.spring.oidc.validation.api.EnableOIDCTokenValidation;
import no.nav.security.spring.oidc.validation.api.ProtectedWithClaims;

public class OIDCTokenControllerHandlerInterceptorTest {

	@Rule
	public ExpectedException thrown = ExpectedException.none();
	
	private OIDCRequestContextHolder contextHolder = createContextHolder();
    private Map<String, Object> annotationAttributesMap =
        Stream.of(new AbstractMap.SimpleEntry<>("ignore", new String[] {"org.springframework"}))
            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));	    
	private AnnotationAttributes annotationAttrs = AnnotationAttributes.fromMap(annotationAttributesMap);
	private OIDCTokenControllerHandlerInterceptor interceptor = new OIDCTokenControllerHandlerInterceptor(annotationAttrs, contextHolder);
	
	@Test
	public void testHandleProtectedAnnotation() {
		thrown.expect(OIDCUnauthorizedException.class);
		interceptor.handleProtectedAnnotation(new OIDCValidationContext());
		
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
		claims = createOIDCClaims("customClaim", "shouldNOTmatch");
		context = createOidcValidationContext(claims);
		thrown.expect(OIDCUnauthorizedException.class);
		interceptor.handleProtectedWithClaimsAnnotation(context, annotation);
	}

	@Test
	public void testContainsRequiredClaims() {
		OIDCClaims claims = createOIDCClaims("customClaim", "shouldmatch");
		assertTrue("claims do not match", interceptor.containsRequiredClaims(claims, "customClaim=shouldmatch", "acr=Level4", ""));
		assertTrue("claims do not match", interceptor.containsRequiredClaims(claims, " customClaim = shouldmatch "));
		assertFalse("claims match", interceptor.containsRequiredClaims(claims, "customClaim=shouldNOTmatch"));
		assertFalse("claims match", interceptor.containsRequiredClaims(claims, "notintoken=value"));
	}
	
	private OIDCValidationContext createOidcValidationContext(OIDCClaims claims1){
		OIDCValidationContext context = new OIDCValidationContext();
		context.addValidatedToken("issuer1", new TokenContext("issuer1", "someidtoken"), claims1);
		return context;
	}
	
	private ProtectedWithClaims createProtectedWithClaims(String issuer, String... claimMap){
		return new ProtectedWithClaims() {		
			public Class<? extends Annotation> annotationType() {
				return ProtectedWithClaims.class;
			}
			public String issuer() { return issuer; }

			public String[] claimMap() { return claimMap; }
		};
	}
	
	private OIDCClaims createOIDCClaims(String name, String value){
		 JWT jwt = new PlainJWT( new JWTClaimsSet.Builder()
				    .subject("subject")
				    .issuer("http//issuer1")
				    .claim("acr", "Level4")
				    .claim(name, value).build());
		 OIDCClaims claims = new OIDCClaims(jwt);
		 return claims;
	}
	
	private OIDCRequestContextHolder createContextHolder(){
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
	class TestMainClass {}
	
}
