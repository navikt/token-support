package no.nav.security.spring.oidc.validation.api;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import org.springframework.core.annotation.AliasFor;

@Retention(RUNTIME)
@Target({ TYPE, METHOD })
@Protected
public @interface ProtectedWithClaims {
	String issuer();
	/**
	 * Required claims in token in key=value format
	 * @return array containing claims as key=value
	 */
	String[] claimMap() default {};
		
}
