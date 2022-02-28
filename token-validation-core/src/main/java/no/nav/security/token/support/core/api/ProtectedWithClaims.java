package no.nav.security.token.support.core.api;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

@Retention(RUNTIME)
@Target({ TYPE, METHOD })
@Protected
public @interface ProtectedWithClaims {

	String issuer();
	/**
	 * Required claims in token in key=value format.
     * If the value is an asterisk (*), it checks that the required key is present.
	 * @return array containing claims as key=value
	 */
	String[] claimMap() default {};

	/**
	 * How to check for the presence of claims,
	 * default is false which will require all claims in the list
	 * to be present in token. If set to true, any claim in the list
	 * will suffice.
	 *
	 * @return boolean
	 */
	boolean combineWithOr() default false;
}
