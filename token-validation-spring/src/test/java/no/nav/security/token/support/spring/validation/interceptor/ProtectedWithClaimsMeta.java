package no.nav.security.token.support.spring.validation.interceptor;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import no.nav.security.token.support.core.api.ProtectedWithClaims;

@ProtectedWithClaims(issuer = "issuer1", claimMap = { "acr=Level4" })
@Target({ ElementType.TYPE, ElementType.METHOD })
@Retention(RetentionPolicy.RUNTIME)

public @interface ProtectedWithClaimsMeta {

}
