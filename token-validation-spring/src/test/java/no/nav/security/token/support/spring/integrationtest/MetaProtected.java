package no.nav.security.token.support.spring.integrationtest;

import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import org.springframework.core.annotation.AliasFor;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import no.nav.security.token.support.core.api.ProtectedWithClaims;

@RestController
@Documented
@ProtectedWithClaims(issuer = "knownissuer")
@Target(TYPE)
@Retention(RUNTIME)
@RequestMapping
public @interface MetaProtected {
    @AliasFor(annotation = RequestMapping.class, attribute = "value")
    String[] value() default {};

    @AliasFor(annotation = ProtectedWithClaims.class, attribute = "claimMap")
    String[] claimMap() default "acr=Level4";

    @AliasFor(annotation = RequestMapping.class, attribute = "produces")
    String[] produces() default APPLICATION_JSON_VALUE;

}
