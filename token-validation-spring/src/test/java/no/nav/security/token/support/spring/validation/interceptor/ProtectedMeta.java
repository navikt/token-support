package no.nav.security.token.support.spring.validation.interceptor;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import no.nav.security.token.support.core.api.Protected;

@Protected
@Target({ ElementType.TYPE, ElementType.METHOD })
@Retention(RetentionPolicy.RUNTIME)

public @interface ProtectedMeta {

}
