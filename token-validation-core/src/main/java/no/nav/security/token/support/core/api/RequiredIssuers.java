package no.nav.security.token.support.core.api;

import java.lang.annotation.Retention;

import static java.lang.annotation.RetentionPolicy.RUNTIME;

@Retention(RUNTIME)
public @interface RequiredIssuers {
    ProtectedWithClaims[] value();
}
