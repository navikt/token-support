package no.nav.security.token.support.core.api;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
public @interface RequiredIssuers {
    ProtectedWithClaims[] value();
}
