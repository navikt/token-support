package no.nav.security.token.support.core.api;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import static java.lang.annotation.RetentionPolicy.*;

@Retention(RUNTIME)
public @interface RequiredIssuers {
    ProtectedWithClaims[] value();
}
