package no.nav.security.token.support.core.api

import kotlin.annotation.AnnotationRetention.RUNTIME

@Retention(RUNTIME)
annotation class RequiredIssuers(vararg val value : ProtectedWithClaims)