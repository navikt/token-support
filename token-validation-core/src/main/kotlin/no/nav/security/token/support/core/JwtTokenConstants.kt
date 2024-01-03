package no.nav.security.token.support.core

object JwtTokenConstants {
    const val AUTHORIZATION_HEADER = "Authorization"
    const val EXPIRY_THRESHOLD_ENV_PROPERTY = "no.nav.security.jwt.expirythreshold"
    const val TOKEN_VALIDATION_FILTER_ORDER_PROPERTY = "no.nav.security.jwt.tokenvalidationfilter.order"
    const val TOKEN_EXPIRES_SOON_HEADER = "x-token-expires-soon"
    const val BEARER_TOKEN_DONT_PROPAGATE_ENV_PROPERTY = "no.nav.security.jwt.dont-propagate-bearertoken"
}