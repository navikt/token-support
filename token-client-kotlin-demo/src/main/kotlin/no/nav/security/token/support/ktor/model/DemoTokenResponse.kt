package no.nav.security.token.support.ktor.model

import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse

data class DemoTokenResponse(
    val oAuth2AccessTokenResponse: OAuth2AccessTokenResponse
)