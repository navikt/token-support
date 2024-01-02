package no.nav.security.token.support.client.core.http

import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse

interface OAuth2HttpClient {

    fun post(request : OAuth2HttpRequest) : OAuth2AccessTokenResponse?
}