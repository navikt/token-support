package no.nav.security.token.support.client.core.oauth2

import no.nav.security.token.support.client.core.OAuth2ParameterNames.ASSERTION
import no.nav.security.token.support.client.core.OAuth2ParameterNames.REQUESTED_TOKEN_USE
import no.nav.security.token.support.client.core.OAuth2ParameterNames.SCOPE
import no.nav.security.token.support.client.core.http.OAuth2HttpClient

class OnBehalfOfTokenClient(oAuth2HttpClient : OAuth2HttpClient) : AbstractOAuth2TokenClient<OnBehalfOfGrantRequest>(oAuth2HttpClient) {

    override fun formParameters(grantRequest : OnBehalfOfGrantRequest)  =
        LinkedHashMap<String, String>().apply {
            put(ASSERTION, grantRequest.assertion)
            put(REQUESTED_TOKEN_USE,REQUESTED_TOKEN_USE_VALUE)
            put(SCOPE, grantRequest.scopes())

        }

    companion object {
        private const val REQUESTED_TOKEN_USE_VALUE = "on_behalf_of"
    }
}