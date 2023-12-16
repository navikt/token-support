package no.nav.security.token.support.client.core.oauth2

import no.nav.security.token.support.client.core.OAuth2ParameterNames.SCOPE
import no.nav.security.token.support.client.core.http.OAuth2HttpClient

class ClientCredentialsTokenClient(oAuth2HttpClient : OAuth2HttpClient) : AbstractOAuth2TokenClient<ClientCredentialsGrantRequest>(oAuth2HttpClient) {

    override fun formParameters(grantRequest : ClientCredentialsGrantRequest) = LinkedHashMap<String, String>().apply {
        put(SCOPE, grantRequest.clientProperties.scope.joinToString(" "))
    }
}