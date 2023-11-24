package no.nav.security.token.support.client.core.oauth2

import no.nav.security.token.support.client.core.OAuth2ParameterNames.AUDIENCE
import no.nav.security.token.support.client.core.OAuth2ParameterNames.RESOURCE
import no.nav.security.token.support.client.core.OAuth2ParameterNames.SUBJECT_TOKEN
import no.nav.security.token.support.client.core.OAuth2ParameterNames.SUBJECT_TOKEN_TYPE
import no.nav.security.token.support.client.core.http.OAuth2HttpClient

class TokenExchangeClient(oAuth2HttpClient : OAuth2HttpClient) : AbstractOAuth2TokenClient<TokenExchangeGrantRequest>(oAuth2HttpClient) {

    override fun formParameters(grantRequest : TokenExchangeGrantRequest) =
        LinkedHashMap<String, String>().apply {
            grantRequest.clientProperties.tokenExchange.run {
                put(SUBJECT_TOKEN_TYPE, this!!.subjectTokenType())
                put(SUBJECT_TOKEN,grantRequest.subjectToken)
                put(AUDIENCE, audience)
                resource?.takeIf { it.isNotEmpty() }?.let { put(RESOURCE, it) }
            }
        }
}