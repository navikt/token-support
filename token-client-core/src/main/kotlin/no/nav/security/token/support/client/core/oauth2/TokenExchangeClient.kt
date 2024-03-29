package no.nav.security.token.support.client.core.oauth2

import no.nav.security.token.support.client.core.ClientProperties.TokenExchangeProperties.Companion.SUBJECT_TOKEN_TYPE_VALUE
import no.nav.security.token.support.client.core.OAuth2ParameterNames.AUDIENCE
import no.nav.security.token.support.client.core.OAuth2ParameterNames.RESOURCE
import no.nav.security.token.support.client.core.OAuth2ParameterNames.SUBJECT_TOKEN
import no.nav.security.token.support.client.core.OAuth2ParameterNames.SUBJECT_TOKEN_TYPE
import no.nav.security.token.support.client.core.http.OAuth2HttpClient

class TokenExchangeClient(oAuth2HttpClient : OAuth2HttpClient) : AbstractOAuth2TokenClient<TokenExchangeGrantRequest>(oAuth2HttpClient) {

    override fun formParameters(grantRequest : TokenExchangeGrantRequest) =
        with(grantRequest)  {
            HashMap<String, String>().apply {
                clientProperties.tokenExchange?.run {
                    put(SUBJECT_TOKEN_TYPE, SUBJECT_TOKEN_TYPE_VALUE)
                    put(SUBJECT_TOKEN,subjectToken)
                    put(AUDIENCE, audience)
                    resource?.takeIf { it.isNotEmpty() }?.let { put(RESOURCE, it) }
                }
            }
        }
}