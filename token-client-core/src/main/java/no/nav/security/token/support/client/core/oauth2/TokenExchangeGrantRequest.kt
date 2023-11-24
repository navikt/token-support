package no.nav.security.token.support.client.core.oauth2

import java.util.Objects
import no.nav.security.token.support.client.core.ClientProperties
import no.nav.security.token.support.client.core.OAuth2GrantType.Companion.TOKEN_EXCHANGE

class TokenExchangeGrantRequest(clientProperties : ClientProperties, val subjectToken : String) : AbstractOAuth2GrantRequest(TOKEN_EXCHANGE,
    clientProperties) {

    override fun equals(o : Any?) : Boolean {
        if (this === o) return true
        if (o == null || javaClass != o.javaClass) return false
        if (!super.equals(o)) return false
        val that = o as TokenExchangeGrantRequest
        return subjectToken == that.subjectToken
    }

    override fun hashCode() = Objects.hash(super.hashCode(), subjectToken)
}