package no.nav.security.token.support.client.core.oauth2

import java.util.Objects
import no.nav.security.token.support.client.core.ClientProperties
import no.nav.security.token.support.client.core.OAuth2GrantType.Companion.TOKEN_EXCHANGE

class TokenExchangeGrantRequest(clientProperties : ClientProperties, val subjectToken : String) : AbstractOAuth2GrantRequest(TOKEN_EXCHANGE,
    clientProperties) {

    override fun equals(other : Any?) : Boolean {
        if (this === other) return true
        if (other == null || javaClass != other.javaClass) return false
        if (!super.equals(other)) return false
        val that = other as TokenExchangeGrantRequest
        return subjectToken == that.subjectToken
    }

    override fun hashCode() = Objects.hash(super.hashCode(), subjectToken)
}