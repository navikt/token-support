package no.nav.security.token.support.client.core.oauth2

import java.util.Objects
import no.nav.security.token.support.client.core.ClientProperties
import no.nav.security.token.support.client.core.OAuth2GrantType
import no.nav.security.token.support.client.core.OAuth2GrantType.Companion.JWT_BEARER

class OnBehalfOfGrantRequest(clientProperties : ClientProperties, val assertion : String) : AbstractOAuth2GrantRequest(JWT_BEARER, clientProperties) {

    override fun equals(other : Any?) : Boolean {
        if (this === other) return true
        if (other == null || javaClass != other.javaClass) return false
        if (!super.equals(other)) return false
        val that = other as OnBehalfOfGrantRequest
        return assertion == that.assertion
    }

    override fun hashCode()  = Objects.hash(super.hashCode(), assertion)
}