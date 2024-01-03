package no.nav.security.token.support.client.core.oauth2

import com.nimbusds.oauth2.sdk.GrantType.JWT_BEARER
import java.util.Objects
import no.nav.security.token.support.client.core.ClientProperties

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