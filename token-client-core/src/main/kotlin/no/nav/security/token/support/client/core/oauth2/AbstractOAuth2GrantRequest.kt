package no.nav.security.token.support.client.core.oauth2

import com.nimbusds.oauth2.sdk.GrantType
import java.util.Objects
import no.nav.security.token.support.client.core.ClientProperties

abstract class AbstractOAuth2GrantRequest(val grantType : GrantType, val clientProperties : ClientProperties) {

    override fun equals(other : Any?) : Boolean {
        if (this === other) return true
        if (other == null || javaClass != other.javaClass) return false
        val that = other as AbstractOAuth2GrantRequest
        return grantType == that.grantType && clientProperties == that.clientProperties
    }

    override fun hashCode() = Objects.hash(grantType, clientProperties)
    override fun toString() = "${javaClass.getSimpleName()} [oAuth2GrantType=$grantType, clientProperties=$clientProperties]"
}