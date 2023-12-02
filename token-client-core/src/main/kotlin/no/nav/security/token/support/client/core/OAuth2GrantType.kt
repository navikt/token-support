package no.nav.security.token.support.client.core

import com.nimbusds.oauth2.sdk.GrantType

@Deprecated("Use GrantType from nimbus instead", ReplaceWith("GrantType"), DeprecationLevel.WARNING)
data class OAuth2GrantType(@JvmField val value : String) {
     fun value() = value

    companion object {
       @JvmField
       @Deprecated("Use GrantType.JWT_BEARER from nimbus instead")
       val JWT_BEARER = OAuth2GrantType(GrantType.JWT_BEARER.value)
        @JvmField
        @Deprecated("Use GrantType.CLIENT_CREDENTIALS from nimbus instead")
        val CLIENT_CREDENTIALS = OAuth2GrantType(GrantType.CLIENT_CREDENTIALS.value)
        @JvmField
        @Deprecated("Use GrantType.TOKEN_EXCHANGE from nimbus instead")
        val TOKEN_EXCHANGE = OAuth2GrantType(GrantType.TOKEN_EXCHANGE.value)
    }
}