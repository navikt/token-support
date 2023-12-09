package no.nav.security.token.support.client.core

import com.nimbusds.oauth2.sdk.GrantType
import kotlin.DeprecationLevel.WARNING

@Deprecated("Use GrantType from nimbus instead", ReplaceWith("GrantType"), WARNING)
data class OAuth2GrantType(@JvmField val value : String) {
     fun value() = value

    companion object {
       @JvmField
       @Deprecated("Use com.nimbusds.oauth2.sdk.GrantType instead", ReplaceWith("GrantType.JWT_BEARER"), WARNING)
       val JWT_BEARER = GrantType(GrantType.JWT_BEARER.value)
        @JvmField
        @Deprecated("Use com.nimbusds.oauth2.sdk.GrantType instead", ReplaceWith("GrantType.CLIENT_CREDENTIALS"), WARNING)
        val CLIENT_CREDENTIALS = GrantType(GrantType.CLIENT_CREDENTIALS.value)
        @JvmField
        @Deprecated("Use com.nimbusds.oauth2.sdk.GrantType instead", ReplaceWith("GrantType.TOKEN_EXCHANGE"), WARNING)
        val TOKEN_EXCHANGE = GrantType(GrantType.TOKEN_EXCHANGE.value)
    }
}