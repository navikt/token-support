package no.nav.security.token.support.client.core

 data class OAuth2GrantType(@JvmField val value : String) {
     fun value() = value

    companion object {
       @JvmField
        val JWT_BEARER = OAuth2GrantType("urn:ietf:params:oauth:grant-type:jwt-bearer")
        @JvmField
        val CLIENT_CREDENTIALS = OAuth2GrantType("client_credentials")
        @JvmField
        val TOKEN_EXCHANGE = OAuth2GrantType("urn:ietf:params:oauth:grant-type:token-exchange")
    }
}