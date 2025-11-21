package no.nav.security.token.support.client.core.oauth2

data class OAuth2AccessTokenResponse (@get:JvmName("getAccessToken") var access_token : String? = null,
                                      @get:JvmName("getExpiresAt") var expires_at : Int? = null,
                                      @get:JvmName("getExpiresIn") var expires_in : Int? = 60,
                                      private val additionalParameters : Map<String, Any> = emptyMap()) {


    fun getAccess_token() = access_token
    fun getExpires_at() = expires_at
    fun getExpires_in() = expires_in
}