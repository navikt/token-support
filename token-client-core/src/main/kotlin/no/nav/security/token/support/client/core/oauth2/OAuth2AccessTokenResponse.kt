package no.nav.security.token.support.client.core.oauth2

 data class OAuth2AccessTokenResponse (@get:JvmName("getAccessToken") var access_token : String? = null,
                                       @get:JvmName("getExpiresAt") var expires_at : Int? = null,
                                       @get:JvmName("getExpiresIn") var expires_in : Int? = 60,
                                       private val additionalParameters : Map<String, Any> = emptyMap()) {

     @Deprecated(message = "Ikke bruk denne", replaceWith = ReplaceWith("getAccessToken()"))
     fun getAccess_token() = access_token
     @Deprecated(message = "Ikke bruk denne", replaceWith = ReplaceWith("getExpiresAt()"))
     fun getExpires_at() = expires_at
     @Deprecated(message = "Ikke bruk denne", replaceWith = ReplaceWith("getExpiresIn()"))
     fun getExpires_in() = expires_in
}