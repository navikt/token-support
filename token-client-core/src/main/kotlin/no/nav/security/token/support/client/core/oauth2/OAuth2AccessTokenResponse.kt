package no.nav.security.token.support.client.core.oauth2

 data class OAuth2AccessTokenResponse (var access_token : String? = null,  var expires_at : Int? = null,  var expires_in : Int? = 60, private val additionalParameters : Map<String, Any> = emptyMap()) {

     val accessToken = access_token
     val expiresAt = expires_at
     val expiresIn = expires_in

}