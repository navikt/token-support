package no.nav.security.token.support.client.core.oauth2

 class OAuth2AccessTokenResponse @JvmOverloads constructor(var accessToken : String? = null,  var expiresAt : Int? = null,  var expiresIn : Int? = 60, private var additionalParameters : Map<String, Any> = emptyMap()) {


    //for jackson if it is used for deserialization
    fun setAccess_token(access_token : String?) {
        accessToken = access_token
    }

    fun setExpires_at(expires_at : Int) {
        expiresAt = expires_at
    }
    fun setExpires_in(expires_in : Int) {
        expiresIn = expires_in
    }

}