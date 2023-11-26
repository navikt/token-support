package no.nav.security.token.support.client.core.oauth2

 class OAuth2AccessTokenResponse @JvmOverloads constructor(var accessToken : String? = null,  var expiresAt : Int? = null,  var expiresIn : Int? = 60, private var additionalParameters : Map<String, Any> = emptyMap()) {

    companion object {
       @JvmStatic
       fun builder() = OAuth2AccessTokenResponseBuilder()
    }
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

    class OAuth2AccessTokenResponseBuilder @JvmOverloads internal constructor(private var accessToken : String? = null, private var expiresAt : Int = 0, private var expiresIn : Int = 0 , private var additionalParameters : Map<String, Any> = emptyMap()) {
        fun accessToken(accessToken : String?) : OAuth2AccessTokenResponseBuilder {
            this.accessToken = accessToken
            return this
        }

        fun expiresAt(expiresAt : Int) : OAuth2AccessTokenResponseBuilder {
            this.expiresAt = expiresAt
            return this
        }

        fun expiresIn(expiresIn : Int) : OAuth2AccessTokenResponseBuilder {
            this.expiresIn = expiresIn
            return this
        }

        fun additionalParameters(additionalParameters : Map<String, Any>) : OAuth2AccessTokenResponseBuilder {
            this.additionalParameters = additionalParameters
            return this
        }

        fun build() : OAuth2AccessTokenResponse {
            return OAuth2AccessTokenResponse(accessToken, expiresAt, expiresIn, additionalParameters)
        }

        override fun toString() : String {
            return "OAuth2AccessTokenResponse.OAuth2AccessTokenResponseBuilder(accessToken=" + accessToken + ", expiresAt=" + expiresAt + ", expiresIn=" + expiresIn + ", additionalParameters=" + additionalParameters + ")"
        }
    }
}