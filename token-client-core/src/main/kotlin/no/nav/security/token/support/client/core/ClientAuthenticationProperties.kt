package no.nav.security.token.support.client.core;

import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_BASIC
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_POST
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.PRIVATE_KEY_JWT
import no.nav.security.token.support.client.core.jwk.JwkFactory.fromJson
import no.nav.security.token.support.client.core.jwk.JwkFactory.fromJsonFile

class ClientAuthenticationProperties @JvmOverloads constructor(val clientId: String, val clientAuthMethod: ClientAuthenticationMethod,val clientSecret: String?,val clientJwk: String? = null, val clientRsaKey: RSAKey? = loadKey(clientJwk)) {

    init {
        require(clientAuthMethod in CLIENT_AUTH_METHODS) {
            "Unsupported authentication method $clientAuthMethod, must be one of $CLIENT_AUTH_METHODS"
        }
        if (clientAuthMethod in listOf(CLIENT_SECRET_BASIC, CLIENT_SECRET_POST)) {
            requireNotNull(clientSecret) { "Client secret must be set for authentication method $clientAuthMethod" }
        }
        if (PRIVATE_KEY_JWT.equals(clientAuthMethod)) {
            requireNotNull(clientJwk) { "Client private key must be set for authentication method $clientAuthMethod" }
        }
    }


    companion object {
        private val CLIENT_AUTH_METHODS = listOf(CLIENT_SECRET_BASIC, CLIENT_SECRET_POST, PRIVATE_KEY_JWT)

        @JvmStatic
        fun builder(clientId: String, clientAuthMethod: ClientAuthenticationMethod) = ClientAuthenticationPropertiesBuilder(clientId, clientAuthMethod)
        private fun loadKey(clientJwk: String?) =
            clientJwk?.let {
                if (it.startsWith("{")) {
                    fromJson(it)
                } else {
                    fromJsonFile(it)
                }
            }
    }

}

class ClientAuthenticationPropertiesBuilder @JvmOverloads constructor(private val clientId: String, private val clientAuthMethod: ClientAuthenticationMethod, private var clientSecret: String? = null, private var clientJwk: String? = null) {
    fun  clientSecret(clientSecret: String)= this.also { it.clientSecret = clientSecret }
    fun  clientJwk(clientJwk: String)= this.also { it.clientJwk = clientJwk }
    fun  build() = ClientAuthenticationProperties(clientId, clientAuthMethod, clientSecret, clientJwk);
}