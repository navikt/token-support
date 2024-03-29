package no.nav.security.token.support.client.core

import com.nimbusds.jose.util.DefaultResourceRetriever
import com.nimbusds.oauth2.sdk.GrantType
import com.nimbusds.oauth2.sdk.GrantType.CLIENT_CREDENTIALS
import com.nimbusds.oauth2.sdk.GrantType.JWT_BEARER
import com.nimbusds.oauth2.sdk.GrantType.TOKEN_EXCHANGE
import com.nimbusds.oauth2.sdk.ParseException
import com.nimbusds.oauth2.sdk.`as`.AuthorizationServerMetadata.parse
import java.io.IOException
import java.net.URI

class ClientProperties @JvmOverloads constructor(var tokenEndpointUrl: URI? = null,
                                                 private val wellKnownUrl: URI? = null,
                                                 val grantType: GrantType,
                                                 val scope: List<String> = emptyList(),
                                                 val authentication: ClientAuthenticationProperties,
                                                 val resourceUrl: URI? = null,
                                                 val tokenExchange: TokenExchangeProperties? = null) {


    init {
        tokenEndpointUrl = tokenEndpointUrl ?: endpointUrlFromMetadata(requireNotNull(wellKnownUrl))
        require(grantType in GRANT_TYPES) { "Unsupported grantType $grantType, must be one of $GRANT_TYPES" }
    }


    fun toBuilder() =
        ClientPropertiesBuilder(grantType, authentication)
            .tokenEndpointUrl(tokenEndpointUrl)
            .wellKnownUrl(wellKnownUrl)
            .scope(scope)
            .resourceUrl(resourceUrl)
            .tokenExchange(tokenExchange)

    companion object {
        private val GRANT_TYPES = listOf(JWT_BEARER, CLIENT_CREDENTIALS, TOKEN_EXCHANGE)

       @JvmStatic
        fun builder(grantType: GrantType, authentication: ClientAuthenticationProperties) = ClientPropertiesBuilder(grantType, authentication)

        private fun endpointUrlFromMetadata(wellKnown: URI?) =
            runCatching {
                wellKnown?.let { parse(DefaultResourceRetriever().retrieveResource(wellKnown.toURL()).content).tokenEndpointURI }
                    ?: throw OAuth2ClientException("Well-known url cannot be null, please check your configuration")
            }.getOrElse {
                when(it) {
                    is ParseException-> throw OAuth2ClientException("Unable to parse response from $wellKnown", it)
                    is IOException -> throw OAuth2ClientException("Unable to read from $wellKnown", it)
                    is OAuth2ClientException -> throw it
                    else -> throw OAuth2ClientException("Unexpected error reading from $wellKnown", it)
                }
            }
    }

    class ClientPropertiesBuilder @JvmOverloads constructor(private val grantType: GrantType,
                                                            val authentication: ClientAuthenticationProperties,
                                                            private var tokenEndpointUrl: URI? = null,
                                                            private var wellKnownUrl: URI? = null,
                                                            private var scope: List<String> = emptyList(),
                                                            private var resourceUrl: URI? = null,
                                                            private var tokenExchange: TokenExchangeProperties? = null) {

        fun tokenEndpointUrl(endpointURI: String?) = endpointURI?.let { tokenEndpointUrl(URI.create(it)) } ?: this
        fun tokenEndpointUrl(endpointURI: URI?) = this.also { it.tokenEndpointUrl = endpointURI }
        fun wellKnownUrl(wellKnownURI: String?) = wellKnownURI?.let { wellKnownUrl(URI.create(it)) } ?: this
        fun wellKnownUrl(wellKnownURI: URI?) = this.also { it.wellKnownUrl = wellKnownURI }
        fun scopes(vararg scopes:  String) =   scope(scopes.toList())
        fun scope(scope: List<String>) =  this.also { it.scope = scope}
        fun resourceUrl(resourceUrl: URI?) = this.also { it.resourceUrl = resourceUrl }
        fun tokenExchange(tokenExchange: TokenExchangeProperties?) = this.also { it.tokenExchange = tokenExchange }
        fun build() = ClientProperties(tokenEndpointUrl, wellKnownUrl, grantType, scope, authentication, resourceUrl, tokenExchange)
    }


    data class TokenExchangeProperties @JvmOverloads constructor(val audience: String, var resource: String? = null) {
        companion object {
            const val SUBJECT_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:jwt"
        }
    }
}