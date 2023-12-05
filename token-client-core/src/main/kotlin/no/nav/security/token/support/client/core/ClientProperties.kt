package no.nav.security.token.support.client.core

import com.nimbusds.jose.util.DefaultResourceRetriever
import com.nimbusds.oauth2.sdk.GrantType
import com.nimbusds.oauth2.sdk.ParseException
import com.nimbusds.oauth2.sdk.`as`.AuthorizationServerMetadata
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
        require(grantType in GRANT_TYPES) { "Unsupported grantType $grantType, must be one of $GRANT_TYPES" }
        tokenEndpointUrl = tokenEndpointUrl ?: endpointUrlFromMetadata(wellKnownUrl)
    }


    fun toBuilder() =
        ClientPropertiesBuilder(grantType, authentication)
            .tokenEndpointUrl(tokenEndpointUrl)
            .wellKnownUrl(wellKnownUrl)
            .scope(scope)
            .resourceUrl(resourceUrl)
            .tokenExchange(tokenExchange)

    companion object {
        private val GRANT_TYPES = listOf(GrantType.JWT_BEARER, GrantType.CLIENT_CREDENTIALS, GrantType.TOKEN_EXCHANGE)

       @JvmStatic
        fun builder(grantType: GrantType, authentication: ClientAuthenticationProperties) = ClientPropertiesBuilder(grantType, authentication)

        private fun endpointUrlFromMetadata(wellKnown: URI?) =
            runCatching {
                wellKnown?.let { AuthorizationServerMetadata.parse(DefaultResourceRetriever().retrieveResource(wellKnown.toURL()).content).tokenEndpointURI }
                    ?: throw OAuth2ClientException("Well knowcn url cannot be null, please check your configuration")
            }.getOrElse {
                when(it) {
                    is ParseException-> throw OAuth2ClientException("Unable to parse response from $wellKnown", it)
                    is IOException -> throw OAuth2ClientException("Unable to read from  $wellKnown", it)
                    is OAuth2ClientException -> throw it
                    else -> throw OAuth2ClientException("Unexpected error reading from $wellKnown", it)
                }
            }
    }

    class ClientPropertiesBuilder @JvmOverloads constructor(private val grantType: GrantType, val authentication: ClientAuthenticationProperties,
                                                            private var tokenEndpointUrl: URI? = null,
                                                            private var wellKnownUrl: URI? = null,
                                                            private var scope: List<String> = emptyList(),
                                                            private var resourceUrl: URI? = null,
                                                            private var tokenExchange: TokenExchangeProperties? = null) {

        fun tokenEndpointUrl(endpointURI: URI?) = this.also { it.tokenEndpointUrl = endpointURI }
        fun wellKnownUrl(wellKnownURI: URI?) = this.also { it.wellKnownUrl = wellKnownURI }
        fun scope(scope: List<String>) =  this.also { it.scope = scope}
        fun resourceUrl(resourceUrl: URI?) = this.also { it.resourceUrl = resourceUrl }
        fun tokenExchange(tokenExchange: TokenExchangeProperties?) = this.also { it.tokenExchange = tokenExchange }
        fun build() = ClientProperties(tokenEndpointUrl, wellKnownUrl, grantType, scope, authentication, resourceUrl, tokenExchange)
    }


    class TokenExchangeProperties @JvmOverloads constructor(val audience: String, var resource: String? = null) {

        fun subjectTokenType() = "urn:ietf:params:oauth:token-type:jwt"
    }
}