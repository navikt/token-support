package no.nav.security.token.support.client.core.oauth2

import com.nimbusds.common.contenttype.ContentType.APPLICATION_JSON
import com.nimbusds.common.contenttype.ContentType.APPLICATION_URLENCODED
import com.nimbusds.oauth2.sdk.GrantType.*
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.*
import com.nimbusds.oauth2.sdk.auth.JWTAuthentication
import java.lang.String.*
import java.nio.charset.StandardCharsets.*
import java.util.Base64
import java.util.Base64.*
import no.nav.security.token.support.client.core.ClientProperties
import no.nav.security.token.support.client.core.OAuth2ClientException
import no.nav.security.token.support.client.core.OAuth2ParameterNames.CLIENT_ASSERTION
import no.nav.security.token.support.client.core.OAuth2ParameterNames.CLIENT_ASSERTION_TYPE
import no.nav.security.token.support.client.core.OAuth2ParameterNames.CLIENT_ID
import no.nav.security.token.support.client.core.OAuth2ParameterNames.CLIENT_SECRET
import no.nav.security.token.support.client.core.OAuth2ParameterNames.GRANT_TYPE
import no.nav.security.token.support.client.core.OAuth2ParameterNames.SCOPE
import no.nav.security.token.support.client.core.auth.ClientAssertion
import no.nav.security.token.support.client.core.http.OAuth2HttpClient
import no.nav.security.token.support.client.core.http.OAuth2HttpHeaders
import no.nav.security.token.support.client.core.http.OAuth2HttpRequest

abstract class AbstractOAuth2TokenClient<T : AbstractOAuth2GrantRequest?> internal constructor(private val oAuth2HttpClient : OAuth2HttpClient) {

    protected abstract fun formParameters(grantRequest : T) : Map<String, String>

    fun getTokenResponse(grantRequest : T) =
        grantRequest?.clientProperties?.let {
            runCatching {
                oAuth2HttpClient.post(OAuth2HttpRequest.builder(it.tokenEndpointUrl)
                    .oAuth2HttpHeaders(OAuth2HttpHeaders.of(tokenRequestHeaders(it)))
                    .formParameters(createDefaultFormParameters(grantRequest).apply {
                        putAll(formParameters(grantRequest))
                    })
                    .build())
            }.getOrElse {e ->
                if (e !is OAuth2ClientException) {
                    throw OAuth2ClientException("Received exception $e when invoking token endpoint=${it.tokenEndpointUrl}", e)
                }
                throw e
            }
        }

    private fun tokenRequestHeaders(clientProperties : ClientProperties) =
        HashMap<String, List<String>>().apply {
            put("Accept",listOf("$APPLICATION_JSON"))
            put("Content-Type",listOf("$APPLICATION_URLENCODED"))
            val auth = clientProperties.authentication
            if (CLIENT_SECRET_BASIC == auth.clientAuthMethod) {
                put("Authorization",listOf("Basic ${basicAuth(auth.clientId, auth.clientSecret!!)}"))
            }
        }

    private fun createDefaultFormParameters(grantRequest : T) =
        grantRequest?.clientProperties?.let {
            clientAuthenticationFormParameters(grantRequest).apply {
                put(GRANT_TYPE,grantRequest.grantType.value)
                if (it.grantType != TOKEN_EXCHANGE) {
                    put(SCOPE,  join(" ", it.scope))
                }
            }
        } ?: throw OAuth2ClientException("ClientProperties cannot be null")

    private fun clientAuthenticationFormParameters(grantRequest : T) =
         grantRequest?.clientProperties?.let {
            with(it) {
                when (authentication.clientAuthMethod) {
                    CLIENT_SECRET_POST -> {
                         LinkedHashMap<String, String>().apply {
                            put(CLIENT_ID, authentication.clientId)
                            put(CLIENT_SECRET, authentication.clientSecret!!)
                        }
                    }
                    PRIVATE_KEY_JWT -> {
                         LinkedHashMap<String, String>().apply {
                            put(CLIENT_ID, authentication.clientId)
                            put(CLIENT_ASSERTION_TYPE, JWTAuthentication.CLIENT_ASSERTION_TYPE)
                            put(CLIENT_ASSERTION, ClientAssertion(tokenEndpointUrl, authentication).assertion())
                        }
                    }
                    else ->  mutableMapOf()
                }
            }
        } ?:  throw OAuth2ClientException("ClientProperties cannot be null")

    private fun basicAuth(username : String, password : String) =
        UTF_8.newEncoder().run {
            if (canEncode(username) && canEncode(password)) {
                getEncoder().encode("$username:$password".toByteArray(UTF_8)).toString()
            }
            else {
                throw IllegalArgumentException("Username or password contains characters that cannot be encoded to ${UTF_8.displayName()}")
            }
        }

    override fun toString() = "${javaClass.getSimpleName()} [oAuth2HttpClient=$oAuth2HttpClient]"

}