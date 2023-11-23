package no.nav.security.token.support.client.core.oauth2

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.*
import java.lang.String.*
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.Optional
import no.nav.security.token.support.client.core.ClientProperties
import no.nav.security.token.support.client.core.OAuth2ClientException
import no.nav.security.token.support.client.core.OAuth2GrantType
import no.nav.security.token.support.client.core.OAuth2ParameterNames
import no.nav.security.token.support.client.core.auth.ClientAssertion
import no.nav.security.token.support.client.core.http.OAuth2HttpClient
import no.nav.security.token.support.client.core.http.OAuth2HttpHeaders
import no.nav.security.token.support.client.core.http.OAuth2HttpRequest

abstract class AbstractOAuth2TokenClient<T : AbstractOAuth2GrantRequest?> internal constructor(private val oAuth2HttpClient : OAuth2HttpClient) {

    fun getTokenResponse(grantRequest : T) : OAuth2AccessTokenResponse {
        val clientProperties = grantRequest?.clientProperties ?: throw OAuth2ClientException("ClientProperties cannot be null")
        return try {
            val formParameters = createDefaultFormParameters(grantRequest)
            formParameters.putAll(formParameters(grantRequest)!!)
            val oAuth2HttpRequest = OAuth2HttpRequest.builder()
                .tokenEndpointUrl(clientProperties.tokenEndpointUrl)
                .oAuth2HttpHeaders(OAuth2HttpHeaders.of(tokenRequestHeaders(clientProperties)))
                .formParameters(formParameters)
                .build()
            oAuth2HttpClient.post(oAuth2HttpRequest)
        }
        catch (e : Exception) {
            if (e !is OAuth2ClientException) {
                throw OAuth2ClientException("received exception $e when invoking token endpoint=${clientProperties.tokenEndpointUrl}", e)
            }
            throw e
        }
    }

    private fun tokenRequestHeaders(clientProperties : ClientProperties) : Map<String, List<String>> {
        val headers = HashMap<String, List<String>>()
        headers["Accept"] = listOf(CONTENT_TYPE_JSON)
        headers["Content-Type"] = listOf(CONTENT_TYPE_FORM_URL_ENCODED)
        val auth = clientProperties.authentication
        if (CLIENT_SECRET_BASIC == auth.clientAuthMethod) {
            headers["Authorization"] = listOf("Basic " + basicAuth(auth.clientId, auth.clientSecret))
        }
        return headers
    }

    fun createDefaultFormParameters(grantRequest : T) : MutableMap<String, String> {
        val clientProperties = grantRequest?.clientProperties ?: throw OAuth2ClientException("ClientProperties cannot be null")
        val formParameters : MutableMap<String, String> = LinkedHashMap(clientAuthenticationFormParameters(grantRequest))
        formParameters[OAuth2ParameterNames.GRANT_TYPE] = grantRequest.grantType.value()
        if (clientProperties.grantType != OAuth2GrantType.TOKEN_EXCHANGE) {
            formParameters[OAuth2ParameterNames.SCOPE] = join(" ", clientProperties.scope)
        }
        return formParameters
    }

    private fun clientAuthenticationFormParameters(grantRequest : T) : Map<String, String> {
        val clientProperties = grantRequest!!.clientProperties
        val formParameters : MutableMap<String, String> = LinkedHashMap()
        val auth = clientProperties.authentication
        if (CLIENT_SECRET_POST == auth.clientAuthMethod) {
            formParameters[OAuth2ParameterNames.CLIENT_ID] = auth.clientId
            formParameters[OAuth2ParameterNames.CLIENT_SECRET] = auth.clientSecret
        }
        else if (PRIVATE_KEY_JWT == auth.clientAuthMethod) {
            val clientAssertion = ClientAssertion(clientProperties.tokenEndpointUrl, auth)
            formParameters[OAuth2ParameterNames.CLIENT_ID] = auth.clientId
            formParameters[OAuth2ParameterNames.CLIENT_ASSERTION_TYPE] = clientAssertion.assertionType()
            formParameters[OAuth2ParameterNames.CLIENT_ASSERTION] = clientAssertion.assertion()
        }
        return formParameters
    }

    private fun basicAuth(username : String, password : String) : String {
        val charset = StandardCharsets.UTF_8
        val encoder = charset.newEncoder()
        return if (encoder.canEncode(username) && encoder.canEncode(password)) {
            val credentialsString = "$username:$password"
            val encodedBytes = Base64.getEncoder().encode(credentialsString.toByteArray(StandardCharsets.UTF_8))
            String(encodedBytes, StandardCharsets.UTF_8)
        }
        else {
            throw IllegalArgumentException("Username or password contains characters that cannot be encoded to " + charset.displayName())
        }
    }

    protected abstract fun formParameters(grantRequest : T) : Map<String, String>
    override fun toString() = javaClass.getSimpleName() + " [oAuth2HttpClient=" + oAuth2HttpClient + "]"

    companion object {

        private const val CONTENT_TYPE_FORM_URL_ENCODED = "application/x-www-form-urlencoded;charset=UTF-8"
        private const val CONTENT_TYPE_JSON = "application/json;charset=UTF-8"
    }
}