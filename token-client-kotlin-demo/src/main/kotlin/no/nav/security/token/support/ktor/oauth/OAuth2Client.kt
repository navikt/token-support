package no.nav.security.token.support.ktor.oauth

import com.fasterxml.jackson.annotation.JsonProperty
import com.nimbusds.oauth2.sdk.GrantType
import com.nimbusds.oauth2.sdk.GrantType.CLIENT_CREDENTIALS
import com.nimbusds.oauth2.sdk.GrantType.JWT_BEARER
import com.nimbusds.oauth2.sdk.GrantType.TOKEN_EXCHANGE
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_BASIC
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.CLIENT_SECRET_POST
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod.PRIVATE_KEY_JWT
import com.nimbusds.oauth2.sdk.auth.JWTAuthentication.CLIENT_ASSERTION_TYPE
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import java.net.URI
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.future.await
import kotlinx.coroutines.runBlocking
import no.nav.security.token.support.client.core.ClientAuthenticationProperties
import no.nav.security.token.support.client.core.OAuth2ParameterNames
import no.nav.security.token.support.client.core.OAuth2ParameterNames.ASSERTION
import no.nav.security.token.support.client.core.OAuth2ParameterNames.AUDIENCE
import no.nav.security.token.support.client.core.OAuth2ParameterNames.CLIENT_ASSERTION
import no.nav.security.token.support.client.core.OAuth2ParameterNames.CLIENT_ID
import no.nav.security.token.support.client.core.OAuth2ParameterNames.CLIENT_SECRET
import no.nav.security.token.support.client.core.OAuth2ParameterNames.GRANT_TYPE
import no.nav.security.token.support.client.core.OAuth2ParameterNames.REQUESTED_TOKEN_USE
import no.nav.security.token.support.client.core.OAuth2ParameterNames.SCOPE
import no.nav.security.token.support.client.core.OAuth2ParameterNames.SUBJECT_TOKEN
import no.nav.security.token.support.client.core.OAuth2ParameterNames.SUBJECT_TOKEN_TYPE
import no.nav.security.token.support.client.core.auth.ClientAssertion
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse
import no.nav.security.token.support.core.JwtTokenConstants.AUTHORIZATION_HEADER


class OAuth2Client(private val httpClient: HttpClient, private val wellKnownUrl: String, private val clientAuthProperties: ClientAuthenticationProperties, private val cacheConfig: OAuth2CacheConfig = OAuth2CacheConfig(true, 1000,  5)) {
    private val wellKnown: WellKnown = runBlocking { httpClient.get(wellKnownUrl).body() }
    private val coroutineScope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    private val cache =
        cacheConfig.cache(coroutineScope) {
            httpClient.tokenRequest(wellKnown.tokenEndpointUrl, clientAuthProperties, it)
        }

    suspend fun onBehalfOf(token: String, scope: String) = accessToken(GrantRequest.onBehalfOf(token, scope))

    suspend fun tokenExchange(token: String, audience: String) = accessToken(GrantRequest.tokenExchange(token, audience))

    suspend fun clientCredentials(scope: String) = accessToken(GrantRequest.clientCredentials(scope))

    suspend fun accessToken(grantRequest: GrantRequest) =
        if (cacheConfig.enabled) {
            cache.get(grantRequest).await()
        } else {
            httpClient.tokenRequest(wellKnown.tokenEndpointUrl, clientAuthProperties, grantRequest)
        }
    data class WellKnown(@JsonProperty("token_endpoint") val tokenEndpointUrl: String)
}

data class GrantRequest(val grantType: GrantType, val params: Map<String, String> = emptyMap()) {
    companion object {
        fun tokenExchange(token: String, audience: String) = GrantRequest(TOKEN_EXCHANGE, mapOf(SUBJECT_TOKEN_TYPE to "urn:ietf:params:oauth:token-type:jwt", SUBJECT_TOKEN to token, AUDIENCE to audience))
        fun onBehalfOf(token: String, scope: String) = GrantRequest(JWT_BEARER, mapOf(SCOPE to scope, REQUESTED_TOKEN_USE to "on_behalf_of", ASSERTION to token))
        fun clientCredentials(scope: String) = GrantRequest(CLIENT_CREDENTIALS, mapOf(SCOPE to scope))
    }
}

internal suspend fun HttpClient.tokenRequest(tokenEndpointUrl: String, clientAuthProperties: ClientAuthenticationProperties, grantRequest: GrantRequest
): OAuth2AccessTokenResponse {
    val p = Parameters.build {
        appendClientAuthParams(tokenEndpointUrl, clientAuthProperties)
        append(GRANT_TYPE, grantRequest.grantType.value)
        grantRequest.params.forEach {
            append(it.key, it.value)
        }
    }
    val res: OAuth2AccessTokenResponse = submitForm(tokenEndpointUrl,p) {
        if (clientAuthProperties.clientAuthMethod == CLIENT_SECRET_BASIC) {
            header(AUTHORIZATION_HEADER, "Basic ${basicAuth(clientAuthProperties.clientId, clientAuthProperties.clientSecret!!)}")
        }
    }.body()
    return res
}

private fun ParametersBuilder.appendClientAuthParams(tokenEndpointUrl: String, clientAuthProperties: ClientAuthenticationProperties) = apply {
    when (clientAuthProperties.clientAuthMethod) {
        CLIENT_SECRET_POST -> {
            append(CLIENT_ID, clientAuthProperties.clientId)
            append(CLIENT_SECRET, clientAuthProperties.clientSecret!!)
        }
        PRIVATE_KEY_JWT -> {
            val clientAssertion = ClientAssertion(URI.create(tokenEndpointUrl), clientAuthProperties)
            append(CLIENT_ID, clientAuthProperties.clientId)
            append(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE, CLIENT_ASSERTION_TYPE)
            append(CLIENT_ASSERTION, clientAssertion.assertion())
        }
    }
}