package no.nav.security.token.support.ktor.oauth

import io.ktor.util.KtorExperimentalAPI
import no.nav.security.token.support.client.core.ClientProperties
import no.nav.security.token.support.client.core.context.JwtBearerTokenResolver
import no.nav.security.token.support.client.core.oauth2.ClientCredentialsTokenClient
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService
import no.nav.security.token.support.client.core.oauth2.OnBehalfOfTokenClient
import no.nav.security.token.support.client.core.oauth2.TokenExchangeClient
import no.nav.security.token.support.ktor.jwt.ClientAssertion
import java.util.*

@KtorExperimentalAPI
class OAuth2Client(
    private val clientConfig: ClientProperties,
    private val client: ClientAssertion,
    httpClient: DefaultOAuth2HttpClient
) : JwtBearerTokenResolver {

    private val oauth2AccessTokenService: OAuth2AccessTokenService =
        OAuth2AccessTokenService(
            this,
            OnBehalfOfTokenClient(httpClient),
            ClientCredentialsTokenClient(httpClient),
            TokenExchangeClient(httpClient)
        )

    override fun token(): Optional<String> {
        return Optional.of(client.assertion())
    }

    fun getAccessToken(): OAuth2AccessTokenResponse =
        oauth2AccessTokenService.getAccessToken(clientConfig)
}