package no.nav.security.token.support.ktor

import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.auth.principal
import io.ktor.features.ContentNegotiation
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.jackson.JacksonConverter
import io.ktor.response.respond
import io.ktor.routing.get
import io.ktor.routing.routing
import io.ktor.util.KtorExperimentalAPI
import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.token.support.client.core.OAuth2CacheFactory
import no.nav.security.token.support.client.core.oauth2.ClientCredentialsTokenClient
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenService
import no.nav.security.token.support.client.core.oauth2.OnBehalfOfTokenClient
import no.nav.security.token.support.client.core.oauth2.TokenExchangeClient
import no.nav.security.token.support.ktor.http.DefaultOAuth2HttpClient
import no.nav.security.token.support.ktor.model.TokenResponse
import no.nav.security.token.support.ktor.oauth.ClientPropertiesConfig
import no.nav.security.token.support.ktor.oauth.TokenResolver
import no.nav.security.token.support.ktor.utils.Jackson
import no.nav.security.token.support.ktor.utils.configFor

fun main(args: Array<String>): Unit = io.ktor.server.netty.EngineMain.main(args)

@KtorExperimentalAPI
@Suppress("unused") // Referenced in application.conf
fun Application.module() {

    install(ContentNegotiation) {
        register(ContentType.Application.Json, JacksonConverter(Jackson.defaultMapper))
    }

    // mock oAuth2 server for demo app
    MockOAuth2Server().start(1111)

    // Setup properties
    val client = "demo-client"
    val clientPropertiesConfig = ClientPropertiesConfig(this.environment.config)
    val clientProperties = clientPropertiesConfig.configFor(client)

    val tokenResolver = TokenResolver()
    val httpClient = DefaultOAuth2HttpClient()
    val accessTokenService = setupOAuth2AccessTokenService(
        tokenResolver = tokenResolver,
        httpClient = httpClient,
        clientPropertiesConfig = clientPropertiesConfig
    )

    routing {
        get("/onbehalfof") {
            tokenResolver.tokenPrincipal = call.principal()
            val oAuth2Response = accessTokenService.getAccessToken(clientProperties)
            call.respond(
                HttpStatusCode.OK,
                TokenResponse(
                    oAuth2Response.accessToken
                )
            )
        }
    }
}

internal fun setupOAuth2AccessTokenService(
    tokenResolver: TokenResolver,
    httpClient: DefaultOAuth2HttpClient,
    clientPropertiesConfig: ClientPropertiesConfig
): OAuth2AccessTokenService {
    val accessTokenService = OAuth2AccessTokenService(
        tokenResolver,
        OnBehalfOfTokenClient(httpClient),
        ClientCredentialsTokenClient(httpClient),
        TokenExchangeClient(httpClient)
    )
    if (clientPropertiesConfig.cacheConfig.enabled) {
        accessTokenService.onBehalfOfGrantCache =
            OAuth2CacheFactory.accessTokenResponseCache(
                clientPropertiesConfig.cacheConfig.maximumSize,
                clientPropertiesConfig.cacheConfig.evictSkew
            )
    }
    return accessTokenService
}
