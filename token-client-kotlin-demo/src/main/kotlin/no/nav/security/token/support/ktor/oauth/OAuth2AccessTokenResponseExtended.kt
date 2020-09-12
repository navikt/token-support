package no.nav.security.token.support.ktor.oauth

import com.fasterxml.jackson.annotation.JsonProperty
import no.nav.security.token.support.client.core.oauth2.OAuth2AccessTokenResponse

// Only for testing
data class OAuth2AccessTokenResponseExtended(
    @JsonProperty("token_type")
    private var tokenType: String = "",
    @JsonProperty("refresh_token")
    private var refreshToken: String = "",
    @JsonProperty("scope")
    private var scope: String = ""
) : OAuth2AccessTokenResponse()