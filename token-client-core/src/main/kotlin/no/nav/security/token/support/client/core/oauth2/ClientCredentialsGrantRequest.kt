package no.nav.security.token.support.client.core.oauth2

import no.nav.security.token.support.client.core.ClientProperties
import no.nav.security.token.support.client.core.OAuth2GrantType.Companion.CLIENT_CREDENTIALS

class ClientCredentialsGrantRequest(clientProperties : ClientProperties) : AbstractOAuth2GrantRequest(CLIENT_CREDENTIALS, clientProperties)