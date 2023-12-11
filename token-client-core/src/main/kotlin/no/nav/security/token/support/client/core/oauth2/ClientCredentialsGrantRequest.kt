package no.nav.security.token.support.client.core.oauth2

import com.nimbusds.oauth2.sdk.GrantType
import com.nimbusds.oauth2.sdk.GrantType.*
import no.nav.security.token.support.client.core.ClientProperties

class ClientCredentialsGrantRequest(clientProperties : ClientProperties) : AbstractOAuth2GrantRequest(CLIENT_CREDENTIALS, clientProperties)