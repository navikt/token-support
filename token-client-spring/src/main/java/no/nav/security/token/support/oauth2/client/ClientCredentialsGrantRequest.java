package no.nav.security.token.support.oauth2.client;

import no.nav.security.token.support.oauth2.ClientConfigurationProperties;
import no.nav.security.token.support.oauth2.OAuth2GrantType;

class ClientCredentialsGrantRequest extends AbstractOAuth2GrantRequest {

    ClientCredentialsGrantRequest(ClientConfigurationProperties.ClientProperties clientProperties) {
        super(OAuth2GrantType.CLIENT_CREDENTIALS, clientProperties);
    }
}
