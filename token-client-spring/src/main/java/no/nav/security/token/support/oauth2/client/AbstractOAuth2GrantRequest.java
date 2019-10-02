package no.nav.security.token.support.oauth2.client;

import no.nav.security.token.support.oauth2.ClientConfigurationProperties;
import no.nav.security.token.support.oauth2.OAuth2GrantType;

abstract class AbstractOAuth2GrantRequest {

    private final OAuth2GrantType oAuth2GrantType;
    private final ClientConfigurationProperties.ClientProperties clientProperties;

    AbstractOAuth2GrantRequest(OAuth2GrantType oAuth2GrantType, ClientConfigurationProperties.ClientProperties clientProperties) {
        this.oAuth2GrantType = oAuth2GrantType;
        this.clientProperties = clientProperties;
    }

    OAuth2GrantType getGrantType() {
        return oAuth2GrantType;
    }

    ClientConfigurationProperties.ClientProperties getClientProperties() {
        return clientProperties;
    }
}
