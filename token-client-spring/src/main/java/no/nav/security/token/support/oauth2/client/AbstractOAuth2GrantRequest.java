package no.nav.security.token.support.oauth2.client;

import no.nav.security.token.support.oauth2.OAuth2GrantType;

abstract class AbstractOAuth2GrantRequest {

    private final OAuth2GrantType oAuth2GrantType;
    private final OAuth2ClientConfig.OAuth2Client oAuth2Client;

    AbstractOAuth2GrantRequest(OAuth2GrantType oAuth2GrantType, OAuth2ClientConfig.OAuth2Client oAuth2Client) {
        this.oAuth2GrantType = oAuth2GrantType;
        this.oAuth2Client = oAuth2Client;
    }

    public OAuth2GrantType getGrantType() {
        return oAuth2GrantType;
    }

    public OAuth2ClientConfig.OAuth2Client getClientProperties() {
        return oAuth2Client;
    }
}
