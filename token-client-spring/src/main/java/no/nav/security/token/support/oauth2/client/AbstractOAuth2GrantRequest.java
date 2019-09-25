package no.nav.security.token.support.oauth2.client;

import no.nav.security.token.support.oauth2.OAuth2GrantType;

public abstract class AbstractOAuth2GrantRequest {

    private final OAuth2GrantType oAuth2GrantType;
    private final OAuth2ClientConfig.OAuth2ClientProperties oAuth2ClientProperties;

    protected AbstractOAuth2GrantRequest(OAuth2GrantType oAuth2GrantType, OAuth2ClientConfig.OAuth2ClientProperties oAuth2ClientProperties) {
        this.oAuth2GrantType = oAuth2GrantType;
        this.oAuth2ClientProperties = oAuth2ClientProperties;
    }

    public OAuth2GrantType getGrantType() {
        return oAuth2GrantType;
    }

    public OAuth2ClientConfig.OAuth2ClientProperties getClientProperties() {
        return oAuth2ClientProperties;
    }
}
