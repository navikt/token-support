package no.nav.security.token.support.oauth2.client;

import no.nav.security.token.support.oauth2.ClientConfigurationProperties;
import no.nav.security.token.support.oauth2.OAuth2GrantType;

class OnBehalfOfGrantRequest extends AbstractOAuth2GrantRequest {
    private final String assertion;

    OnBehalfOfGrantRequest(ClientConfigurationProperties.ClientProperties clientProperties, String assertion) {
        super(OAuth2GrantType.JWT_BEARER, clientProperties);
        this.assertion = assertion;
    }

    String getAssertion() {
        return this.assertion;
    }
}
