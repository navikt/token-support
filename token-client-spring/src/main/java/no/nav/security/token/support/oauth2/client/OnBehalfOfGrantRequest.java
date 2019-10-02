package no.nav.security.token.support.oauth2.client;

import no.nav.security.token.support.oauth2.ClientConfigurationProperties;
import no.nav.security.token.support.oauth2.OAuth2GrantType;

public class OnBehalfOfGrantRequest extends AbstractOAuth2GrantRequest {
    private final String assertion;

    public OnBehalfOfGrantRequest(ClientConfigurationProperties.ClientProperties clientProperties, String assertion) {
        super(OAuth2GrantType.JWT_BEARER, clientProperties);
        this.assertion = assertion;
    }

    public String getAssertion() {
        return this.assertion;
    }
}
