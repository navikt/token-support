package no.nav.security.token.support.oauth2.client;

import no.nav.security.token.support.oauth2.OAuth2ClientConfig;
import no.nav.security.token.support.oauth2.OAuth2GrantType;

public class OnBehalfOfGrantRequest extends AbstractOAuth2GrantRequest {
    private final String assertion;

    public OnBehalfOfGrantRequest(OAuth2ClientConfig.OAuth2Client oAuth2Client, String assertion) {
        super(OAuth2GrantType.JWT_BEARER, oAuth2Client);
        this.assertion = assertion;
    }

    public String getAssertion() {
        return this.assertion;
    }
}
