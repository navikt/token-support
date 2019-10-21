package no.nav.security.token.support.client.core.oauth2;

import lombok.EqualsAndHashCode;
import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.core.OAuth2GrantType;

@EqualsAndHashCode(callSuper = true)
public class OnBehalfOfGrantRequest extends AbstractOAuth2GrantRequest {
    private final String assertion;

    public OnBehalfOfGrantRequest(ClientProperties clientProperties, String assertion) {
        super(OAuth2GrantType.JWT_BEARER, clientProperties);
        this.assertion = assertion;
    }

    String getAssertion() {
        return this.assertion;
    }
}
