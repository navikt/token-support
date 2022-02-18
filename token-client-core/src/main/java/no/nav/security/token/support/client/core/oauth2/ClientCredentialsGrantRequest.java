package no.nav.security.token.support.client.core.oauth2;

import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.core.OAuth2GrantType;

public class ClientCredentialsGrantRequest extends AbstractOAuth2GrantRequest {

    public ClientCredentialsGrantRequest(ClientProperties clientProperties) {
        super(OAuth2GrantType.CLIENT_CREDENTIALS, clientProperties);
    }
}
